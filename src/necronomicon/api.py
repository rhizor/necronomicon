"""
Necronomicon SIEM - REST API
Receives events from all Providence security tools
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

from .models import Event, Alert, Incident, EventSource, EventSeverity, DashboardStats
from .correlator import EventCorrelator
from .storage import EventStorage

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SIEMAPI:
    """
    Main API for Necronomicon SIEM
    Receives events from arkham, providence-soc, security-enforcer, azathoth-ti, rlyeh
    """
    
    def __init__(self, host: str = '0.0.0.0', port: int = 7000, 
                 storage_path: str = './data/necronomicon.db'):
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        CORS(self.app)  # Enable CORS for frontend
        
        self.storage = EventStorage(storage_path)
        self.correlator = EventCorrelator()
        
        self._setup_routes()
        
        # Disable Flask default logging
        self.app.logger.disabled = True
        log = logging.getLogger('werkzeug')
        log.disabled = True
    
    def _setup_routes(self):
        """Setup API routes"""
        
        # Health check
        @self.app.route('/health', methods=['GET'])
        def health():
            return jsonify({"status": "ok", "service": "necronomicon", "version": "1.0.0"})
        
        # Dashboard (HTML)
        @self.app.route('/')
        def dashboard():
            return render_template_string(self._get_dashboard_template())
        
        # API Documentation
        @self.app.route('/api')
        def api_docs():
            return jsonify({
                "service": "Necronomicon SIEM",
                "version": "1.0.0",
                "endpoints": {
                    "POST /api/events": "Submit a new event",
                    "GET /api/events": "Get all events (with filters)",
                    "GET /api/events/<id>": "Get specific event",
                    "GET /api/stats": "Get dashboard statistics",
                    "GET /api/alerts": "Get all alerts",
                    "GET /api/incidents": "Get all incidents",
                    "POST /api/correlate": "Run correlation manually",
                }
            })
        
        # Receive event from any source
        @self.app.route('/api/events', methods=['POST'])
        def receive_event():
            try:
                data = request.get_json()
                
                if not data:
                    return jsonify({"error": "No data provided"}), 400
                
                # Create event from data
                event = self._parse_event(data)
                
                # Store event
                self.storage.store_event(event)
                
                # Run correlation
                correlations = self.correlator.correlate(event, self.storage)
                
                # If correlations found, create alert
                if correlations:
                    alert = self._create_alert_from_correlations(event, correlations)
                    self.storage.store_alert(alert)
                
                logger.info(f"📥 Event received from {event.source.value}: {event.event_type}")
                
                return jsonify({
                    "status": "ok",
                    "event_id": event.id,
                    "correlations": len(correlations),
                    "alert_created": len(correlations) > 0
                }), 201
                
            except Exception as e:
                logger.error(f"Error processing event: {e}")
                return jsonify({"error": str(e)}), 500
        
        # Get events (with optional filters)
        @self.app.route('/api/events', methods=['GET'])
        def get_events():
            source = request.args.get('source')
            severity = request.args.get('severity')
            limit = int(request.args.get('limit', 100))
            
            events = self.storage.get_events(
                source=source,
                severity=severity,
                limit=limit
            )
            
            return jsonify({
                "count": len(events),
                "events": [e.to_dict() for e in events]
            })
        
        # Get specific event
        @self.app.route('/api/events/<event_id>', methods=['GET'])
        def get_event(event_id):
            event = self.storage.get_event(event_id)
            if event:
                return jsonify(event.to_dict())
            return jsonify({"error": "Event not found"}), 404
        
        # Get statistics
        @self.app.route('/api/stats', methods=['GET'])
        def get_stats():
            stats = self._calculate_stats()
            return jsonify(stats.to_dict())
        
        # Get geographic data (for map)
        @self.app.route('/api/geo', methods=['GET'])
        def get_geo():
            geo_data = self.storage.get_geographic_data()
            return jsonify(geo_data)
        
        # Get timeline
        @self.app.route('/api/timeline', methods=['GET'])
        def get_timeline():
            hours = int(request.args.get('hours', 24))
            timeline = self.storage.get_timeline(hours)
            return jsonify(timeline)
        
        # Get alerts
        @self.app.route('/api/alerts', methods=['GET'])
        def get_alerts():
            status = request.args.get('status')
            limit = int(request.args.get('limit', 50))
            
            alerts = self.storage.get_alerts(status=status, limit=limit)
            return jsonify({
                "count": len(alerts),
                "alerts": [a.to_dict() for a in alerts]
            })
        
        # Get incidents
        @self.app.route('/api/incidents', methods=['GET'])
        def get_incidents():
            status = request.args.get('status')
            limit = int(request.args.get('limit', 50))
            
            incidents = self.storage.get_incidents(status=status, limit=limit)
            return jsonify({
                "count": len(incidents),
                "incidents": [i.to_dict() for i in incidents]
            })
        
        # Manual correlation trigger
        @self.app.route('/api/correlate', methods=['POST'])
        def manual_correlate():
            try:
                # Run correlation on all recent events
                events = self.storage.get_events(limit=1000)
                new_correlations = 0
                
                for event in events:
                    if not event.correlated_events:
                        correlations = self.correlator.correlate(event, self.storage)
                        if correlations:
                            event.correlated_events = [c.id for c in correlations]
                            self.storage.update_event(event)
                            new_correlations += 1
                
                return jsonify({
                    "status": "ok",
                    "events_processed": len(events),
                    "new_correlations": new_correlations
                })
                
            except Exception as e:
                logger.error(f"Error in manual correlation: {e}")
                return jsonify({"error": str(e)}), 500
    
    def _parse_event(self, data: Dict[str, Any]) -> Event:
        """Parse incoming event data"""
        event = Event()
        
        # Required fields
        event.source = EventSource(data.get('source', 'manual'))
        event.event_type = data.get('event_type', 'unknown')
        event.title = data.get('title', 'Untitled Event')
        event.description = data.get('description', '')
        
        # Optional fields
        if 'source_id' in data:
            event.source_id = data['source_id']
        if 'severity' in data:
            event.severity = EventSeverity(data['severity'])
        if 'source_ip' in data:
            event.source_ip = data['source_ip']
        if 'source_port' in data:
            event.source_port = data['source_port']
        if 'target' in data:
            event.target = data['target']
        if 'target_port' in data:
            event.target_port = data['target_port']
        
        # Geographic data (may be enriched later)
        if 'geo' in data:
            geo = data['geo']
            event.country = geo.get('country')
            event.city = geo.get('city')
            event.latitude = geo.get('lat')
            event.longitude = geo.get('lon')
        
        # Raw data
        event.raw_data = data.get('raw_data', data)
        event.tags = data.get('tags', [])
        
        return event
    
    def _create_alert_from_correlations(self, event: Event, correlations: List[Event]) -> Alert:
        """Create an alert from correlated events"""
        alert = Alert()
        alert.severity = EventSeverity.HIGH if len(correlations) >= 3 else EventSeverity.MEDIUM
        alert.title = f"Correlated Events Detected: {event.event_type}"
        alert.description = f"Event {event.id} from {event.source.value} correlated with {len(correlations)} other events"
        alert.event_ids = [event.id] + [c.id for c in correlations]
        
        return alert
    
    def _calculate_stats(self) -> DashboardStats:
        """Calculate dashboard statistics"""
        return self.storage.get_stats()
    
    def _get_dashboard_template(self) -> str:
        """Return HTML dashboard template"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Necronomicon SIEM - Providence Security Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a0f;
            color: #e0e0e0;
            min-height: 100vh;
        }
        
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 20px;
            border-bottom: 3px solid #e94560;
            text-align: center;
        }
        
        .header h1 {
            color: #e94560;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            color: #888;
            font-style: italic;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, #1a1a2e 0%, #0f0f23 100%);
            border-radius: 10px;
            padding: 20px;
            border: 1px solid #2a2a4a;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        
        .stat-card h3 {
            color: #888;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }
        
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #e94560;
        }
        
        .stat-value.critical { color: #ff4444; }
        .stat-value.warning { color: #ffaa00; }
        .stat-value.info { color: #44aaff; }
        .stat-value.success { color: #44ff44; }
        
        .section {
            background: #1a1a2e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #2a2a4a;
        }
        
        .section h2 {
            color: #e94560;
            margin-bottom: 15px;
            border-bottom: 2px solid #e94560;
            padding-bottom: 10px;
        }
        
        .events-table {
            width: 100%;
            border-collapse: collapse;
        }
        
        .events-table th,
        .events-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #2a2a4a;
        }
        
        .events-table th {
            background: #0f0f23;
            color: #e94560;
            text-transform: uppercase;
            font-size: 0.9em;
        }
        
        .events-table tr:hover {
            background: #2a2a4a;
        }
        
        .severity-critical { color: #ff4444; font-weight: bold; }
        .severity-high { color: #ff8800; }
        .severity-medium { color: #ffcc00; }
        .severity-low { color: #44aaff; }
        .severity-info { color: #888; }
        
        .source-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .source-arkham { background: #4a4aff; color: white; }
        .source-providence_soc { background: #ff4a4a; color: white; }
        .source-security_enforcer { background: #4aff4a; color: black; }
        .source-azathoth_ti { background: #ffaa00; color: black; }
        .source-rlyeh { background: #aa00ff; color: white; }
        .source-manual { background: #888; color: white; }
        
        .loading {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        
        .refresh-btn {
            background: #e94560;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            margin-bottom: 20px;
        }
        
        .refresh-btn:hover {
            background: #ff6b6b;
        }
        
        .timestamp {
            color: #666;
            font-size: 0.9em;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid #2a2a4a;
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📖 Necronomicon</h1>
        <p>The Book of the Dead - Unifying All Forbidden Knowledge</p>
        <p style="margin-top: 10px; font-size: 0.9em;">Providence Security Ecosystem Dashboard</p>
    </div>
    
    <div class="container">
        <button class="refresh-btn" onclick="loadDashboard()">🔄 Refresh Dashboard</button>
        
        <div id="stats-container" class="stats-grid">
            <div class="stat-card">
                <h3>Total Events</h3>
                <div class="stat-value" id="total-events">--</div>
            </div>
            <div class="stat-card">
                <h3>Events (24h)</h3>
                <div class="stat-value info" id="events-24h">--</div>
            </div>
            <div class="stat-card">
                <h3>Critical Events</h3>
                <div class="stat-value critical" id="critical-events">--</div>
            </div>
            <div class="stat-card">
                <h3>Open Alerts</h3>
                <div class="stat-value warning" id="open-alerts">--</div>
            </div>
            <div class="stat-card">
                <h3>Open Incidents</h3>
                <div class="stat-value" id="open-incidents">--</div>
            </div>
            <div class="stat-card">
                <h3>Active Sources</h3>
                <div class="stat-value success" id="active-sources">6</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🔥 Recent Events</h2>
            <div id="events-container">
                <div class="loading">Loading events...</div>
            </div>
        </div>
        
        <div class="section">
            <h2>⚠️ Active Alerts</h2>
            <div id="alerts-container">
                <div class="loading">Loading alerts...</div>
            </div>
        </div>
        
        <div class="section">
            <h2>🌍 Geographic Distribution</h2>
            <div id="geo-container">
                <div class="loading">Loading geographic data...</div>
            </div>
        </div>
    </div>
    
    <div class="footer">
        <p>Necronomicon SIEM v1.0.0 | Part of the Providence Security Ecosystem</p>
        <p style="font-style: italic; margin-top: 5px;">"That is not dead which can eternal lie..."</p>
    </div>
    
    <script>
        // Auto-refresh every 30 seconds
        setInterval(loadDashboard, 30000);
        
        // Initial load
        document.addEventListener('DOMContentLoaded', loadDashboard);
        
        async function loadDashboard() {
            try {
                // Load stats
                const statsResponse = await fetch('/api/stats');
                const stats = await statsResponse.json();
                updateStats(stats);
                
                // Load events
                const eventsResponse = await fetch('/api/events?limit=10');
                const eventsData = await eventsResponse.json();
                updateEvents(eventsData.events);
                
                // Load alerts
                const alertsResponse = await fetch('/api/alerts?status=open&limit=5');
                const alertsData = await alertsResponse.json();
                updateAlerts(alertsData.alerts);
                
                // Load geo data
                const geoResponse = await fetch('/api/geo');
                const geoData = await geoResponse.json();
                updateGeo(geoData);
                
            } catch (error) {
                console.error('Error loading dashboard:', error);
                showError('Failed to load dashboard data');
            }
        }
        
        function updateStats(stats) {
            if (stats.events) {
                document.getElementById('total-events').textContent = stats.events.total || 0;
                document.getElementById('events-24h').textContent = stats.events.last_24h || 0;
                document.getElementById('critical-events').textContent = 
                    (stats.events.by_severity?.critical || 0) + 
                    (stats.events.by_severity?.high || 0);
            }
            if (stats.alerts) {
                document.getElementById('open-alerts').textContent = stats.alerts.open || 0;
            }
            if (stats.incidents) {
                document.getElementById('open-incidents').textContent = stats.incidents.open || 0;
            }
        }
        
        function updateEvents(events) {
            const container = document.getElementById('events-container');
            if (!events || events.length === 0) {
                container.innerHTML = '<p style="color: #666;">No events recorded yet</p>';
                return;
            }
            
            let html = `
                <table class="events-table">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Source</th>
                            <th>Type</th>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>IP</th>
                        </tr>
                    </thead>
                    <tbody>
            `;
            
            events.forEach(event => {
                const time = new Date(event.timestamp).toLocaleTimeString();
                const sourceClass = `source-${event.source}`;
                const severityClass = `severity-${event.severity}`;
                
                html += `
                    <tr>
                        <td class="timestamp">${time}</td>
                        <td><span class="source-badge ${sourceClass}">${event.source}</span></td>
                        <td>${event.event_type}</td>
                        <td class="${severityClass}">${event.severity.toUpperCase()}</td>
                        <td>${event.title}</td>
                        <td>${event.source_ip || '-'}</td>
                    </tr>
                `;
            });
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }
        
        function updateAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            if (!alerts || alerts.length === 0) {
                container.innerHTML = '<p style="color: #666;">No active alerts</p>';
                return;
            }
            
            let html = '<ul style="list-style: none;">';
            alerts.forEach(alert => {
                const severityClass = `severity-${alert.severity}`;
                html += `
                    <li style="padding: 10px; border-left: 3px solid #e94560; margin-bottom: 10px; background: #2a2a4a;">
                        <strong class="${severityClass}">${alert.severity.toUpperCase()}</strong> - 
                        ${alert.title}<br>
                        <small style="color: #888;">${alert.description}</small>
                    </li>
                `;
            });
            html += '</ul>';
            container.innerHTML = html;
        }
        
        function updateGeo(geoData) {
            const container = document.getElementById('geo-container');
            if (!geoData || !geoData.countries) {
                container.innerHTML = '<p style="color: #666;">No geographic data available</p>';
                return;
            }
            
            let html = '<div style="display: flex; flex-wrap: wrap; gap: 10px;">';
            Object.entries(geoData.countries || {}).forEach(([country, count]) => {
                html += `
                    <div style="background: #2a2a4a; padding: 10px 15px; border-radius: 5px;">
                        <span style="font-size: 1.2em;">🇺🇳</span> 
                        <strong>${country}</strong>: ${count} attacks
                    </div>
                `;
            });
            html += '</div>';
            container.innerHTML = html;
        }
        
        function showError(message) {
            console.error(message);
        }
    </script>
</body>
</html>
        '''
    
    def start(self):
        """Start the API server"""
        logger.info(f"📖 Necronomicon SIEM API starting on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=False, threaded=True)

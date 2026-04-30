"""
Necronomicon SIEM - Simple Storage (In-Memory)
For production, replace with Elasticsearch or PostgreSQL
"""

import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict

from .models import Event, Alert, Incident, DashboardStats, EventSeverity

logger = logging.getLogger(__name__)


class EventStorage:
    """
    Simple in-memory storage for events
    In production, replace with Elasticsearch or database
    """
    
    def __init__(self, db_path: str = None):
        self.events: List[Event] = []
        self.alerts: List[Alert] = []
        self.incidents: List[Incident] = []
        self.db_path = db_path
    
    def store_event(self, event: Event):
        """Store an event"""
        self.events.append(event)
        logger.debug(f"Stored event {event.id}")
    
    def get_events(self, limit: int = 100, since: datetime = None, 
                   source: str = None, severity: str = None) -> List[Event]:
        """Get events with filters"""
        events = self.events
        
        if since:
            events = [e for e in events if datetime.fromisoformat(e.timestamp) > since]
        
        if source:
            events = [e for e in events if e.source.value == source]
        
        if severity:
            events = [e for e in events if e.severity.value == severity]
        
        return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]
    
    def get_event(self, event_id: str) -> Optional[Event]:
        """Get a specific event"""
        for event in self.events:
            if event.id == event_id:
                return event
        return None
    
    def update_event(self, event: Event):
        """Update an event"""
        for i, e in enumerate(self.events):
            if e.id == event.id:
                self.events[i] = event
                break
    
    def store_alert(self, alert: Alert):
        """Store an alert"""
        self.alerts.append(alert)
        logger.info(f"🚨 Alert created: {alert.title}")
    
    def get_alerts(self, status: str = None, limit: int = 50) -> List[Alert]:
        """Get alerts"""
        alerts = self.alerts
        if status:
            alerts = [a for a in alerts if a.status == status]
        return sorted(alerts, key=lambda a: a.created_at, reverse=True)[:limit]
    
    def store_incident(self, incident: Incident):
        """Store an incident"""
        self.incidents.append(incident)
    
    def get_incidents(self, status: str = None, limit: int = 50) -> List[Incident]:
        """Get incidents"""
        incidents = self.incidents
        if status:
            incidents = [i for i in incidents if i.status == status]
        return sorted(incidents, key=lambda i: i.created_at, reverse=True)[:limit]
    
    def get_stats(self) -> DashboardStats:
        """Calculate dashboard statistics"""
        stats = DashboardStats()
        
        now = datetime.now()
        day_ago = now - timedelta(days=1)
        hour_ago = now - timedelta(hours=1)
        
        # Event counts
        stats.total_events = len(self.events)
        stats.events_last_24h = len([e for e in self.events 
                                     if datetime.fromisoformat(e.timestamp) > day_ago])
        stats.events_last_hour = len([e for e in self.events 
                                      if datetime.fromisoformat(e.timestamp) > hour_ago])
        
        # By severity
        for event in self.events:
            if event.severity == EventSeverity.CRITICAL:
                stats.critical_events += 1
            elif event.severity == EventSeverity.HIGH:
                stats.high_events += 1
            elif event.severity == EventSeverity.MEDIUM:
                stats.medium_events += 1
            elif event.severity == EventSeverity.LOW:
                stats.low_events += 1
        
        # By source
        source_counts = defaultdict(int)
        for event in self.events:
            source_counts[event.source.value] += 1
        stats.events_by_source = dict(source_counts)
        
        # Alerts
        stats.total_alerts = len(self.alerts)
        stats.open_alerts = len([a for a in self.alerts if a.status == "open"])
        
        # Incidents
        stats.total_incidents = len(self.incidents)
        stats.open_incidents = len([i for i in self.incidents if i.status == "open"])
        
        return stats
    
    def get_geographic_data(self) -> Dict[str, Any]:
        """Get geographic distribution of events"""
        countries = defaultdict(int)
        cities = defaultdict(int)
        
        for event in self.events:
            if event.country:
                countries[event.country] += 1
            if event.city:
                cities[event.city] += 1
        
        return {
            "countries": dict(countries),
            "cities": dict(cities),
        }
    
    def get_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get event timeline"""
        since = datetime.now() - timedelta(hours=hours)
        
        timeline = []
        for hour in range(hours):
            hour_start = since + timedelta(hours=hour)
            hour_end = hour_start + timedelta(hours=1)
            
            count = len([e for e in self.events
                        if hour_start <= datetime.fromisoformat(e.timestamp) < hour_end])
            
            timeline.append({
                "hour": hour_start.isoformat(),
                "count": count
            })
        
        return timeline

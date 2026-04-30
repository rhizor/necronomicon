"""
Data models for Necronomicon SIEM
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List
from enum import Enum
import uuid
import json


class EventSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventSource(Enum):
    ARKHAM = "arkham"           # CTF Agent
    PROVIDENCE_SOC = "providence_soc"  # Security Operations Center
    SECURITY_ENFORCER = "security_enforcer"  # Dynamic Security Policy
    AZATHOTH_TI = "azathoth_ti"     # Threat Intelligence
    RLYEH = "rlyeh"             # Honeypot
    MANUAL = "manual"           # Manual entry


@dataclass
class Event:
    """
    Security event from any source in the Providence ecosystem
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    source: EventSource = EventSource.MANUAL
    source_id: str = ""  # ID from original source (e.g., attack ID, finding ID)
    
    # Event details
    event_type: str = ""
    severity: EventSeverity = EventSeverity.INFO
    title: str = ""
    description: str = ""
    
    # Source details
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    target: Optional[str] = None
    target_port: Optional[int] = None
    
    # Geographic info (enriched)
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    
    # Additional data (flexible)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    # Correlation
    correlated_events: List[str] = field(default_factory=list)
    incident_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary"""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "source": self.source.value,
            "source_id": self.source_id,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "target": self.target,
            "target_port": self.target_port,
            "geo": {
                "country": self.country,
                "city": self.city,
                "lat": self.latitude,
                "lon": self.longitude,
            } if self.latitude else None,
            "raw_data": self.raw_data,
            "tags": self.tags,
            "correlated_events": self.correlated_events,
            "incident_id": self.incident_id,
        }


@dataclass
class Alert:
    """
    Alert generated from one or more events
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Alert details
    severity: EventSeverity = EventSeverity.MEDIUM
    title: str = ""
    description: str = ""
    
    # Related events
    event_ids: List[str] = field(default_factory=list)
    
    # Status
    status: str = "open"  # open, acknowledged, resolved, false_positive
    assigned_to: Optional[str] = None
    
    # Response
    response_action: Optional[str] = None
    notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "event_ids": self.event_ids,
            "status": self.status,
            "assigned_to": self.assigned_to,
            "response_action": self.response_action,
            "notes": self.notes,
        }


@dataclass
class Incident:
    """
    Security incident - collection of related events and alerts
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Incident details
    title: str = ""
    description: str = ""
    severity: EventSeverity = EventSeverity.MEDIUM
    
    # Timeline of events
    event_ids: List[str] = field(default_factory=list)
    alert_ids: List[str] = field(default_factory=list)
    
    # Status
    status: str = "open"  # open, investigating, contained, resolved, closed
    
    # Impact assessment
    affected_systems: List[str] = field(default_factory=list)
    iocs: List[Dict[str, Any]] = field(default_factory=list)  # Indicators of Compromise
    
    # Response
    response_plan: str = ""
    containment_actions: List[str] = field(default_factory=list)
    remediation_actions: List[str] = field(default_factory=list)
    
    # Team
    lead: Optional[str] = None
    team: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "status": self.status,
            "event_count": len(self.event_ids),
            "alert_count": len(self.alert_ids),
            "affected_systems": self.affected_systems,
            "iocs": self.iocs,
            "lead": self.lead,
            "team": self.team,
        }


@dataclass
class DashboardStats:
    """
    Statistics for the dashboard
    """
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    # Event counts
    total_events: int = 0
    events_last_24h: int = 0
    events_last_hour: int = 0
    
    # By severity
    critical_events: int = 0
    high_events: int = 0
    medium_events: int = 0
    low_events: int = 0
    
    # By source
    events_by_source: Dict[str, int] = field(default_factory=dict)
    
    # Alerts
    open_alerts: int = 0
    total_alerts: int = 0
    
    # Incidents
    open_incidents: int = 0
    total_incidents: int = 0
    
    # Geographic
    top_attackers: List[Dict[str, Any]] = field(default_factory=list)
    attacks_by_country: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "events": {
                "total": self.total_events,
                "last_24h": self.events_last_24h,
                "last_hour": self.events_last_hour,
                "by_severity": {
                    "critical": self.critical_events,
                    "high": self.high_events,
                    "medium": self.medium_events,
                    "low": self.low_events,
                },
                "by_source": self.events_by_source,
            },
            "alerts": {
                "open": self.open_alerts,
                "total": self.total_alerts,
            },
            "incidents": {
                "open": self.open_incidents,
                "total": self.total_incidents,
            },
            "geographic": {
                "top_attackers": self.top_attackers,
                "by_country": self.attacks_by_country,
            },
        }

"""
Necronomicon SIEM - Event Correlator
Correlates events from different sources to identify attacks
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

from .models import Event, EventSource

logger = logging.getLogger(__name__)


class EventCorrelator:
    """
    Correlates events from different sources to identify coordinated attacks
    """
    
    def __init__(self, time_window: int = 300):
        """
        Args:
            time_window: Time window in seconds for correlation (default: 5 minutes)
        """
        self.time_window = time_window
    
    def correlate(self, event: Event, storage) -> List[Event]:
        """
        Find correlated events for the given event
        
        Returns:
            List of correlated events
        """
        correlations = []
        
        # Get recent events
        recent_events = storage.get_events(
            limit=100,
            since=datetime.now() - timedelta(seconds=self.time_window)
        )
        
        # Filter out the event itself
        recent_events = [e for e in recent_events if e.id != event.id]
        
        # Correlation rules
        
        # Rule 1: Same source IP across multiple sources
        if event.source_ip:
            for other in recent_events:
                if other.source_ip == event.source_ip and other.source != event.source:
                    correlations.append(other)
                    logger.info(f"🔗 Correlated by IP: {event.id} -> {other.id}")
        
        # Rule 2: Same event type within time window
        for other in recent_events:
            if (other.event_type == event.event_type and 
                other.source != event.source and
                other.id not in [c.id for c in correlations]):
                correlations.append(other)
                logger.info(f"🔗 Correlated by type: {event.id} -> {other.id}")
        
        return correlations


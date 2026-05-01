"""
Necronomicon SIEM - Security Information and Event Management

Unifies all Providence security tools into a single dashboard:
- Arkham (CTF Agent)
- Providence SOC
- Security Enforcer
- Azathoth TI
- R'lyeh Honeypot

The Book of the Dead containing all forbidden knowledge...
"""

__version__ = "1.0.0"
__author__ = "rhizor"

from .api import SIEMAPI
from .correlator import EventCorrelator
from .models import Event, Alert, Incident

__all__ = [
    "SIEMAPI",
    "EventCorrelator",
    "Event",
    "Alert",
    "Incident",
]

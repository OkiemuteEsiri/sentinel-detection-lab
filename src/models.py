from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone

ALLOWED_EVENT_TYPES = {"signin", "process", "audit", "network"}

@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: datetime
    event_type: str
    user: str
    host: str
    source_ip: str
    action: str
    result: str
    details: dict

    def __post_init__(self):
        if not self.event_id.strip(): raise ValueError("event_id required")
        if self.timestamp.tzinfo is None: raise ValueError("timestamp must be timezone-aware")
        if self.event_type not in ALLOWED_EVENT_TYPES: raise ValueError("unsupported event_type")
        if not self.action.strip(): raise ValueError("action required")

@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    confidence: int
    attack_techniques: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    rationale: str
    remediation: str

    def __post_init__(self):
        if self.severity not in {"low", "medium", "high", "critical"}: raise ValueError("invalid severity")
        if not 0 <= self.confidence <= 100: raise ValueError("confidence must be 0-100")
        if not self.evidence_ids: raise ValueError("finding requires evidence")

def parse_timestamp(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if ts.tzinfo is None: raise ValueError("timestamp must include timezone")
    return ts.astimezone(timezone.utc)

"""Defensive metadata validation for Microsoft Sentinel KQL detections."""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import re

ATTACK_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

@dataclass(frozen=True)
class Detection:
    name: str
    path: str
    attack_ids: tuple[str, ...]
    required_tables: tuple[str, ...]
    severity: str

    def __post_init__(self):
        if self.severity not in {"low", "medium", "high"}:
            raise ValueError("invalid severity")
        if not self.name.strip() or not self.path.endswith(".kql"):
            raise ValueError("invalid detection metadata")
        if not self.attack_ids or any(not ATTACK_RE.fullmatch(x) for x in self.attack_ids):
            raise ValueError("invalid ATT&CK mapping")
        if not self.required_tables:
            raise ValueError("at least one table is required")

    @property
    def detection_id(self) -> str:
        raw = f"{self.name}|{self.path}|{','.join(sorted(self.attack_ids))}"
        return "DET-" + sha256(raw.encode()).hexdigest()[:12].upper()

CATALOG = (
    Detection("Encoded PowerShell", "detections/encoded-powershell.kql", ("T1059.001",), ("DeviceProcessEvents",), "medium"),
    Detection("Remote Logon Fan-out", "detections/remote-logon-fanout.kql", ("T1021", "T1078"), ("DeviceLogonEvents",), "high"),
    Detection("Security Control Impairment", "detections/security-control-impairment.kql", ("T1562.001",), ("DeviceEvents",), "high"),
)

def validate_query(text: str, detection: Detection) -> list[str]:
    errors = []
    if not text.strip(): errors.append("empty query")
    if "| where " not in text: errors.append("missing filter")
    if "| project " not in text and "| summarize " not in text: errors.append("missing output shaping")
    for table in detection.required_tables:
        if table not in text: errors.append(f"missing required table: {table}")
    for technique in detection.attack_ids:
        if technique not in text: errors.append(f"missing ATT&CK comment: {technique}")
    return errors

def validate_repository(root: Path) -> dict:
    findings = {}
    for detection in CATALOG:
        path = root / detection.path
        findings[detection.detection_id] = ["missing file"] if not path.exists() else validate_query(path.read_text(encoding="utf-8"), detection)
    return findings

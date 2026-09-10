from __future__ import annotations
import json
from pathlib import Path
from .models import Event, parse_timestamp

REQUIRED={"event_id","timestamp","event_type","user","host","source_ip","action","result","details"}

def load_events(path: str) -> list[Event]:
    raw=json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw,list): raise ValueError("telemetry root must be a list")
    seen=set(); events=[]
    for row in raw:
        missing=REQUIRED-set(row)
        if missing: raise ValueError(f"missing fields: {sorted(missing)}")
        if row["event_id"] in seen: raise ValueError("duplicate event_id")
        seen.add(row["event_id"])
        events.append(Event(row["event_id"],parse_timestamp(row["timestamp"]),row["event_type"],row["user"],row["host"],row["source_ip"],row["action"],row["result"],row["details"]))
    return events

def render_markdown(findings) -> str:
    lines=["# Sentinel Detection Assessment","","Synthetic defensive telemetry only.","",f"Total findings: **{len(findings)}**","", "| Severity | Detection | Confidence | ATT&CK | Evidence |","|---|---|---:|---|---|"]
    for f in findings:
        lines.append(f"| {f.severity.title()} | {f.title} | {f.confidence}% | {', '.join(f.attack_techniques)} | {', '.join(f.evidence_ids)} |")
    lines += ["","## Analyst notes"]
    for f in findings:
        lines += ["",f"### {f.finding_id} — {f.title}",f"**Rationale:** {f.rationale}",f"**Remediation:** {f.remediation}"]
    return "\n".join(lines)+"\n"

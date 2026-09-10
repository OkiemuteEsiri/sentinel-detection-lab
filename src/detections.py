from __future__ import annotations
from collections import defaultdict
from hashlib import sha256
from .models import Event, Finding

def _fid(title: str, evidence: list[str]) -> str:
    raw = title + "|" + "|".join(sorted(evidence))
    return "DET-" + sha256(raw.encode()).hexdigest()[:12].upper()

def detect_impossible_admin_signin(events: list[Event]) -> list[Finding]:
    findings=[]
    for e in events:
        if e.event_type=="signin" and e.result=="success" and e.details.get("privileged") and not e.details.get("mfa", False):
            findings.append(Finding(_fid("Privileged sign-in without MFA",[e.event_id]),"Privileged sign-in without MFA","high",90,("T1078",),(e.event_id,),"A privileged identity authenticated successfully without MFA.","Require phishing-resistant MFA and review conditional access policy coverage."))
    return findings

def detect_encoded_powershell(events: list[Event]) -> list[Finding]:
    findings=[]
    for e in events:
        command=str(e.details.get("command_line","")).lower()
        if e.event_type=="process" and "powershell" in e.action.lower() and any(x in command for x in ("-enc ","-encodedcommand")):
            findings.append(Finding(_fid("Encoded PowerShell execution",[e.event_id]),"Encoded PowerShell execution","high",85,("T1059.001",),(e.event_id,),"PowerShell was observed with an encoded-command argument.","Validate the initiating user/process, inspect script-block telemetry, and contain the host if activity is unauthorized."))
    return findings

def detect_remote_logon_fanout(events: list[Event], threshold: int=3) -> list[Finding]:
    by_user=defaultdict(list)
    for e in events:
        if e.event_type=="signin" and e.result=="success" and e.details.get("remote",False): by_user[e.user].append(e)
    findings=[]
    for user, rows in by_user.items():
        hosts={r.host for r in rows}
        if len(hosts)>=threshold:
            ids=[r.event_id for r in rows]
            findings.append(Finding(_fid("Remote logon fan-out",ids),"Remote logon fan-out","medium",75,("T1021","T1078"),tuple(sorted(ids)),f"{user} authenticated remotely to {len(hosts)} hosts in the observed window.","Validate administrative intent, review source device context, and investigate lateral-movement evidence."))
    return findings

def detect_logging_impairment(events: list[Event]) -> list[Finding]:
    findings=[]
    for e in events:
        if e.event_type=="audit" and e.action in {"disable_diagnostic_setting","stop_security_agent","clear_audit_log"}:
            findings.append(Finding(_fid("Security telemetry impairment",[e.event_id]),"Security telemetry impairment","critical",95,("T1562.001","T1070.001"),(e.event_id,),"A synthetic security-control or logging impairment event was observed.","Restore telemetry, preserve available evidence, validate authorization, and scope related activity."))
    return findings

def run_all(events: list[Event]) -> list[Finding]:
    findings = detect_impossible_admin_signin(events)+detect_encoded_powershell(events)+detect_remote_logon_fanout(events)+detect_logging_impairment(events)
    order={"critical":4,"high":3,"medium":2,"low":1}
    return sorted(findings,key=lambda f:(-order[f.severity],-f.confidence,f.finding_id))

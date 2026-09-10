import unittest
from datetime import datetime, timezone
from src.models import Event, parse_timestamp
from src.detections import detect_impossible_admin_signin, detect_encoded_powershell, detect_remote_logon_fanout, detect_logging_impairment, run_all


def evt(i, kind, user="u", host="h", action="a", result="success", details=None):
    return Event(i, datetime(2026,9,1,tzinfo=timezone.utc), kind, user, host, "203.0.113.1", action, result, details or {})

class DetectionTests(unittest.TestCase):
    def test_parse_timestamp_utc(self):
        self.assertEqual(parse_timestamp("2026-09-01T10:00:00+01:00").hour, 9)
    def test_privileged_no_mfa(self):
        rows=[evt("1","signin",action="signin",details={"privileged":True,"mfa":False})]
        self.assertEqual(len(detect_impossible_admin_signin(rows)),1)
    def test_mfa_suppresses_privileged_signin_finding(self):
        rows=[evt("1","signin",action="signin",details={"privileged":True,"mfa":True})]
        self.assertEqual(detect_impossible_admin_signin(rows),[])
    def test_encoded_powershell(self):
        rows=[evt("1","process",action="powershell.exe",details={"command_line":"powershell -enc SYNTHETIC"})]
        self.assertEqual(len(detect_encoded_powershell(rows)),1)
    def test_plain_powershell_not_flagged(self):
        rows=[evt("1","process",action="powershell.exe",details={"command_line":"powershell Get-Date"})]
        self.assertEqual(detect_encoded_powershell(rows),[])
    def test_remote_fanout(self):
        rows=[evt(str(i),"signin",user="admin",host=f"srv-{i}",action="remote",details={"remote":True}) for i in range(3)]
        self.assertEqual(len(detect_remote_logon_fanout(rows)),1)
    def test_remote_fanout_threshold(self):
        rows=[evt(str(i),"signin",user="admin",host=f"srv-{i}",action="remote",details={"remote":True}) for i in range(2)]
        self.assertEqual(detect_remote_logon_fanout(rows),[])
    def test_logging_impairment(self):
        rows=[evt("1","audit",action="clear_audit_log")]
        self.assertEqual(detect_logging_impairment(rows)[0].severity,"critical")
    def test_run_all_orders_critical_first(self):
        rows=[evt("1","audit",action="clear_audit_log"),evt("2","signin",action="signin",details={"privileged":True,"mfa":False})]
        self.assertEqual(run_all(rows)[0].severity,"critical")
    def test_finding_id_deterministic(self):
        rows=[evt("1","audit",action="clear_audit_log")]
        self.assertEqual(detect_logging_impairment(rows)[0].finding_id,detect_logging_impairment(rows)[0].finding_id)

if __name__ == "__main__": unittest.main()

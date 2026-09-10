import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from src.detection_catalog import CATALOG, Detection, validate_query, validate_repository

class DetectionCatalogTests(unittest.TestCase):
    def test_catalog_has_three_detections(self): self.assertEqual(len(CATALOG), 3)
    def test_ids_are_deterministic(self): self.assertEqual(CATALOG[0].detection_id, CATALOG[0].detection_id)
    def test_invalid_severity_rejected(self):
        with self.assertRaises(ValueError): Detection("x","detections/x.kql",("T1078",),("DeviceEvents",),"critical")
    def test_invalid_attack_id_rejected(self):
        with self.assertRaises(ValueError): Detection("x","detections/x.kql",("BAD",),("DeviceEvents",),"high")
    def test_missing_filter_detected(self):
        q="DeviceEvents\n| project Timestamp\n// T1078"
        d=Detection("x","detections/x.kql",("T1078",),("DeviceEvents",),"high")
        self.assertIn("missing filter", validate_query(q,d))
    def test_missing_table_detected(self):
        q="OtherTable\n| where x == 1\n| project x\n// T1078"
        d=Detection("x","detections/x.kql",("T1078",),("DeviceEvents",),"high")
        self.assertTrue(any("missing required table" in e for e in validate_query(q,d)))
    def test_missing_attack_comment_detected(self):
        q="DeviceEvents\n| where x == 1\n| project x"
        d=Detection("x","detections/x.kql",("T1078",),("DeviceEvents",),"high")
        self.assertTrue(any("ATT&CK" in e for e in validate_query(q,d)))
    def test_repository_reports_missing_files(self):
        with TemporaryDirectory() as tmp:
            results=validate_repository(Path(tmp))
            self.assertEqual(len(results),3)
            self.assertTrue(all(v == ["missing file"] for v in results.values()))

if __name__ == "__main__": unittest.main()

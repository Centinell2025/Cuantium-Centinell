"""9 defensive tests for the compact student-only Sherlock case."""
import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

LITE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LITE / "tools"))
import build_lite

class LiteCaseTests(unittest.TestCase):
    def test_exact_16_questions(self):
        self.assertEqual(build_lite.validate()["graded_questions"], 16)

    def test_only_12_source_files(self):
        self.assertEqual(len(build_lite.CSV_FILES), 10)
        self.assertEqual(len(build_lite.POLICIES), 2)

    def test_actual_policy_specimens_have_distinct_hashes(self):
        self.assertNotEqual(build_lite.digest("policy-hybrid.txt"),
                            build_lite.digest("policy-classic.txt"))

    def test_student_zip_is_self_contained_and_allowlisted(self):
        build_lite.verify(build_lite.build())

    def test_unsigned_job_must_match_rejected_change(self):
        original = build_lite.rows
        def alternate(file):
            return [r for r in original(file) if r["signing_status"] == "signed"] if file == "ci_deliveries.csv" else original(file)
        with patch.object(build_lite, "rows", side_effect=alternate):
            with self.assertRaises(ValueError):
                build_lite.validate()

    def test_denied_session_cannot_authorize_write(self):
        original = build_lite.rows
        def alternate(file):
            return [r for r in original(file) if r["result"] == "denied"] if file == "idp_sessions.csv" else original(file)
        with patch.object(build_lite, "rows", side_effect=alternate):
            with self.assertRaises(ValueError):
                build_lite.validate()

    def test_wrong_edge_sensor_offset_breaks_correlation(self):
        original = build_lite.rows
        def alternate(file):
            if file == "clock_calibration.csv":
                return [{**r, "offset_seconds": "10"} if r["sensor"] == "edge-sensor" else r for r in original(file)]
            return original(file)
        with patch.object(build_lite, "rows", side_effect=alternate):
            with self.assertRaises(ValueError):
                build_lite.validate()

    def test_wrong_modified_hash_breaks_correlation(self):
        original = build_lite.rows
        def alternate(file):
            if file == "fim_events.csv":
                return [{**r, "sha256": "0"*64} if r["event_type"] == "modified" else r for r in original(file)]
            return original(file)
        with patch.object(build_lite, "rows", side_effect=alternate):
            with self.assertRaises(ValueError):
                build_lite.validate()

    def test_manifest_is_real_sha256(self):
        h = hashlib.sha256(b"abc").hexdigest()
        self.assertEqual(build_lite.manifest({"x": b"abc"}), (h + "  x\n").encode())

if __name__ == "__main__":
    unittest.main()

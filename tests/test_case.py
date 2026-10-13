"""Regression checks for the fully synthetic QC-001 training case."""
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_case
import build_student

class SyntheticCaseTests(unittest.TestCase):
    def test_case_invariants(self):
        summary = verify_case.validate()
        self.assertEqual(summary["graded_tasks"], 22)
        self.assertGreater(summary["records"], 25)

    def test_crypto_specimen_sha256_is_real(self):
        self.assertEqual(len(verify_case.sha256("policy-hybrid.txt")), 64)
        self.assertNotEqual(
            verify_case.sha256("policy-hybrid.txt"),
            verify_case.sha256("policy-classic.txt"),
        )

    def test_idp_sessions_are_unique(self):
        data = verify_case.rows("idp_sessions.csv")
        self.assertEqual(len({x["session_id"] for x in data}), len(data))

    def test_change_states_are_not_all_approved(self):
        states = {x["approval_state"] for x in verify_case.rows("change_control.csv")}
        self.assertIn("rejected", states)
        self.assertIn("approved", states)
        self.assertIn("pending", states)

    def test_host_write_has_positive_session_proof(self):
        session = {s["session_id"]: s for s in verify_case.rows("idp_sessions.csv")}
        writes = [x for x in verify_case.rows("host_audit.csv") if x["action"] == "write"]
        self.assertTrue(writes)
        self.assertTrue(all(session[x["session_id"]]["result"] == "success" for x in writes))

    def test_clock_calibration_is_nontrivial(self):
        offsets = [int(x["offset_seconds"]) for x in verify_case.rows("clock_calibration.csv")]
        self.assertIn(0, offsets)
        self.assertTrue(any(v > 0 for v in offsets))

    def test_flows_join_observation_ids(self):
        flow_ids = {x["connection_id"] for x in verify_case.rows("edge_flows.csv")}
        self.assertTrue(all(x["connection_id"] in flow_ids for x in verify_case.rows("tls_observations.csv")))

    def test_student_archive_excludes_confidential_material(self):
        path = build_student.build()
        build_student.verify_student(path)
        with zipfile.ZipFile(path) as z:
            self.assertIn("SHA256SUMS.txt", z.namelist())
            self.assertNotIn("tools/verify_case.py", z.namelist())
            self.assertIn("questions/INVESTIGATION.md", z.namelist())

    def test_manifest_is_sha256_not_a_handwaved_claim(self):
        self.assertEqual(
            build_student.manifest({"x": b"abc"}),
            (hashlib.sha256(b"abc").hexdigest() + "  x\n").encode(),
        )

    def test_missing_reference_causes_verification_failure(self):
        original = verify_case.rows
        def modified(filename):
            data = original(filename)
            if filename == "idp_sessions.csv":
                return [r for r in data if r["result"] == "denied"]
            return data
        try:
            verify_case.rows = modified
            with self.assertRaises(ValueError):
                verify_case.validate()
        finally:
            verify_case.rows = original

if __name__ == "__main__":
    unittest.main()

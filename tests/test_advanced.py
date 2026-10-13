"""Additional regression and negative-control tests for synthetic QC-001 v2."""
from __future__ import annotations

import sqlite3
import struct
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_advanced
import verify_advanced
from verify_case import rows

class AdvancedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build_advanced.build()

    def test_advanced_provenance_consistency(self):
        result = verify_advanced.validate()
        self.assertEqual(result["binary_pcap_packets"], 10)
        self.assertGreater(result["derived_sql_rows"], 50)

    def test_tcp_frame_header_and_checksums(self):
        count, totals = build_advanced.inspect_pcap()
        self.assertEqual(count, 10)
        self.assertEqual(len(totals), 4)
        self.assertTrue(all(v >= 0 for v in totals.values()))

    def test_distinct_writer_and_parent_pids(self):
        linked = [r for r in rows("process_lineage.csv") if r["related_audit_id"] == "AUD-101"]
        self.assertEqual(len(linked), 1)
        self.assertNotEqual(linked[0]["pid"], linked[0]["ppid"])

    def test_writer_pid_reused_on_different_host(self):
        writers = [r for r in rows("process_lineage.csv") if r["pid"] == "3880"]
        self.assertGreaterEqual(len(writers), 2)
        self.assertGreater(len({r["hostname"] for r in writers}), 1)

    def test_governance_rejection_precedes_unsigned_build(self):
        reject = next(r for r in rows("governance_audit.csv")
                      if r["control_state"] == "security_rejected")
        job = next(r for r in rows("ci_deliveries.csv")
                   if r["signing_status"] == "unsigned" and r["delivery_status"] == "applied")
        self.assertLess(reject["observed_utc"], job["observed_utc"])

    def test_firewall_decoys_have_different_protocol_and_port(self):
        decisions = rows("firewall_decisions.csv")
        self.assertTrue(any(r["protocol"] == "udp" and r["action"] == "deny" for r in decisions))
        self.assertTrue(any(r["destination_port"] == "8443" and r["action"] == "deny"
                            for r in decisions))

    def test_partial_telemetry_is_not_local_destruction(self):
        gaps = rows("collector_health.csv")
        self.assertTrue(any(r["source"] == "central-forwarder" and
                            r["local_source_retained"] == "yes" for r in gaps))

    def test_restoration_attempts_cannot_be_counted_as_proof_without_hash(self):
        attempts = [r for r in rows("rollback_validation.csv") if r["hostname"] == "nb-gw-07"]
        self.assertIn("mismatch_detected", {r["result"] for r in attempts})
        self.assertIn("applied_verified", {r["result"] for r in attempts})

    def test_pcap_truncation_is_detected(self):
        path = build_advanced.PCAP
        original = path.read_bytes()
        try:
            path.write_bytes(original[:-7])
            with self.assertRaises(ValueError):
                build_advanced.inspect_pcap()
        finally:
            path.write_bytes(original)

    def test_ipv4_checksum_tamper_is_detected(self):
        path = build_advanced.PCAP
        original = path.read_bytes()
        try:
            changed = bytearray(original)
            # PCAP global 24 + packet-record 16 + Ethernet 14 + IPv4 TTL byte 8
            offset = 24 + 16 + 14 + 8
            changed[offset] ^= 1
            path.write_bytes(bytes(changed))
            with self.assertRaises(ValueError):
                build_advanced.inspect_pcap()
        finally:
            path.write_bytes(original)

    def test_missing_authentication_join_is_detected(self):
        original_rows = verify_advanced.rows
        def missing_token(filename):
            result = original_rows(filename)
            if filename == "identity_risk.csv":
                return [r for r in result if r["session_id"] != "SID-88"]
            return result
        with patch.object(verify_advanced, "rows", side_effect=missing_token):
            with self.assertRaises(ValueError):
                verify_advanced.validate()

    def test_derived_sqlite_is_disclosed_and_queryable(self):
        with sqlite3.connect(f"file:{build_advanced.SQLITE}?mode=ro", uri=True) as conn:
            self.assertEqual(conn.execute("PRAGMA quick_check").fetchone()[0], "ok")
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM source_rows").fetchone()[0], 50)
            self.assertIn("NOT AN INDEPENDENT WITNESS",
                          conn.execute("SELECT value FROM provenance").fetchone()[0])

if __name__ == "__main__":
    unittest.main()

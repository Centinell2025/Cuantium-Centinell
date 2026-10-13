#!/usr/bin/env python3
"""Create one limited QC-001 Sherlock learner ZIP, without enterprise modules.

All content is simulated; validator checks internal consistency, not real
provenance, cryptographic implementation, or independent solver difficulty.
"""
from __future__ import annotations

import csv
import hashlib
import re
import zipfile
from datetime import datetime, timedelta
from pathlib import Path

LITE = Path(__file__).resolve().parents[1]
ROOT = LITE.parent
SOURCE = ROOT / "evidence"
DIST = LITE / "dist" / "QC001-The-Trust-Downgrade-LITE-STUDENT.zip"
PREFIX = "QC001-The-Trust-Downgrade/"
CSV_FILES = (
    "asset_inventory.csv", "policy_baseline.csv", "change_control.csv",
    "ci_deliveries.csv", "idp_sessions.csv", "host_audit.csv",
    "fim_events.csv", "clock_calibration.csv",
    "tls_observations.csv", "edge_flows.csv",
)
POLICIES = ("policy-hybrid.txt", "policy-classic.txt")
DOCUMENTS = (
    "README.txt", "docs/CASE_BRIEF.md", "docs/EVIDENCE_LIMITS.md",
    "questions/INVESTIGATION.md",
)

def rows(filename: str) -> list[dict[str, str]]:
    with (SOURCE / filename).open(newline="", encoding="utf-8") as handle:
        data = list(csv.DictReader(handle))
    if not data or any(None in r or any(v is None for v in r.values()) for r in data):
        raise ValueError(f"Missing or malformed CSV records: {filename}")
    return data

def require_one(items, purpose):
    if len(items) != 1:
        raise ValueError(f"{purpose}: expected exactly 1 match, got {len(items)}")
    return items[0]

def digest(filename):
    return hashlib.sha256((SOURCE / filename).read_bytes()).hexdigest()

def when(raw):
    if not raw.endswith("Z"):
        raise ValueError(f"Non-UTC timestamp: {raw}")
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))

def validate():
    for filename in CSV_FILES + POLICIES:
        if not (SOURCE / filename).is_file():
            raise FileNotFoundError(filename)
    for filename in DOCUMENTS:
        if not (LITE / "student" / filename).is_file():
            raise FileNotFoundError(filename)
    inventory, baselines = rows("asset_inventory.csv"), rows("policy_baseline.csv")
    changes, jobs = rows("change_control.csv"), rows("ci_deliveries.csv")
    idp, audit, fim = rows("idp_sessions.csv"), rows("host_audit.csv"), rows("fim_events.csv")
    calib, tls, flows = rows("clock_calibration.csv"), rows("tls_observations.csv"), rows("edge_flows.csv")

    host = require_one([r for r in inventory if r["role"] == "edge-tls-gateway"
                        and r["migration_wave"] == "PQC-W1" and r["criticality"] == "critical"],
                       "Target gateway")["hostname"]
    baseline = require_one([r for r in baselines if r["hostname"] == host
                            and r["policy_mode"] == "hybrid_required"], "Policy baseline")
    if baseline["specimen_file"] not in POLICIES:
        raise ValueError("Baseline refers to a file outside the student scope")
    if f"key_share={baseline['required_group']}\n" not in (SOURCE / baseline["specimen_file"]).read_text():
        raise ValueError("Intended key-share label differs from actual specimen bytes")
    ticket = require_one([r for r in changes if r["hostname"] == host
                          and r["approval_state"] == "rejected"
                          and r["change_scope"] == "legacy_fallback"], "Rejected change")
    job = require_one([r for r in jobs if r["hostname"] == host
                       and r["change_ticket"] == ticket["ticket"]
                       and r["signing_status"] == "unsigned"
                       and r["delivery_status"] == "applied"], "Unsigned applied build")
    writer = require_one([r for r in audit if r["hostname"] == host
                          and r["action"] == "write" and
                          r["target"] == "/etc/qc/tls-policy.conf"
                          and r["build_artifact_id"] == job["build_artifact_id"]], "File writer")
    session = require_one([r for r in idp if r["session_id"] == writer["session_id"]
                           and r["principal"] == writer["principal"]
                           and r["result"] == "success"], "Writer authentication")
    if when(session["observed_utc"]) > when(writer["observed_utc"]):
        raise ValueError("IdP login happens after host file write")
    changed_digest = digest("policy-classic.txt")
    if writer["policy_sha256"] != changed_digest:
        raise ValueError("Host audit digest differs from specimen bytes")
    measured = require_one([r for r in fim if r["hostname"] == host
                            and r["event_type"] == "modified"
                            and r["sha256"] == changed_digest], "Modified file integrity")
    if when(measured["observed_utc"]) < when(writer["observed_utc"]):
        raise ValueError("FIM reports changed specimen before local write")
    reload = require_one([r for r in audit if r["hostname"] == host
                          and r["action"] == "service_reload"
                          and r["build_artifact_id"] == job["build_artifact_id"]],
                         "Service reload")
    if when(reload["observed_utc"]) <= when(writer["observed_utc"]):
        raise ValueError("Reload time is not after write time")
    clock = require_one([r for r in calib if r["sensor"] == "edge-sensor"
                         and r["model"] == "recorded_utc_equals_actual_utc_plus_offset"],
                        "Sensor clock calibration")
    offset = int(clock["offset_seconds"])
    if offset <= 0:
        raise ValueError("Scenario requires positive source offset")
    normalize = lambda observation: when(observation["recorded_utc"]) - timedelta(seconds=offset)
    possible = [r for r in tls if r["hostname"] == host
                and r["sensor"] == clock["sensor"]
                and r["reported_group"] == "X25519"
                and normalize(r) > when(reload["observed_utc"])]
    if not possible:
        raise ValueError("Cannot establish post-reload classical-only observation")
    first_time = min(map(normalize, possible))
    first = require_one([r for r in possible if normalize(r) == first_time],
                        "Earliest normalized classical-only observation")
    flow = require_one([r for r in flows if r["connection_id"] == first["connection_id"]
                        and r["hostname"] == host
                        and r["source_ip"] == first["source_ip"]
                        and when(r["observed_utc"]) == first_time], "Matching network flow")
    if int(flow["reported_egress_bytes"]) <= 0:
        raise ValueError("Invalid reported byte counter")
    q = (LITE / "student/questions/INVESTIGATION.md").read_text(encoding="utf-8")
    nums = [int(x) for x in re.findall(r"(?m)^(\d{2})\.", q)]
    if nums != list(range(1, 17)):
        raise ValueError("Student file must contain exactly 16 consecutive graded questions")
    return {"graded_questions": len(nums), "csv_sources": len(CSV_FILES),
            "policy_specimens": len(POLICIES), "synthetic_records":
            sum(len(rows(name)) for name in CSV_FILES)}

def members():
    names = {n: (LITE / "student" / n).read_bytes() for n in DOCUMENTS}
    names.update({f"evidence/{n}": (SOURCE / n).read_bytes()
                  for n in CSV_FILES + POLICIES})
    return names

def manifest(mapping):
    return "".join(f"{hashlib.sha256(mapping[n]).hexdigest()}  {n}\n"
                   for n in sorted(mapping)).encode("utf-8")

def build():
    stats = validate()
    files = members()
    files["SHA256SUMS.txt"] = manifest(files)
    DIST.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(DIST, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            archive.writestr(PREFIX + name, files[name])
    verify(DIST)
    print(f"PASS: lightweight case produced: {stats}, {len(files)} student files")
    return DIST

def verify(path):
    expected = members()
    expected["SHA256SUMS.txt"] = manifest(expected)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or set(names) != {PREFIX + n for n in expected}:
            raise ValueError("Unexpected/missing student ZIP members")
        if archive.testzip() is not None:
            raise ValueError("Bad archive CRC")
        for name, payload in expected.items():
            if archive.read(PREFIX + name) != payload:
                raise ValueError(f"Archive member differs from evidence: {name}")
        if any(any(word in name.lower() for word in
                   ("instructor", "writeup", "answer_key", "enterprise", ".py", ".sqlite", ".pcap"))
               for name in names):
            raise ValueError("Out-of-scope proprietary module or answer leaked")

if __name__ == "__main__":
    build()

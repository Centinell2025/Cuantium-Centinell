#!/usr/bin/env python3
"""Validate consistency and source limitations of synthetic QC-001 evidence."""
from __future__ import annotations

import csv
import hashlib
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
CSV_FILES = (
    "asset_inventory.csv",
    "policy_baseline.csv",
    "change_control.csv",
    "ci_deliveries.csv",
    "idp_sessions.csv",
    "host_audit.csv",
    "fim_events.csv",
    "clock_calibration.csv",
    "tls_observations.csv",
    "edge_flows.csv",
)

def rows(filename: str) -> list[dict[str, str]]:
    with (EVIDENCE / filename).open(newline="", encoding="utf-8") as handle:
        data = list(csv.DictReader(handle))
    if not data:
        raise ValueError(f"No evidence records: {filename}")
    if any(not all(value is not None for value in row.values()) for row in data):
        raise ValueError(f"Broken CSV row: {filename}")
    return data

def sha256(filename: str) -> str:
    return hashlib.sha256((EVIDENCE / filename).read_bytes()).hexdigest()

def timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError(f"Non-UTC timestamp: {value}")
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.utcoffset() != timedelta(0):
        raise ValueError(f"Non-UTC timestamp: {value}")
    return dt

def unique(records: list[dict[str, str]], column: str) -> None:
    values = [r[column] for r in records]
    if len(values) != len(set(values)):
        raise ValueError(f"Duplicate IDs in {column}")

def validate() -> dict[str, int]:
    for filename in CSV_FILES + ("policy-hybrid.txt", "policy-classic.txt"):
        if not (EVIDENCE / filename).is_file():
            raise ValueError(f"Missing evidence: {filename}")
    data = {name: rows(name) for name in CSV_FILES}
    assets = {r["hostname"]: r for r in data["asset_inventory.csv"]}
    policies = data["policy_baseline.csv"]
    approvals = {r["ticket"]: r for r in data["change_control.csv"]}
    jobs = {r["build_artifact_id"]: r for r in data["ci_deliveries.csv"]}
    sessions = {r["session_id"]: r for r in data["idp_sessions.csv"]}
    audits = data["host_audit.csv"]
    fim = data["fim_events.csv"]
    offsets = {r["sensor"]: int(r["offset_seconds"]) for r in data["clock_calibration.csv"]}
    tls = data["tls_observations.csv"]
    flows = {r["connection_id"]: r for r in data["edge_flows.csv"]}

    for name, field in (
        ("asset_inventory.csv", "asset_id"),
        ("policy_baseline.csv", "baseline_id"),
        ("change_control.csv", "ticket"),
        ("ci_deliveries.csv", "job_id"),
        ("idp_sessions.csv", "idp_event_id"),
        ("host_audit.csv", "audit_id"),
        ("fim_events.csv", "fim_id"),
        ("clock_calibration.csv", "sensor"),
        ("tls_observations.csv", "tls_id"),
        ("edge_flows.csv", "flow_id"),
    ):
        unique(data[name], field)

    for policy in policies:
        if policy["hostname"] not in assets:
            raise ValueError("Policy refers to unknown host")
        specimen = EVIDENCE / policy["specimen_file"]
        if not specimen.is_file():
            raise ValueError("Baseline policy specimen absent")
        content = specimen.read_text(encoding="utf-8")
        # A baseline can intentionally require something other than the specimen
        # only if it is marked as a monitoring-only asset.
        if policy["policy_mode"] != "monitor_only":
            if f"mode={policy['policy_mode']}\n" not in content:
                raise ValueError("Baseline/specimen mode conflict")
            if f"key_share={policy['required_group']}\n" not in content:
                raise ValueError("Baseline/specimen group conflict")

    for job in data["ci_deliveries.csv"]:
        if job["hostname"] not in assets or job["change_ticket"] not in approvals:
            raise ValueError("Job references unknown asset or ticket")
        if job["hostname"] != approvals[job["change_ticket"]]["hostname"]:
            raise ValueError("Change ticket applies to another host")
        if job["delivery_status"] == "applied" and job["signing_status"] not in ("signed", "unsigned"):
            raise ValueError("Unexpected signing status")

    for audit in audits:
        if audit["hostname"] not in assets:
            raise ValueError("Audit refers to unknown asset")
        if audit["session_id"] not in sessions:
            raise ValueError("Audit references absent IdP session")
        if audit["principal"] != sessions[audit["session_id"]]["principal"]:
            raise ValueError("IdP principal disagrees with host audit")
        if sessions[audit["session_id"]]["result"] != "success":
            raise ValueError("A denied login cannot authenticate host audit")
        if audit["build_artifact_id"] not in jobs:
            raise ValueError("Audit references missing CI delivery")
        timestamp(audit["observed_utc"])
        if audit["action"] == "write":
            job = jobs[audit["build_artifact_id"]]
            if job["hostname"] != audit["hostname"] or job["delivery_status"] != "applied":
                raise ValueError("File write and CI delivery disagree")
            if audit["policy_sha256"] != sha256("policy-classic.txt"):
                raise ValueError("Policy write digest disagrees with actual specimen")

    if not any(f["event_type"] == "baseline" and f["sha256"] == sha256("policy-hybrid.txt") for f in fim):
        raise ValueError("No hash-supported baseline")
    if not any(f["event_type"] == "modified" and f["sha256"] == sha256("policy-classic.txt") for f in fim):
        raise ValueError("No hash-supported changed state")

    if "edge-sensor" not in offsets:
        raise ValueError("Missing sensor calibration")
    target = [r for r in audits if r["action"] == "service_reload" and r["hostname"] == "nb-gw-07"]
    if len(target) != 1:
        raise ValueError("Ambiguous gateway reload")
    reload_utc = timestamp(target[0]["observed_utc"])

    matched_after = []
    for obs in tls:
        if obs["sensor"] not in offsets or obs["connection_id"] not in flows:
            raise ValueError("Sensor or connection cannot be verified")
        flow = flows[obs["connection_id"]]
        if (flow["hostname"], flow["source_ip"]) != (obs["hostname"], obs["source_ip"]):
            raise ValueError("Five-tuple/source disagreement")
        actual = timestamp(obs["recorded_utc"]) - timedelta(seconds=offsets[obs["sensor"]])
        if actual != timestamp(flow["observed_utc"]):
            raise ValueError("Sensor UTC normalization disagrees with flow")
        if obs["hostname"] == "nb-gw-07" and obs["reported_group"] == "X25519" and actual > reload_utc:
            matched_after.append(obs)
    if len(matched_after) < 2:
        raise ValueError("Insufficient classical-only post-reload observations")

    investigation = (ROOT / "questions" / "INVESTIGATION.md").read_text(encoding="utf-8")
    numbers = [int(m.group(1)) for m in re.finditer(r"(?m)^(\d{2})\.", investigation)]
    if numbers != list(range(1, 23)):
        raise ValueError("Expected 22 sequential investigation prompts")
    required_limits = ("synthetic", "NOT a verified", "not evidence")
    limits = (ROOT / "docs" / "EVIDENCE_LIMITS.md").read_text(encoding="utf-8")
    if not all(term.lower() in limits.lower() for term in required_limits):
        raise ValueError("Evidence limits are incomplete")
    return {"csv_sources": len(CSV_FILES), "records": sum(len(d) for d in data.values()), "graded_tasks": len(numbers)}

if __name__ == "__main__":
    result = validate()
    print("PASS: synthetic evidence validated:", result)

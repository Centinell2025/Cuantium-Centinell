#!/usr/bin/env python3
"""Check deep cross-source provenance, recovery state and real binary structure.

These checks concern a fully synthetic training dataset, not a real incident.
"""
from __future__ import annotations

import sqlite3
from datetime import timedelta

from verify_case import EVIDENCE, rows, sha256, timestamp, validate as validate_core
from build_advanced import SQLITE, build, inspect_pcap

def singleton(items, reason):
    if len(items) != 1:
        raise ValueError(f"{reason}: expected unique match; observed {len(items)}")
    return items[0]

def validate():
    core = validate_core()
    build()
    process = rows("process_lineage.csv")
    audit = {row["audit_id"]: row for row in rows("host_audit.csv")}
    sessions = {row["session_id"]: row for row in rows("idp_sessions.csv")}
    governance = rows("governance_audit.csv")
    changes = {row["ticket"]: row for row in rows("change_control.csv")}
    jobs = rows("ci_deliveries.csv")
    identity = rows("identity_risk.csv")
    firewall = rows("firewall_decisions.csv")
    gaps = rows("collector_health.csv")
    rollback = rows("rollback_validation.csv")
    recipe = rows("packet_recipe.csv")
    tls = rows("tls_observations.csv")
    flows = rows("edge_flows.csv")

    for source, column in (
        (process, "process_event_id"),
        (governance, "governance_event_id"),
        (identity, "risk_event_id"),
        (firewall, "decision_id"),
        (gaps, "gap_id"),
        (rollback, "rollback_id"),
        (recipe, "connection_id"),
    ):
        ids = [r[column] for r in source]
        if len(set(ids)) != len(ids):
            raise ValueError(f"Duplicate identifier: {column}")
    writer = singleton(
        [r for r in process if r["hostname"] == "nb-gw-07"
         and r["related_audit_id"] == "AUD-101" and r["session_id"] == "SID-88"],
        "Writer process"
    )
    if writer["observed_utc"] != audit["AUD-101"]["observed_utc"]:
        raise ValueError("Writer event and host audit disagree")
    if writer["pid"] == writer["ppid"]:
        raise ValueError("Writer cannot be own parent")
    parents = [r for r in process if r["hostname"] == writer["hostname"]
               and r["pid"] == writer["ppid"] and r["session_id"] == writer["session_id"]]
    singleton(parents, "Writer parent")
    if writer["session_id"] not in sessions or sessions[writer["session_id"]]["result"] != "success":
        raise ValueError("Host process has no valid authenticated session")
    if not any(r["hostname"] != writer["hostname"] and r["pid"] == writer["pid"] for r in process):
        raise ValueError("Missing cross-host duplicate PID decoy")

    unsigned = singleton([r for r in jobs if r["hostname"] == writer["hostname"]
                          and r["signing_status"] == "unsigned"
                          and r["delivery_status"] == "applied"], "Unsigned applied job")
    rejected = singleton([r for r in governance if r["change_ticket"] == unsigned["change_ticket"]
                          and r["control_state"] == "security_rejected"], "Governance rejection")
    if timestamp(rejected["observed_utc"]) >= timestamp(unsigned["observed_utc"]):
        raise ValueError("Security rejection does not precede unapproved deployment")
    if changes[unsigned["change_ticket"]]["approval_state"] != "rejected":
        raise ValueError("Unsigned job not tied to denied change")
    risks = [r for r in identity if r["session_id"] == writer["session_id"]
             and r["principal"] == sessions[writer["session_id"]]["principal"]
             and r["risk_class"] == "off_window_service_token"]
    risk = singleton(risks, "Identity anomaly")
    if not (timestamp(sessions[writer["session_id"]]["observed_utc"])
            <= timestamp(risk["observed_utc"])
            <= timestamp(unsigned["observed_utc"])):
        raise ValueError("Risk time inconsistent with IdP and CI delivery")

    observed = singleton([r for r in tls if r["hostname"] == writer["hostname"]
                          and r["connection_id"] == "CONN-601"], "Post-change TLS observation")
    flow = singleton([r for r in flows if r["connection_id"] == observed["connection_id"]],
                     "Matched flow")
    allowed = singleton([r for r in firewall
                         if r["connection_id"] == flow["connection_id"]
                         and r["hostname"] == flow["hostname"]
                         and r["source_ip"] == flow["source_ip"]
                         and r["destination_ip"] == flow["destination_ip"]
                         and r["destination_port"] == flow["destination_port"]
                         and r["protocol"] == "tcp" and r["action"] == "allow"],
                        "Allowed five-tuple")
    if timestamp(allowed["observed_utc"]) != timestamp(flow["observed_utc"]):
        raise ValueError("Firewall permit time disagrees with flow")
    denied_decoy = singleton(
        [r for r in firewall if r["hostname"] == flow["hostname"]
         and r["source_ip"] == flow["source_ip"]
         and r["protocol"] == "tcp" and r["destination_port"] == "8443"
         and r["action"] == "deny"], "Denied TCP lookalike"
    )
    if denied_decoy["connection_id"] == flow["connection_id"]:
        raise ValueError("Denied decoy must be separate connection")
    if not any(r["protocol"] == "udp" and r["action"] == "deny"
               and r["source_ip"] == flow["source_ip"] for r in firewall):
        raise ValueError("Protocol lookalike missing")

    local_write_utc = timestamp(audit["AUD-101"]["observed_utc"])
    gap = singleton([r for r in gaps if r["hostname"] == writer["hostname"]
                     and r["source"] == "central-forwarder"
                     and timestamp(r["from_utc"]) <= local_write_utc <= timestamp(r["to_utc"])],
                    "Overlapping central forwarding gap")
    if gap["local_source_retained"] != "yes":
        raise ValueError("Central gap incorrectly marked as local source deletion")

    approved = singleton([r for r in changes.values()
                          if r["hostname"] == writer["hostname"] and
                          r["change_scope"] == "hybrid_restoration"
                          and r["approval_state"] == "approved"], "Authorized rollback")
    approval_events = [r for r in governance if r["change_ticket"] == approved["ticket"]
                       and r["control_state"] == "approved"]
    consent = singleton(approval_events, "Rollback governance approval")
    failed = singleton([r for r in rollback if r["hostname"] == writer["hostname"]
                        and r["change_ticket"] == approved["ticket"]
                        and r["result"] == "mismatch_detected"], "First rollback attempt")
    good = singleton([r for r in rollback if r["hostname"] == writer["hostname"]
                      and r["change_ticket"] == approved["ticket"]
                      and r["result"] == "applied_verified"], "Locally verified rollback")
    if failed["observed_policy_sha256"] != sha256("policy-classic.txt"):
        raise ValueError("Failed rollback hash not from actual changed specimen")
    if (good["observed_policy_sha256"] != sha256("policy-hybrid.txt") or
        good["expected_baseline_sha256"] != sha256("policy-hybrid.txt") or
        good["verification_scope"] != "local_file_bytes"):
        raise ValueError("Successful rollback does not match provided specimen bytes")
    if not (timestamp(consent["observed_utc"]) < timestamp(failed["observed_utc"])
            < timestamp(good["observed_utc"])):
        raise ValueError("Rollback lifecycle order invalid")
    if not (timestamp(approved["valid_from_utc"]) <= timestamp(good["observed_utc"])
            <= timestamp(approved["valid_to_utc"])):
        raise ValueError("Rollback outside its approved window")
    if not any(r["result"] == "rechecked" and
               timestamp(r["observed_utc"]) > timestamp(good["observed_utc"]) and
               r["observed_policy_sha256"] == good["observed_policy_sha256"] for r in rollback):
        raise ValueError("No follow-up measurement after rollback")

    count, totals = inspect_pcap()
    matched = singleton([r for r in recipe if r["connection_id"] == flow["connection_id"]],
                        "PCAP recipe for selected connection")
    packet_key = (matched["source_ip"], int(matched["source_port"]),
                  matched["destination_ip"], int(matched["destination_port"]))
    observed_app_bytes = totals.get(packet_key)
    if observed_app_bytes != len(matched["payload_ascii"].encode("ascii")):
        raise ValueError("PCAP client payload does not match recorded recipe")
    if int(flow["reported_egress_bytes"]) <= observed_app_bytes:
        raise ValueError("Flow-to-packet observation gap unexpectedly absent")
    for row in recipe:
        key = (row["source_ip"], int(row["source_port"]),
               row["destination_ip"], int(row["destination_port"]))
        if totals.get(key) != len(row["payload_ascii"].encode("ascii")):
            raise ValueError("Packet source/direction count mismatch")

    connection = sqlite3.connect(f"file:{SQLITE}?mode=ro", uri=True)
    try:
        if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("SQLite derived evidence damaged")
        row_count = connection.execute("SELECT COUNT(*) FROM source_rows").fetchone()[0]
        distinct_sources = connection.execute("SELECT COUNT(DISTINCT source_file) FROM source_rows").fetchone()[0]
        statement = connection.execute("SELECT value FROM provenance WHERE key='disclosure'").fetchone()[0]
        if row_count < 50 or distinct_sources < 15 or "NOT AN INDEPENDENT WITNESS" not in statement:
            raise ValueError("Derived database lacks documented, multi-source rows")
    finally:
        connection.close()
    return {
        **core,
        "binary_pcap_packets": count,
        "scoped_client_payload_bytes": observed_app_bytes,
        "derived_sql_rows": row_count,
        "additional_csv_sources": len((process, governance, identity, firewall, gaps, rollback, recipe)),
        "reviewer_approval": "PENDING: independent blind solve and confidential answer key"
    }

if __name__ == "__main__":
    print("PASS: advanced synthetic DFIR evidence and negative-inference gates:", validate())

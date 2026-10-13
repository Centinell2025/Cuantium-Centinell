# Examiner-independent correlation matrix — QC-001 v2

This file identifies **source families and investigative methods**, not the confidential answers.

| Question range | Evidence to reconcile | Specific ambiguity to eliminate |
| --- | --- | --- |
| 01–05 | asset_inventory, policy_baseline, real policy specimen bytes | Expected configuration is not an observed handshake |
| 06–09 | change_control, governance_audit, ci_deliveries | A signed/approved unrelated build is a decoy |
| 10–14 | idp_sessions, host_audit, process_lineage, fim_events | Service principal is not an identified human |
| 15–20 | tls_observations, clock_calibration, edge_flows | Per-sensor UTC offset and same five-tuple are essential |
| 21–22 | idp_sessions, limits of synthetic crypto metadata | No proven cryptographic primitive or hardware attestation |
| 23–24 | process_lineage, host_audit, IdP session | Distinguish writer PID from its parent and same PID on another host |
| 25–26 | governance_audit, ci_deliveries, identity_risk | Rejection predates unsigned build; token alert is not actor attribution |
| 27–28 | firewall_decisions, edge_flows, TLS metadata | Allowing TCP/443 is distinct from rejecting TCP/8443 or UDP/443 |
| 29 | collector_health, local host_audit | A central forwarding gap does not prove local record deletion |
| 30–32 | change_control, governance_audit, rollback_validation, specimen SHA-256 | An approved rollback can fail first, then show locally verified bytes |
| 33–34 | real synthetic pcap bytes, packet_recipe, edge_flows | Partial captured payload is not full flow volume or exfiltration |

**Caution:** Cross-checking exports of the same simulated generator does not establish independent provenance. The SQLite index is derived from these same rows and does not constitute a second source.

**Human review:** reject answers that rely solely on a copied headline or conflate simulated labels with independently authenticated TLS/ML-KEM operations.

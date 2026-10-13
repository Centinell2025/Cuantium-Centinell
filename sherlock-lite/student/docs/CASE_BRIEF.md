# QC-001 — The Trust Downgrade

**Fictional organization:** Northbridge Systems
**Incident date:** 2026-10-10 UTC
**Publisher:** Beacon of the Eagle LLC / Centinell Suite Defense

## Case assignment

An edge gateway assigned to migration wave PQC-W1 was intended to run a hybrid key-exchange policy. During a maintenance interval, a reported classical-only policy appeared. A service principal was observed, the CI pipeline recorded both legitimate and questionable activities, and one network sensor has a positive clock offset.

Your job is to establish the intended policy, whether the applied change was approved, the session linked to the local configuration write, the hash of the changed bytes, the first corrected observation after service reload, and what the limited evidence can actually prove.

## Evidence inventory

- asset_inventory.csv + policy_baseline.csv: locate the target and required group
- policy-hybrid.txt + policy-classic.txt: exact inspectable configuration bytes
- change_control.csv + ci_deliveries.csv: approvals, signing and build deliveries
- idp_sessions.csv + host_audit.csv: authenticated service identity and recorded actions
- fim_events.csv: reported file integrity after the write
- clock_calibration.csv + tls_observations.csv + edge_flows.csv: normalize UTC and match the relevant flow

## Rules

Use the delivered ZIP only. Record filenames, event IDs, hashes and time corrections. Do not infer attribution to a named human, authenticated cryptographic handshake, physical host compromise or data theft from simulated CSV observations. No live systems are available or authorized for probing.

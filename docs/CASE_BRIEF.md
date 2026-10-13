# QC-001 — The Trust Downgrade

**Classification:** Synthetic defensive DFIR training · proposed Sherlock difficulty: Medium/Hard (not yet calibrated)

At 03:18 UTC on 10 October 2026, the fictional Northbridge Systems SOC received an alert that edge gateway `nb-gw-07` had apparently reverted from its planned hybrid key-exchange policy to a classical-only fallback. Network monitoring later showed classical-only negotiated-group **labels**, but the sensor clock is not perfectly synchronized. Management believes a maintenance ticket authorized the change; a separate change-control source disagrees.

Your task is to distinguish:
- the **written configuration bytes** from a configuration claim;
- rejected change requests from legitimately approved work;
- a service principal from a named human actor;
- reported TLS metadata from actual cryptographic packet captures;
- source clock time from corrected UTC;
- potential policy exposure from actual evidence of exploitation or data theft.

## Expanded version 2 laboratory

The student ZIP adds process-lineage joins, simulated governance and identity-audit streams, firewall protocol and port decoys, a central forwarding gap, and a multi-step rollback. It also includes **parseable synthetic PCAP bytes** and a SQLite cache **derived from the CSV sources**. There are 34 exact-answer tasks plus 12 non-graded expert exercises. These additions do not transform the fictional dataset into a native acquisition or independently authenticate any ML-KEM handshake.

## Practical workflow
1. Preserve the original files; check the package SHA-256 manifest.
2. Trace each asset and its required crypto policy.
3. Rehash both policy specimens and compare snapshot/FIM rows.
4. Join change approvals, CI deliveries and host audit actions.
5. Apply the sensor-specific clock offset to TLS observations.
6. Correlate the normalized network tuple and assess what the available logs prove.
7. Supply exactly one result for each numbered question, with artifact and record IDs.

Everything in this scenario is fictional. Never test or scan any live gateway.

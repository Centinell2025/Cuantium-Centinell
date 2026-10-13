# QC-001 v2 — The Trust Downgrade: 34 exact-response tasks

Read `README.txt` and `docs/CASE_BRIEF.md` first. For every result, retain an artifact name, record ID and explanation in your notebook. Do not assume a recorded group name proves a real TLS or ML-KEM handshake.

## Stage 1 — Scope and policy

01. Which **hostname** in the asset inventory is the critical edge gateway in migration wave `PQC-W1`? **Format:** lowercase hostname.
02. What exact **policy mode** does that gateway's baseline require? **Format:** literal token.
03. What **key-share group label** is recorded in the policy baseline for that gateway? **Format:** literal token.
04. Which policy specimen filename contains the baseline's intended mode and group? **Format:** basename with extension.
05. Compute the SHA-256 of the baseline specimen **bytes**. What is its 64-character lowercase digest? **Format:** hex digest.

## Stage 2 — Authorization, delivery and file integrity

06. Which specific **change ticket** requested the gateway's classical-only fallback but was **rejected**? **Format:** `CHG-NNN`.
07. Which **approved change ticket** applies to the backup host, rather than the gateway? **Format:** `CHG-NNN`.
08. Which CI **job ID** delivered an **unsigned** classical-only configuration to the affected gateway? **Format:** `JOB-NNN`.
09. What exact **build artifact ID** did that unsigned job reference? **Format:** `CFG-NN`.
10. Which authenticated **session ID** joins the gateway configuration write to its preceding deployment login? **Format:** `SID-NN`.
11. Which **audit event ID** records the gateway's actual local policy-file write? **Format:** `AUD-NNN`.
12. Which **FIM event ID** first registers the digest of the changed classical-only configuration? **Format:** `FIM-NNN`.
13. Recompute the SHA-256 of the changed policy-specimen **bytes**. What exact digest matches the post-write evidence? **Format:** 64 lowercase hex characters.
14. At what exact UTC time does the audit stream record the gateway's service reload? **Format:** `YYYY-MM-DDTHH:MM:SSZ`.

## Stage 3 — Network, clocks and identity limits

15. Which TLS **observation ID** is the **earliest normalized** classical-only group reported for the gateway after its service reload? **Format:** `TLS-NNN`.
16. What is that observation's **normalized UTC timestamp** after applying its sensor's clock offset? **Format:** `YYYY-MM-DDTHH:MM:SSZ`.
17. Which **sensor name** and **positive offset (seconds)** produced the recorded/true-time disagreement? **Format:** `sensor_name:+NN`.
18. Which **connection ID** joins that normalized classical-only observation to the edge-flow table? **Format:** `CONN-NNN`.
19. What exact **source IP address** appears in the matched edge-flow observation? **Format:** dotted IPv4.
20. What **egress byte count** is recorded for the matched flow? **Format:** decimal integer; do not infer data theft.
21. Which **identity principal** is linked to the local write through the authenticated session? **Format:** exact principal.
22. Based on this dataset, is a real hardware-backed or externally validated **post-quantum cryptographic handshake** established? **Format:** `ESTABLISHED` or `NOT ESTABLISHED`.


## Stage 4 — Deep DFIR: process, governance and token lineage

23. Join the gateway audit file-write event to the system process lineage using the exact host, audit ID and service session; ignore the similarly numbered process on another host. What decimal **PID actually wrote the file**? **Format:** decimal PID.
24. Walk one edge backward from that exact writer PID, ensuring the parent belongs to the same host/session. What is the immediate **parent PID**? **Format:** decimal PID.
25. Which unique governance event records the **security rejection of the classical-only change** before the unsigned CI job executed? Exclude the earlier pending event and later quarantine event. **Format:** GOV-NNN.
26. Correlate the authenticated writer session with the separate identity-risk stream. Which event marks the **off-window service token**? Do not interpret this as proof of the operator's human identity. **Format:** ALERT-NNN.

## Stage 5 — Firewall truth and central telemetry gaps

27. Starting with the corrected classical-only TLS observation, join connection ID, source address, destination address, destination port and **TCP** protocol. Which firewall event records an **allow** for that exact connection? **Format:** FW-NNN.
28. The same client IP/port generated a blocked **TCP connection to destination port 8443**. Which firewall decision ID is the *denied lookalike*? Ignore the UDP/443 distractor. **Format:** FW-NNN.
29. What is the central-forwarding **gap ID** whose interval overlaps the gateway's local audited file write? Explain in your work notes why partial central forwarding is not proof the local record was deleted. **Format:** GAP-NNN.

## Stage 6 — Recovery, hash validation and packet bytes

30. Which **approved change ticket** governed restoration of the hybrid gateway policy, rather than the rejected downgrade or unrelated backup task? **Format:** CHG-NNN.
31. The first restoration attempt still had the changed-policy hash. Which **rollback event** is the earliest one with locally verified policy bytes matching the baseline? **Format:** RB-NNN.
32. At which exact **UTC timestamp** was that first successful local hash verification recorded? **Format:** YYYY-MM-DDTHH:MM:SSZ.
33. Parse the provided synthetic **PCAP binary**. For the connection that matches the first normalized classical-only gateway observation, count only **client-to-server TCP application-payload bytes**, excluding Ethernet, IPv4, TCP headers, ACK-only frames and server replies. What is the captured byte total? **Format:** decimal bytes.
34. For the same connection, subtract the PCAP's observed client payload bytes from the edge flow's **reported egress byte count**. What is the resulting **measurement gap**? This is **not** a proven exfiltration amount. **Format:** decimal bytes.

Read docs/PCAP_SQL_GUIDE.md for offline packet/SQL techniques. For deeper professional assessment, complete the 12 ungraded expert tasks in docs/EXPERT_BOARD.md. Those do not add graded flags.

## Unscored professional finding

Draft a one-page incident determination separating observed unauthorized **policy state**, limits of simulated handshake evidence, possible risk to future session confidentiality, unverified operator identity, and safe restoration under approved change control.

All exhibits are **synthetic**. Challenge difficulty, answer uniqueness and external suitability remain subject to independent blind review.

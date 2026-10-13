# QC-001 — The Trust Downgrade: 22 exact-response tasks

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

## Unscored professional finding

Draft a one-page incident determination separating observed unauthorized **policy state**, limits of simulated handshake evidence, possible risk to future session confidentiality, unverified operator identity, and safe restoration under approved change control.

All exhibits are **synthetic**. Challenge difficulty, answer uniqueness and external suitability remain subject to independent blind review.

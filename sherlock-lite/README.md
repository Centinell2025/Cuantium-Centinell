# QC-001 LITE — The Trust Downgrade

**Publisher:** Beacon of the Eagle LLC · Centinell Suite Defense
**Format:** HTB Sherlock candidate, fully fictional standalone DFIR case
**Proposed difficulty:** Medium/Hard, subject to external calibration

This is a **deliberately bounded** Sherlock edition of Cuantium-Centinell. It contains **16 exact-response questions, 10 synthetic CSV sources, 2 plain-text configuration specimens, 4 student instructions, and a SHA-256 manifest**. It does not distribute the expanded project's generated PCAP, derived SQLite database, code, architecture, advanced board, or instructor solutions.

## Scope

The analyst must correlate a disputed cryptographic **configuration** rollback at fictional Northbridge Systems using baseline policy, rejected change, unsigned CI job, authenticated service session, local write/FIM, clock calibration and network-flow metadata. The collection **does not prove** a real ML-KEM handshake, TLS key establishment, hardware compromise or exfiltration.

## Build

From the repository root with Python 3.10+:

    python3 sherlock-lite/tools/build_lite.py
    python3 -m unittest discover -s sherlock-lite/tests -v

This creates sherlock-lite/dist/QC001-The-Trust-Downgrade-LITE-STUDENT.zip. GitHub Actions publishes its byte-identical contents with password **hackthebox**.

## Student and reviewer guidance

Distribute only the student ZIP, not the author source repository, for a blind solve. Extract the archive, read README.txt, verify SHA256SUMS.txt and investigate the 16 questions. Instructor answers belong in separately restricted files.

**Public source limitation:** The expanded Cuantium-Centinell repository and its older releases were already public. Limiting this ZIP does not make those previously published research files confidential. No independent difficulty measurement or official HTB approval is claimed.

© 2026 Beacon of the Eagle LLC — Centinell Suite Defense.

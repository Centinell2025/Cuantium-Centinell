<div align="center">
  <img src="https://raw.githubusercontent.com/Centinell2025/the-last-evidence-standing/main/branding/BEACON_SEAL.png" width="160" alt="Beacon of the Eagle LLC seal" />
  <p><strong>BEACON OF THE EAGLE LLC</strong><br/><strong>CENTINELL SUITE DEFENSE</strong></p>
</div>

# Cuantium Centinell

**Quantum-safe migration readiness · Cryptographic asset inventory · Defensive DFIR research**

Cuantium Centinell is an original cybersecurity research and training project from **Beacon of the Eagle LLC**, under **Centinell Suite Defense**. The first reproducible exercise, **QC-001 — The Trust Downgrade**, teaches investigators how to identify a disputed cryptographic-policy rollback without misrepresenting simulated telemetry as a real post-quantum cryptography implementation.

> **Project status:** runnable educational prototype and Sherlock candidate. Not a production encryption product, not cryptographically certified, not an HTB-approved Sherlock, and not independently rated Hard.

## What the lab investigates

During a fictional enterprise rollout of a proposed hybrid key-exchange policy, a critical edge gateway switches from an expected hybrid configuration to a classical-only fallback. A rejected change ticket, a service-principal session, unsigned build metadata, a local write, conflicting timestamps, and partial TLS sensor observations must be correlated to determine what happened **and what cannot be proven**.

### Start here

1. Read [student case briefing](docs/CASE_BRIEF.md) and [evidence limitations](docs/EVIDENCE_LIMITS.md).
2. Examine [34 exact-answer investigation questions](questions/INVESTIGATION.md).
3. Generate the student package and verify the synthetic dataset: `python3 tools/verify_advanced.py && python3 tools/build_student.py`.
4. Run local checks: `python3 -m unittest discover -s tests -v`.
5. Follow [reviewer handoff](docs/REVIEWER_HANDOFF.md) for packaging, ethics, and open quality gates.

## Version 2 forensic depth

The expanded investigation correlates **process ancestry, rejected change-control events, risk-scored service tokens, TCP/UDP firewall decoys, partial central forwarding and multi-step rollback**. The learner must inspect a byte-level synthetic PCAP and query a provenance-disclosed SQLite index. All acquisition and cryptographic claims remain strictly simulated. See [correlation matrix](docs/CORRELATION_MATRIX.md), [PCAP/SQLite guide](docs/PCAP_SQL_GUIDE.md), [quality gates](docs/QUALITY_GATES_V2.md), and [expert review board](docs/EXPERT_BOARD.md).

**Quality status:** Author-side packet, integrity and negative-control tests are required. Native independently acquired artifacts, a confidential 34-answer instructor write-up and independent blind solves remain outstanding.

## Repository structure

| Folder | Description |
| --- | --- |
| `evidence/` | Original synthetic CSV observations, policy bytes, generated **synthetic PCAP and derived SQLite** |
| `questions/` | Student-only, exact-answer DFIR challenges |
| `tools/` | Binary generator, cross-source verifiers and packaging tools |
| `tests/` | Automated cross-source, packet checksum and tamper negative-control tests |
| `docs/` | Scenario, architecture, provenance, submission readiness |
| `.github/workflows/` | CI validation and HTB-style password-protected ZIP release |

## Build student evidence package

Requires **Python 3.10+**, standard library only. No virtual machine, live target, outbound network connection, actual PQC implementation or third-party credentials are needed.

```bash
python3 tools/verify_case.py
python3 tools/verify_advanced.py
python3 -m unittest discover -s tests -v
python3 tools/build_student.py
```

The student ZIP built locally is not password-protected; the GitHub Actions release wraps the exact verified student contents in an encrypted ZIP using password **`hackthebox`**, as requested by the HTB submission interface. ZipCrypto password protection is packaging access control, **not modern encryption for sensitive information**.

## Responsible research boundaries

This lab refers to a **simulated** key-share label `X25519MLKEM768` as inventory metadata only; it does **not** perform an ML-KEM exchange, validate TLS handshakes, prove real quantum resistance, provide a FIPS compliance claim, or establish exfiltration from flow byte counts. The cited post-quantum standards are background design context, not implemented library primitives.

The whole source repository is public and may expose author design choices. Blind testers should receive **only the student ZIP**, never this source tree. Confidential grading answers and instructor walkthroughs must live outside this repository.

**Copyright © 2026 Beacon of the Eagle LLC — Centinell Suite Defense.** Synthetic training and authorized defensive research only.

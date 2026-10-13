# QC-001 v2 engineering and reviewer acceptance gates

**Owner:** Beacon of the Eagle LLC — Centinell Suite Defense  
**Difficulty proposed:** Hard, unverified by external analysts  
**Scenario:** Fully simulated, no real victims or cryptographic key establishment

## Engineering checks

1. Exact 34 unique, numbered answer prompts in an offline student archive.
2. Policy specimen SHA-256 must match evidence metadata; any modification causes verification failure.
3. Denied service tokens must not be accepted as a successful host login.
4. Source-specific clock normalization must reconcile selected TLS observations to flow timestamps.
5. The gateway writer must join on hostname, session and exact host audit ID; a reused PID on another host must not be counted.
6. Governance security rejection must predate the unsigned deployment, and rollback approval must be distinct.
7. Firewall decision must match the TCP five-tuple and action, not just the source IP address.
8. Central forwarding gaps must not be presented as evidence of data destruction.
9. Rollback status must be checked against calculated specimen digests, not only a success label.
10. Generated PCAP must contain valid IP/TCP checksums and a parseable packet stream. Only directional application payload counts.
11. Derived SQLite must pass PRAGMA quick_check and contain a documented, read-only, reproducible ingestion of CSV sources.
12. Student archive allowlist and SHA-256 manifest must match every delivered file.
13. Password-protected public release must be test-extracted with the password hackthebox and compared byte-for-byte with verified source archive.
14. Neither private answer keys nor instructor walkthroughs are published in this public repository.

## Still required before submission

- [ ] A confidential, examiner-readable walkthrough proving all 34 answers and identifying the exact source rows and commands.
- [ ] Independent cold solves by two experienced DFIR analysts.
- [ ] Timed difficulty calibration and ambiguity reduction.
- [ ] Review of HTB grading schema, download permissions, ZIP requirements and intellectual property.
- [ ] Native external captures or stronger independently collected artifacts if the publisher wishes to justify an Insane classification.

**No passing CI result, synthetic PCAP, or sample code constitutes a certified post-quantum cryptography implementation.**

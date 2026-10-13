# QC-001 — Expert investigative board (ungraded)

These additional tasks require a **written analytic determination supported by exact source IDs**, not unreviewed multiple-choice flags. Use at least two distinct source *families* for each affirmative claim; distinguish independently acquired data from duplicated or derived exports.

1. Build the raw and corrected UTC timeline for the gateway policy change. Explain exactly why the sensor's reported TLS timestamp cannot be placed directly beside the host audit timestamp.
2. Reconstruct the service principal's authorization path. Which events establish an authenticated session, and which necessary facts are missing to attribute the action to a specific human?
3. Compare governance approval, CI signing, host audit write and FIM measurement. Which observation is an authorization fact, a deployment claim, and a locally observed file state?
4. Demonstrate the complete process lineage for the file writer. Explain why matching a PID without the hostname or authenticated session is insufficient.
5. Investigate the classical-only TLS observation as an **unverified metadata claim**. What real handshake evidence would be needed to support a statement about performed ML-KEM exchange or negotiated cryptographic strength?
6. Match the relevant five-tuple across firewall, flow export and real parseable synthetic PCAP. Explain how packet checksums can show internal packet consistency without establishing provenance from real traffic.
7. Calculate the gap between the reported flow bytes and the scoped captured outbound application payload. Explain why this does not establish transmission of the missing bytes or data exfiltration.
8. Compare a central forwarding gap to the locally retained host audit event. Explain why delayed/partial forwarding cannot establish intentional log erasure.
9. Assess the approved recovery ticket and the two separate local hash observations. Under what conditions should a change board treat the corrected local policy as insufficient proof of fully restored production TLS posture?
10. Describe a chain-of-custody protocol for future real-world acquisition: evidence source, capture operator, timestamps, hashes, transfer register, isolation boundary and re-verification.
11. Design one **negative-control test** per evidence family that would disprove the investigator's preferred incident narrative.
12. Draft an executive opinion with (a) verified observations, (b) simulated assertions, (c) derived calculations, (d) material unknowns and (e) actionable next steps that do not assume a real quantum-capable attacker.

**Assessment:** A reviewer may evaluate completeness, reproducibility, forensic skepticism, precision of source citations, contradictory evidence handling, and recovery safety. These are **not** 12 additional HTB scoring flags.

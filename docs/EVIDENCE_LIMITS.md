# Scope, provenance, and scientific limits

- The user identities, devices, systems, addresses, event chronology, tickets and observation sources are fictional.
- All time-stamped CSV files are **synthetic representations**, not EVTX, cloud audit API acquisitions, syslog originals or authentic PCAPs.
- `X25519MLKEM768` in the dataset is a **declared policy/observation label**, not evidence of a real post-quantum key exchange.
- A conventional RSA-PSS certificate signature is distinct from a hybrid key exchange; the certificate row alone neither proves nor disproves hybrid KEX.
- NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) are relevant standards, but **none is implemented or certified by this repository**.
- A local policy-file SHA-256 proves only the integrity of delivered bytes, not independent authenticity of the collection, firmware state, hardware provenance or remote handshake authenticity.
- Observed flow byte counters are not evidence of external exfiltration or malicious payload content.
- Sensor-specific recorded timestamps must be normalized using `recorded_utc = true_utc + offset_seconds`.
- A service principal or session reference does not identify an operator.
- Public test scripts confirm **internal consistency**, not independent difficulty calibration or HTB acceptance.

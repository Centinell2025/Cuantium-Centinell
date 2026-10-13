# Post-quantum transition research map

| Standard | Name | Relevant defensive inventory question | Implemented here? |
| --- | --- | --- | --- |
| NIST FIPS 203 | ML-KEM | Which assets are planned for key-establishment migration? | No |
| NIST FIPS 204 | ML-DSA | What digital-signature families appear in code and certificate inventories? | No |
| NIST FIPS 205 | SLH-DSA | Which long-term signature dependencies need review? | No |

This training exercises **asset classification, governance, crypto-agility planning, event correlation and logging quality**. It never performs a real post-quantum handshake or measures quantum-safe security strength.

Any future product implementation must use maintained, validated cryptographic libraries; formal interoperability testing; independent security review; and a documented migration/change-control model.

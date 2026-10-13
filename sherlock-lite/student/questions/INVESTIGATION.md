# QC-001 LITE — The Trust Downgrade: 16 exact-answer questions

Use only the supplied evidence. Answers must be exact strings or numeric values. Include file names and record IDs in working notes. Time format: YYYY-MM-DDTHH:MM:SSZ.

## Stage I — Expected gateway policy

01. Which **critical gateway hostname** belongs to migration wave PQC-W1? **Format:** lowercase hostname.
02. What **required key-share group label** is specified by that gateway's baseline? **Format:** literal policy token.
03. Calculate the **SHA-256 of the baseline policy file's actual bytes** rather than copying a reported value. **Format:** 64 lowercase hexadecimal characters.

## Stage II — Rejected change and authenticated writer

04. Which **change ticket ID** requests classical-only fallback on that gateway but is rejected? Exclude approved tickets for other hosts. **Format:** CHG-NNN.
05. Which **unsigned CI job ID** applied that rejected configuration? Distinguish it from signed jobs and staged-only work. **Format:** JOB-NNN.
06. What exact **build artifact ID** belongs to that applied unsigned job? **Format:** CFG-NN.
07. Which **session ID** joins the audited gateway configuration-file write to a successful identity-provider authentication? Exclude denied sessions. **Format:** SID-NN.
08. Which **service principal** is linked to that successful session and on-host write? This does not establish a human operator. **Format:** exact principal name.
09. What exact **UTC timestamp** does the gateway audit record for the policy-file write, not staging or service reload? **Format:** YYYY-MM-DDTHH:MM:SSZ.
10. Which **file-integrity event ID** first reports the modified-policy hash after that write? Exclude baseline and later recheck events. **Format:** FIM-NNN.
11. Recompute the **SHA-256 of the changed policy specimen's bytes** and reconcile it against host-audit and FIM claims. **Format:** 64 lowercase hexadecimal characters.
12. At what exact **UTC timestamp** does the gateway audit record the service reload after the write? **Format:** YYYY-MM-DDTHH:MM:SSZ.

## Stage III — Network timeline and evidence limits

13. After source-specific time correction, which **TLS observation ID** first reports the gateway's classical-only group **after its service reload**? Exclude older hybrid and unrelated-host records. **Format:** TLS-NNN.
14. What is that observation's **normalized UTC timestamp**, applying its sensor's positive clock offset? **Format:** YYYY-MM-DDTHH:MM:SSZ.
15. Match that observation's **connection ID, hostname and source IP** to the flow export. What is the **reported egress byte count**? This does not prove exfiltration. **Format:** decimal integer.
16. Does the supplied synthetic evidence establish an independently authenticated, real-world **ML-KEM cryptographic handshake**? **Format:** ESTABLISHED or NOT ESTABLISHED.

## Optional professional finding (ungraded)

Write 200 words distinguishing the recorded unapproved policy state, proof limitations and safe steps for change-controlled restoration. No further flags or enterprise research deliverables are required.

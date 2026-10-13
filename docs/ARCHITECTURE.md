# Synthetic network and cryptographic-policy topology

```text
       Bastion / IdP (nb-idp-01)
                |
        deploy identity (SID-88)
                |
     Build service + change manager
                |
         nb-gw-07 (edge TLS)
          /             \
    nb-api-02         nb-proxy-03
          \/
      edge-sensor
                |
       external test client
       198.51.100.31 (documentation)
```

The network and actors are fictitious. The case intentionally separates:
1. Change-control truth (approved, pending and rejected tickets).
2. Deployment claims (signed versus unsigned builds).
3. Host evidence (a local config write and a reload).
4. Local file-integrity observations (hash before and after).
5. Reported TLS sessions (sensor values, clock offset and five-tuples).

**Trust boundary:** A derived or same-source log cannot independently confirm itself. Confidence must be limited to the source families provided.

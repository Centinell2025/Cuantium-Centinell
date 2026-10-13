# Hands-on investigation with generated binary evidence

## Binary artifacts shipped inside the verified student ZIP
- evidence/synthetic_gateway_traffic.pcap: real **PCAP-format bytes** generated from a fictional packet recipe; Ethernet/IPv4/TCP headers, TCP checksums, two handshakes and scoped application-like bytes. **Not a capture taken from real traffic.**
- evidence/derived_forensic_index.sqlite3: a queryable SQLite database derived from the supplied synthetic CSV rows. **Not an independent witness.**

## Offline PCAP review
A defensive analyst can inspect the PCAP with Wireshark or tcpdump, or use the provided Python packet parser without external dependencies.

Suggested display filter in Wireshark: tcp.stream == 0 (the stream index must be confirmed by the analyst). For exact byte-count grading, filter **client-to-server** IPv4 packets matching both source/destination ports; exclude SYN/ACK and server replies.

## SQLite analysis (read only)
Python example:

    import sqlite3
    conn = sqlite3.connect("file:evidence/derived_forensic_index.sqlite3?mode=ro", uri=True)
    print(conn.execute("PRAGMA quick_check").fetchone())
    print(conn.execute("SELECT source, COUNT(*) FROM source_rows GROUP BY source").fetchall())

SQL filtering and packet byte parsing are intended as investigative tools, not independent provenance checks.

## Claim discipline
The packet sample only contains bytes deliberately created by the case generator. A network flow export may report more bytes than the scoped capture contains. **The difference is a measurement gap, not proof of transmission, theft, or a malicious payload.** The TLS group fields are metadata claims, not results of a real cryptographic handshake.

The data are authorized and entirely synthetic. Never scan actual organization hosts.

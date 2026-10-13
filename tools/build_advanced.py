#!/usr/bin/env python3
"""Generate an explicitly synthetic, reproducible Ethernet/TCP PCAP and derived SQLite index.

Neither artifact is an actual acquisition or an independent source of truth.
"""
from __future__ import annotations

import csv
import ipaddress
import json
import sqlite3
import struct
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
PCAP = EVIDENCE / "synthetic_gateway_traffic.pcap"
SQLITE = EVIDENCE / "derived_forensic_index.sqlite3"

def rows(filename):
    with (EVIDENCE / filename).open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))

def checksum(blob):
    if len(blob) % 2:
        blob += b"\x00"
    words = struct.unpack("!" + ("H" * (len(blob) // 2)), blob)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

def ip_bytes(value):
    return ipaddress.IPv4Address(value).packed

def tcp_packet(src, dst, srcport, dstport, sequence, acknowledge, flags, payload, ident):
    src_ip, dst_ip = ip_bytes(src), ip_bytes(dst)
    total_len = 20 + 20 + len(payload)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000,
                       64, 6, 0, src_ip, dst_ip)
    ipv4 = ipv4[:10] + struct.pack("!H", checksum(ipv4)) + ipv4[12:]
    tcp = struct.pack("!HHLLBBHHH", int(srcport), int(dstport), sequence,
                      acknowledge, 0x50, flags, 4096, 0, 0)
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp + payload)) + tcp[18:]
    ethernet = bytes.fromhex("0200000000010200000000020800")
    return ethernet + ipv4 + tcp + payload

def build_pcap():
    flow_by_id = {r["connection_id"]: r for r in rows("edge_flows.csv")}
    pcap = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for idx, recipe in enumerate(rows("packet_recipe.csv")):
        conn = recipe["connection_id"]
        if conn not in flow_by_id:
            raise ValueError("Packet recipe has no corresponding edge flow")
        flow = flow_by_id[conn]
        if (flow["source_ip"], flow["destination_ip"], flow["destination_port"]) != (
            recipe["source_ip"], recipe["destination_ip"], recipe["destination_port"]
        ):
            raise ValueError("Recipe disagrees with flow IP or destination")
        start = datetime.fromisoformat(flow["observed_utc"].replace("Z", "+00:00"))
        sec = int(start.timestamp())
        src, sport = recipe["source_ip"], int(recipe["source_port"])
        dst, dport = recipe["destination_ip"], int(recipe["destination_port"])
        client_seq, server_seq = 11000 + idx * 1000, 35000 + idx * 1000
        app = recipe["payload_ascii"].encode("ascii")
        if not app.startswith(b"QC001_") or b"SECRET" not in app and b"DECOY" not in app:
            raise ValueError("Packet payload must be a benign training marker")
        frames = (
            (0, src, dst, sport, dport, client_seq, 0, 0x02, b""),
            (3000, dst, src, dport, sport, server_seq, client_seq + 1, 0x12, b""),
            (5000, src, dst, sport, dport, client_seq + 1, server_seq + 1, 0x10, b""),
            (7000, src, dst, sport, dport, client_seq + 1, server_seq + 1, 0x18, app),
            (10000, dst, src, dport, sport, server_seq + 1, client_seq + 1 + len(app), 0x18, b"OK"),
        )
        for counter, (usec, src2, dst2, sp2, dp2, sequence, acknowledge, flags, payload) in enumerate(frames):
            packet = tcp_packet(src2, dst2, sp2, dp2, sequence, acknowledge,
                                flags, payload, 3000 + idx * 10 + counter)
            pcap.extend(struct.pack("<IIII", sec, usec, len(packet), len(packet)))
            pcap.extend(packet)
    PCAP.write_bytes(pcap)

def inspect_pcap():
    blob = PCAP.read_bytes()
    if len(blob) < 24 or blob[:24] != struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1):
        raise ValueError("Invalid PCAP global header")
    offset, packet_count = 24, 0
    payload_totals = {}
    while offset < len(blob):
        if offset + 16 > len(blob):
            raise ValueError("Truncated record header")
        _seconds, _micro, saved, actual = struct.unpack_from("<IIII", blob, offset)
        offset += 16
        if saved != actual or saved < 54 or offset + saved > len(blob):
            raise ValueError("Damaged/truncated PCAP frame")
        eth = blob[offset:offset + saved]
        offset += saved
        if eth[12:14] != b"\x08\x00":
            raise ValueError("Unexpected Ethernet type")
        ip = eth[14:]
        ihl = (ip[0] & 15) * 4
        if ihl != 20 or ip[9] != 6 or checksum(ip[:ihl]) != 0:
            raise ValueError("Invalid IPv4 header/checksum")
        ip_total = struct.unpack_from("!H", ip, 2)[0]
        if ip_total != len(ip):
            raise ValueError("IPv4 length mismatch")
        tcp = ip[ihl:]
        tcp_hlen = (tcp[12] >> 4) * 4
        if tcp_hlen != 20:
            raise ValueError("Unexpected TCP header size")
        pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp))
        if checksum(pseudo + tcp) != 0:
            raise ValueError("Invalid TCP pseudo-header checksum")
        source = str(ipaddress.IPv4Address(ip[12:16]))
        destination = str(ipaddress.IPv4Address(ip[16:20]))
        source_port, destination_port = struct.unpack_from("!HH", tcp)
        payload = tcp[tcp_hlen:]
        key = (source, source_port, destination, destination_port)
        payload_totals[key] = payload_totals.get(key, 0) + len(payload)
        packet_count += 1
    if offset != len(blob) or packet_count != len(rows("packet_recipe.csv")) * 5:
        raise ValueError("Unexpected PCAP packet count")
    return packet_count, payload_totals

def build_sqlite():
    if SQLITE.exists():
        SQLITE.unlink()
    conn = sqlite3.connect(SQLITE)
    try:
        conn.execute("PRAGMA page_size=4096")
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("""CREATE TABLE source_rows(
            source_file TEXT NOT NULL,
            row_number INTEGER NOT NULL,
            source_record_id TEXT NOT NULL,
            hostname TEXT,
            observed_utc TEXT,
            source_json TEXT NOT NULL,
            PRIMARY KEY(source_file,row_number)
        )""")
        conn.execute("CREATE INDEX idx_source_record ON source_rows(source_record_id)")
        conn.execute("CREATE INDEX idx_host_time ON source_rows(hostname,observed_utc)")
        conn.execute("CREATE TABLE provenance(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT INTO provenance VALUES (?,?)",
                     ("disclosure", "DERIVED FROM SYNTHETIC CSV FILES; NOT AN INDEPENDENT WITNESS"))
        files = sorted(EVIDENCE.glob("*.csv"))
        for file in files:
            with file.open(newline="", encoding="utf-8") as handle:
                for i, entry in enumerate(csv.DictReader(handle), 1):
                    source_id = next((v for k, v in entry.items()
                                      if k in ("audit_id", "job_id", "ticket", "tls_id",
                                               "fim_id", "decision_id", "process_event_id",
                                               "governance_event_id", "risk_event_id",
                                               "gap_id", "rollback_id", "flow_id",
                                               "idp_event_id", "asset_id", "baseline_id",
                                               "connection_id", "sensor")), f"row-{i}")
                    conn.execute("INSERT INTO source_rows VALUES (?,?,?,?,?,?)",
                                 (file.name, i, source_id,
                                  entry.get("hostname"),
                                  entry.get("observed_utc") or entry.get("recorded_utc"),
                                  json.dumps(entry, sort_keys=True, separators=(",", ":"))))
        conn.commit()
        if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("SQLite index check failed")
    finally:
        conn.close()

def build():
    EVIDENCE.mkdir(exist_ok=True)
    build_pcap()
    inspect_pcap()
    build_sqlite()
    return {"pcap": str(PCAP), "sqlite": str(SQLITE)}

if __name__ == "__main__":
    print("PASS: deterministic synthetic binary evidence built:", build())

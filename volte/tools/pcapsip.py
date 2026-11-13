#!/usr/bin/env python3
"""Extract SIP messages from a pcap of IMS signalling (plain TCP/UDP or ESP
with null encryption and a 96-bit ICV). No dependencies.

Usage: pcapsip.py FILE.pcap [--sanitize]
--sanitize masks digit runs of 9+ (IMSI, IMEI, MSISDN) and nonces.
"""
import re
import struct
import sys

ICV = 12


def packets(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        magic = struct.unpack("<I", hdr[:4])[0]
        endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            ts, tus, incl, _ = struct.unpack(endian + "IIII", ph)
            data = f.read(incl)
            yield ts + tus / 1e6, linktype, data


def ip_payload(linktype, data):
    if linktype == 1:  # Ethernet
        data = data[14:]
    elif linktype == 113:  # Linux SLL
        data = data[16:]
    elif linktype == 276:  # SLL2
        data = data[20:]
    # 101 / 228: raw IP
    if not data:
        return None
    v = data[0] >> 4
    if v == 4:
        ihl = (data[0] & 15) * 4
        return data[9], data[12:16], data[16:20], data[ihl:]
    if v == 6:
        return data[6], data[8:24], data[24:40], data[40:]
    return None


def l4(proto, payload):
    """Return (proto, sport, dport, data) after removing ESP if present."""
    if proto == 50:
        body = payload[8:]
        if len(body) < ICV + 2:
            return None
        padlen, nxt = body[-ICV - 2], body[-ICV - 1]
        inner = body[: len(body) - ICV - 2 - padlen]
        return l4(nxt, inner)
    if proto == 6:
        off = (payload[12] >> 4) * 4
        sport, dport = struct.unpack(">HH", payload[:4])
        return "tcp", sport, dport, payload[off:]
    if proto == 17:
        sport, dport = struct.unpack(">HH", payload[:4])
        return "udp", sport, dport, payload[8:]
    return None


def fmt_addr(a):
    return ".".join(map(str, a)) if len(a) == 4 else a.hex()


def sanitize(s):
    s = re.sub(r'nonce="[^"]*"', 'nonce="<nonce>"', s)
    s = re.sub(r'response="[^"]*"', 'response="<response>"', s)
    s = re.sub(r"\d{9,}", lambda m: "9" * len(m.group(0)), s)
    return s


def main():
    path = sys.argv[1]
    clean = "--sanitize" in sys.argv
    streams = {}
    for ts, lt, data in packets(path):
        ip = ip_payload(lt, data)
        if not ip:
            continue
        r = l4(ip[0], ip[3])
        if not r or not r[3]:
            continue
        key = (fmt_addr(ip[1]), r[1], fmt_addr(ip[2]), r[2])
        streams.setdefault(key, []).append((ts, r[3]))
    msgs = []
    for key, chunks in streams.items():
        buf = b"".join(c for _, c in chunks)
        t0 = chunks[0][0]
        for m in re.split(rb"(?=^(?:SIP/2\.0 \d{3}|[A-Z]+ \S+ SIP/2\.0)\r\n)", buf, flags=re.M):
            if m.strip():
                msgs.append((t0, key, m))
    # keep stream order; streams are interleaved by first timestamp only
    for t0, key, m in msgs:
        text = m.decode("utf-8", "replace")
        if clean:
            text = sanitize(text)
        print(f"=== {key[0]}:{key[1]} -> {key[2]}:{key[3]}")
        print(text.rstrip("\r\n").replace("\r\n", "\n"))
        print()


if __name__ == "__main__":
    main()

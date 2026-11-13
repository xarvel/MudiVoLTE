#!/usr/bin/env python3
"""Sec-agree view of a pcap of IMS signalling: for every SIP message the time,
ports, the ESP SPI it travelled in, the first line and the CSeq, Expires,
Warning and Security-Client/Server/Verify headers, SPIs in hex. Nothing else
is printed, so no identities leave the capture: SPIs and ports are random.
ESP with null encryption and a 96-bit ICV is unwrapped. No dependencies.

Usage: secagree.py FILE.pcap [HH:MM:SS from] [to]

Shows whether a REGISTER offers SPIs and ports of SAs in use (compare its
Security-Client with the SPIs of the ESP packets around it) and what the
network answered (TS 33.203 §7.1, §7.4; FINDINGS §93, §94).
"""
import re
import struct
import sys
import time

ICV = 12


def packets(path):
    with open(path, "rb") as f:
        hdr = f.read(24)
        magic = struct.unpack("<I", hdr[:4])[0]
        e = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        lt = struct.unpack(e + "I", hdr[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            ts, tus, incl, _ = struct.unpack(e + "IIII", ph)
            yield ts + tus / 1e6, lt, f.read(incl)


def ipv4(lt, d):
    if lt == 1:  # Ethernet
        d = d[14:]
    elif lt == 113:  # Linux SLL
        d = d[16:]
    elif lt == 276:  # SLL2 (tcpdump -i any)
        d = d[20:]
    if not d or d[0] >> 4 != 4:
        return None
    ihl = (d[0] & 15) * 4
    tot = struct.unpack(">H", d[2:4])[0]
    return d[9], ".".join(map(str, d[12:16])), ".".join(map(str, d[16:20])), d[ihl:tot]


def unwrap(proto, p):
    spi = None
    if proto == 50 and len(p) >= 8 + ICV + 2:
        spi = struct.unpack(">I", p[:4])[0]
        body = p[8:]
        padlen, nxt = body[-ICV - 2], body[-ICV - 1]
        p = body[: len(body) - ICV - 2 - padlen]
        proto = nxt
    return proto, p, spi


KEEP = re.compile(r"^(CSeq|Expires|Warning|Security-Client|Security-Server|Security-Verify):", re.I)
SPI = re.compile(r"(spi-[cs])=(\d+)")


def hexspi(line):
    return SPI.sub(lambda m: f"{m.group(1)}={int(m.group(2)):#010x}", line)


def main():
    lo = sys.argv[2] if len(sys.argv) > 2 else "00:00:00"
    hi = sys.argv[3] if len(sys.argv) > 3 else "23:59:59"
    streams = {}  # (src, sport, dst, dport) -> (time, spi, bytes) of the message being read
    for ts, lt, d in packets(sys.argv[1]):
        r = ipv4(lt, d)
        if not r:
            continue
        proto, src, dst, p = r
        proto, p, spi = unwrap(proto, p)
        if proto == 6 and len(p) >= 20:
            data = p[(p[12] >> 4) * 4:]
        elif proto == 17 and len(p) >= 8:
            data = p[8:]
        else:
            continue
        sport, dport = struct.unpack(">HH", p[:4])
        if not data:
            continue
        key = (src, sport, dst, dport)
        t0, s0, buf = streams.get(key, (ts, spi, b""))
        if not buf:
            t0, s0 = ts, spi
        buf += data
        while True:
            head, sep, rest = buf.partition(b"\r\n\r\n")
            if not sep:
                break
            text = head.decode("latin1")
            m = re.search(r"(?im)^(?:content-length|l)\s*:\s*(\d+)", text)
            n = int(m.group(1)) if m else 0
            if len(rest) < n:
                break
            lines = text.split("\r\n")
            first = lines[0]
            if first.startswith("SIP/2.0 ") or re.match(r"^[A-Z]+ \S+ SIP/2\.0$", first):
                hms = time.strftime("%H:%M:%S", time.localtime(t0))
                if lo <= hms <= hi:
                    esp = f"esp {s0:#010x}" if s0 is not None else "plain"
                    what = first if first.startswith("SIP/2.0") else first.split(" ")[0]
                    print(f"{hms}.{int(t0 % 1 * 1000):03d} {src}:{sport} > {dst}:{dport} [{esp}] {what}")
                    for line in lines[1:]:
                        if KEEP.match(line):
                            print("    " + hexspi(line))
                buf = rest[n:]
            else:
                buf = b""  # not at a message boundary: wait for the next one
            t0, s0 = ts, spi
            if not buf:
                break
        streams[key] = (t0, s0, buf)


if __name__ == "__main__":
    main()

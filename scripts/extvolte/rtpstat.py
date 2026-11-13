#!/usr/bin/env python3
"""RTP streams in a pcap, per UDP flow: packets, first and last, gaps, payload sizes.

python3 -I rtpstat.py file.pcap [HH:MM:SS-from HH:MM:SS-to]  (UTC)
"""
import struct
import sys
import time
from collections import defaultdict


def hms(ts):
    return time.strftime("%H:%M:%S", time.gmtime(ts)) + ("%.3f" % (ts % 1))[1:]


def l3_offset(linktype, pkt):
    if linktype == 101 or linktype == 12:  # raw IP
        return 0
    if linktype == 1:  # Ethernet
        return 14
    if linktype == 113:  # Linux SLL
        return 16
    if linktype == 276:  # Linux SLL2
        return 20
    raise SystemExit(f"linktype {linktype} is not supported")


def secs(s, day):
    h, m, x = s.split(":")
    return day + int(h) * 3600 + int(m) * 60 + float(x)


def main():
    path = sys.argv[1]
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off = 24
    flows = defaultdict(list)
    lo = hi = None
    while off + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        pkt = data[off + 16:off + 16 + incl]
        off += 16 + incl
        ts = sec + frac / (1e9 if nano else 1e6)
        if lo is None and len(sys.argv) > 3:
            day = ts - ts % 86400
            lo, hi = secs(sys.argv[2], day), secs(sys.argv[3], day)
        if lo is not None and not (lo <= ts <= hi):
            continue
        p = pkt[l3_offset(linktype, pkt):]
        if len(p) < 20 or p[0] >> 4 != 4 or p[9] != 17:
            continue
        ihl = (p[0] & 15) * 4
        src = ".".join(map(str, p[12:16]))
        dst = ".".join(map(str, p[16:20]))
        sport, dport, ulen = struct.unpack(">HHH", p[ihl:ihl + 6])
        pl = p[ihl + 8:]
        if len(pl) < 12 or pl[0] >> 6 != 2:
            continue
        pt = pl[1] & 0x7F
        seq = struct.unpack(">H", pl[2:4])[0]
        cc = pl[0] & 15
        hdr = 12 + 4 * cc
        if pl[0] & 0x10 and len(pl) >= hdr + 4:  # extension
            hdr += 4 + 4 * struct.unpack(">H", pl[hdr + 2:hdr + 4])[0]
        flows[(src, sport, dst, dport)].append((ts, pt, seq, len(pl) - hdr))
    for (src, sport, dst, dport), pk in sorted(flows.items(), key=lambda kv: kv[1][0][0]):
        ts = [x[0] for x in pk]
        gaps = sorted(((b - a, a) for a, b in zip(ts, ts[1:])), reverse=True)[:3]
        sizes = defaultdict(int)
        for x in pk:
            sizes[x[3]] += 1
        pts = sorted({x[1] for x in pk})
        seqs = [x[2] for x in pk]
        lost = sum(((b - a) & 0xFFFF) - 1 for a, b in zip(seqs, seqs[1:]) if 0 < ((b - a) & 0xFFFF) < 1000)
        print(f"{src}:{sport} > {dst}:{dport}  pt={pts}  n={len(pk)}  {hms(ts[0])} … {hms(ts[-1])} ({ts[-1] - ts[0]:.1f} s)  lost by seq={lost}")
        print("   gaps: " + ", ".join(f"{g:.2f} s after {hms(a)}" for g, a in gaps))
        print("   payload: " + ", ".join(f"{s} B×{n}" for s, n in sorted(sizes.items(), key=lambda kv: -kv[1])[:6]))


main()

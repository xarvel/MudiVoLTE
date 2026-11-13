#!/usr/bin/env python3
"""Minimal pcap reader for IMS captures: ESP-null (transport mode) unwrap + SIP summary.

usage: esp_sip.py <file.pcap> [HH:MM:SS-from] [HH:MM:SS-to] [--full]
Times are UTC. ICV is assumed 12 bytes (hmac-md5-96 / hmac-sha-1-96).
"""
import struct
import sys
import datetime as dt

ICV = 12


def read_pcap(path):
    with open(path, 'rb') as f:
        data = f.read()
    magic = data[:4]
    if magic == b'\xd4\xc3\xb2\xa1':
        e, ns = '<', False
    elif magic == b'\xa1\xb2\xc3\xd4':
        e, ns = '>', False
    elif magic == b'\x4d\x3c\xb2\xa1':
        e, ns = '<', True
    elif magic == b'\xa1\xb2\x3c\x4d':
        e, ns = '>', True
    else:
        raise SystemExit('unknown pcap magic %r' % magic)
    linktype = struct.unpack(e + 'I', data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(e + 'IIII', data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        if len(pkt) < incl:
            break
        ts = sec + (frac / 1e9 if ns else frac / 1e6)
        yield ts, linktype, pkt


def ip_from_link(linktype, pkt):
    if linktype in (101, 12, 14, 228):
        return pkt
    if linktype == 1:  # ethernet
        et = struct.unpack('>H', pkt[12:14])[0]
        off = 14
        if et == 0x8100:
            et = struct.unpack('>H', pkt[16:18])[0]
            off = 18
        if et in (0x0800, 0x86dd):
            return pkt[off:]
        return None
    if linktype == 113:  # linux cooked
        et = struct.unpack('>H', pkt[14:16])[0]
        return pkt[16:] if et in (0x0800, 0x86dd) else None
    if linktype == 276:  # linux cooked v2
        et = struct.unpack('>H', pkt[0:2])[0]
        return pkt[20:] if et in (0x0800, 0x86dd) else None
    return None


def ipstr(b):
    return '.'.join(str(x) for x in b)


def tcp_flags(f):
    names = [(0x02, 'S'), (0x10, '.'), (0x01, 'F'), (0x04, 'R'), (0x08, 'P')]
    return ''.join(n for bit, n in names if f & bit)


def l4(proto, seg):
    if proto == 6 and len(seg) >= 20:
        sp, dp, seq, ack, offf, flags = struct.unpack('>HHIIBB', seg[:14])
        hl = (offf >> 4) * 4
        return 'TCP', sp, dp, '%s seq=%d ack=%d' % (tcp_flags(flags), seq, ack), seg[hl:]
    if proto == 17 and len(seg) >= 8:
        sp, dp = struct.unpack('>HH', seg[:4])
        return 'UDP', sp, dp, '', seg[8:]
    if proto == 1:
        t, c = seg[0], seg[1]
        return 'ICMP', 0, 0, 'type=%d code=%d' % (t, c), seg[8:]
    return 'P%d' % proto, 0, 0, '', seg


SIP_HDRS = ('from', 'f', 'to', 't', 'call-id', 'i', 'cseq', 'reason', 'p-asserted-identity',
            'contact', 'm', 'via', 'v', 'warning', 'retry-after', 'subscription-state', 'event')


def sip_summary(payload, full=False):
    try:
        txt = payload.decode('utf-8', 'replace')
    except Exception:
        return None
    first = txt.split('\r\n', 1)[0]
    if not (first.startswith('SIP/2.0') or ' sip:' in first or ' tel:' in first or ' urn:' in first):
        return None
    if full:
        return txt
    lines = [first]
    for ln in txt.split('\r\n')[1:]:
        if not ln:
            break
        k = ln.split(':', 1)[0].strip().lower()
        if k in SIP_HDRS:
            lines.append('    ' + ln[:200])
    return '\n'.join(lines)


def parse_hms(s, day):
    h, m, sec = (int(x) for x in s.split(':'))
    return day.replace(hour=h, minute=m, second=sec).timestamp()


def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    full = '--full' in sys.argv
    path = args[0]
    t_from = t_to = None
    for ts, lt, pkt in read_pcap(path):
        day = dt.datetime.fromtimestamp(ts, dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        if len(args) > 1:
            t_from = parse_hms(args[1], day)
        if len(args) > 2:
            t_to = parse_hms(args[2], day)
        break
    for ts, lt, pkt in read_pcap(path):
        if t_from and ts < t_from:
            continue
        if t_to and ts > t_to:
            continue
        ip = ip_from_link(lt, pkt)
        if not ip:
            continue
        stamp = dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime('%H:%M:%S.%f')[:-3]
        if ip[0] >> 4 != 4:
            print(stamp, 'IPv6 len=%d' % len(ip))
            continue
        ihl = (ip[0] & 0x0f) * 4
        proto = ip[9]
        src, dst = ipstr(ip[12:16]), ipstr(ip[16:20])
        body = ip[ihl:struct.unpack('>H', ip[2:4])[0]]
        tag = ''
        if proto == 50 and len(body) > 8 + ICV + 2:
            spi, seq = struct.unpack('>II', body[:8])
            inner = body[8:-ICV]
            nh, padlen = inner[-1], inner[-2]
            seg = inner[:-(2 + padlen)]
            tag = 'ESP spi=0x%08x seq=%d ' % (spi, seq)
            proto = nh
            body = seg
        name, sp, dp, extra, payload = l4(proto, body)
        print('%s %s%s %s:%d > %s:%d %s len=%d' % (stamp, tag, name, src, sp, dst, dp, extra, len(payload)))
        if payload:
            s = sip_summary(payload, full)
            if s:
                print('  ' + s.replace('\n', '\n  '))
            elif name == 'ICMP':
                # quoted original header
                q = payload
                if len(q) >= 20:
                    print('  ICMP quotes proto=%d %s > %s' % (q[9], ipstr(q[12:16]), ipstr(q[16:20])))


if __name__ == '__main__':
    main()

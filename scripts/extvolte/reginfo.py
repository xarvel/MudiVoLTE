import os, sys, re, struct, datetime as dt
exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'esp_sip.py')).read().split("if __name__")[0])
F=sys.argv[1]
streams={}
for ts, lt, pkt in read_pcap(F):
    ip=ip_from_link(lt,pkt)
    if not ip or ip[9]!=50: continue
    ihl=(ip[0]&15)*4
    body=ip[ihl:struct.unpack('>H',ip[2:4])[0]]
    inner=body[8:-ICV]; nh=inner[-1]; pad=inner[-2]; seg=inner[:-(2+pad)]
    if nh!=6: continue
    sp,dp=struct.unpack('>HH',seg[:4]); hl=(seg[12]>>4)*4; pl=seg[hl:]
    if pl:
        k=(sp,dp); streams.setdefault(k,[]).append((ts,pl))
for k,v in streams.items():
    txt=b''.join(p for _,p in v).decode('utf-8','replace')
    for m in re.finditer(r'NOTIFY sip:', txt):
        chunk=txt[m.start():m.start()+6000]
        t0=dt.datetime.fromtimestamp(v[0][0], dt.timezone.utc).strftime('%H:%M:%S')
        i=chunk.find('<reginfo')
        j=chunk.find('</reginfo>')
        if i<0: continue
        body=chunk[i:j+10]
        body=re.sub(r'(sip:|tel:)\+?[0-9]{6,}', r'\1<num>', body)
        print('== stream', k, 'first pkt', t0)
        for line in body.splitlines():
            line=line.strip()
            if line.startswith(('<registration','<contact','<uri')): print('  ', line[:200])

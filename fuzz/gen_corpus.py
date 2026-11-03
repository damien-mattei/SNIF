#!/usr/bin/env python3
"""Small seed corpus for the fuzzer: one pcap per family of protocols."""
import struct, sys, os
out = sys.argv[1] if len(sys.argv) > 1 else "corpus"
os.makedirs(out, exist_ok=True)
M1, M2 = b'\x02\0\0\0\0\1', b'\x02\0\0\0\0\2'
IP1, IP2 = b'\x0a\0\0\1', b'\x0a\0\0\2'
I6a, I6b = b'\xfe\x80' + b'\0'*13 + b'\1', b'\xfe\x80' + b'\0'*13 + b'\2'

def cks(d):
    if len(d) % 2: d += b'\0'
    s = sum(struct.unpack('>%dH' % (len(d)//2), d))
    while s >> 16: s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff
def eth(p, t=0x0800, s=M1, d=M2): return d + s + struct.pack('>H', t) + p
def ip4(proto, data, s=IP1, d=IP2, opts=b''):
    h = struct.pack('>BBHHHBBH4s4s', 0x40 | (5 + len(opts)//4), 0, 20+len(opts)+len(data), 1, 0, 64, proto, 0, s, d) + opts
    h = h[:10] + struct.pack('>H', cks(h)) + h[12:]
    return h + data
def ip6(nh, data, s=I6a, d=I6b):
    return struct.pack('>IHBB', 0x60000000, len(data), nh, 64) + s + d + data
def tcp(flags, data=b'', sp=40000, dp=80, opts=b''):
    return struct.pack('>HHIIBBHHH', sp, dp, 1000, 2000, (5 + len(opts)//4) << 4, flags, 8192, 0, 0) + opts + data
def udp(sp, dp, data): return struct.pack('>HHHH', sp, dp, 8+len(data), 0) + data
def dns(): return struct.pack('>HHHHHH', 1, 0x0100, 1, 0, 0, 0) + b'\3www\7example\3com\0\0\1\0\1'
def dnsans(): return struct.pack('>HHHHHH', 1, 0x8180, 1, 1, 0, 0) + b'\3www\7example\3com\0\0\1\0\1' + b'\xc0\x0c\0\1\0\1\0\0\1\x2c\0\4' + IP2
def pcap(name, pkts, dlt=1):
    with open(os.path.join(out, name + '.pcap'), 'wb') as f:
        f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, dlt))
        for i, p in enumerate(pkts): f.write(struct.pack('<IIII', 1700000000+i, 0, len(p), len(p)) + p)

opts = b'\x02\x04\x05\xb4\x04\x02\x08\x0a' + b'\0'*8 + b'\x01\x03\x03\x07'
pcap('tcp', [eth(ip4(6, tcp(0x02, opts=opts))), eth(ip4(6, tcp(0x18, b'GET / HTTP/1.1\r\nHost: x\r\n\r\n'))),
             eth(ip4(6, tcp(0x10, sp=80, dp=40000))), eth(ip4(6, tcp(0x04)))])
pcap('dns', [eth(ip4(17, udp(5353, 53, dns()))), eth(ip4(17, udp(53, 5353, dnsans()))),
             eth(ip4(17, udp(5353, 5353, dns()))), eth(ip4(17, udp(5355, 5355, dns())))])
pcap('arp_icmp', [eth(struct.pack('>HHBBH', 1, 0x0800, 6, 4, 1) + M1 + IP1 + b'\0'*6 + IP2, 0x0806),
                  eth(ip4(1, struct.pack('>BBHHH', 8, 0, 0, 1, 1) + b'ping')),
                  eth(ip4(1, struct.pack('>BBHI', 3, 4, 0, 1400) + ip4(17, udp(1, 2, b'x')))),
                  eth(ip4(1, struct.pack('>BBHI', 5, 1, 0, 0) + ip4(6, tcp(2))))])
pcap('ipv6', [eth(ip6(58, struct.pack('>BBHI', 128, 0, 0, 0) + b'abcd'), 0x86dd),
              eth(ip6(0, bytes([6, 0, 1, 4, 0, 0, 0, 0]) + tcp(2)), 0x86dd),
              eth(ip6(44, bytes([17, 0, 0, 1, 0, 0, 0, 7]) + udp(1, 2, b'data')), 0x86dd),
              eth(ip6(58, struct.pack('>BBH', 135, 0, 0) + b'\0'*4 + I6b + b'\x01\x01' + M1), 0x86dd),
              eth(ip6(17, udp(546, 547, b'\1\0\0\0')), 0x86dd)])
pcap('dhcp_ntp', [eth(ip4(17, udp(68, 67, b'\1\1\6\0' + b'\0'*232 + b'\x63\x82\x53\x63\x35\x01\x01\xff'))),
                  eth(ip4(17, udp(123, 123, b'\x1b' + b'\0'*47))),
                  eth(ip4(17, udp(1900, 1900, b'M-SEARCH * HTTP/1.1\r\nHOST: x\r\n\r\n'))),
                  eth(ip4(17, udp(5060, 5060, b'INVITE sip:x SIP/2.0\r\n\r\n'))),
                  eth(ip4(17, udp(443, 443, b'\xc0\0\0\0\1\x08' + b'\1'*8 + b'\0')))])
pcap('tunnels', [eth(ip4(47, struct.pack('>HH', 0, 0x0800) + ip4(1, struct.pack('>BBHHH', 8, 0, 0, 1, 1)))),
                 eth(ip4(4, ip4(6, tcp(2)))), eth(ip4(41, ip6(58, b'\x80\0\0\0\0\0\0\0'))),
                 eth(ip4(17, udp(4789, 4789, b'\x08\0\0\0\0\0\1\0' + eth(ip4(1, b'\x08\0\0\0\0\1\0\1'))))),
                 eth(ip4(17, udp(6081, 6081, struct.pack('>BBH', 0, 0, 0x6558) + b'\0\0\0\0' + eth(ip4(1, b'\x08\0\0\0\0\1\0\1'))))),
                 eth(ip4(50, struct.pack('>II', 1, 1) + b'\0'*16))])
pcap('routing', [eth(ip4(89, struct.pack('>BBHIIHHQ', 2, 1, 44, 1, 0, 0, 0, 0) + struct.pack('>IHBBIII', 0xffffff00, 10, 2, 1, 0, 0, 0))),
                 eth(ip4(2, struct.pack('>BBHI', 0x11, 0, 0, 0))),
                 eth(ip4(112, struct.pack('>BBBBBBHI', 0x21, 1, 100, 0, 1, 0, 0, 0) + IP2)),
                 eth(ip4(6, tcp(0x18, b'\xff'*16 + struct.pack('>HB', 19, 4), dp=179))),
                 eth(ip4(17, udp(520, 520, b'\2\2\0\0' + b'\0\2\0\0' + IP1 + b'\0'*12))),
                 eth(ip4(103, struct.pack('>BBH', 0x20, 0, 0) + b'\0'*8))])
pcap('l2', [eth(b'\x42\x42\x03\0\0\0\0' + b'\0'*35, 38, d=b'\x01\x80\xc2\0\0\0'),
            eth(struct.pack('>HH', 0x6001, 0x0800) + ip4(1, b'\x08\0\0\0\0\1\0\1'), 0x8100),
            eth(b'\x11\x00\x00\x01\x00\x06' + b'\0'*6 + ip4(1, b'\x08\0\0\0\0\1\0\1'), 0x8864),
            eth(b'\xaa\xaa\x03\0\0\0\x08\x00' + ip4(1, b'\x08\0\0\0\0\1\0\1'), 40),
            eth(b'\x02\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06' * 3, 0x88cc),
            eth(b'\x01\x02\x03\x04' * 8, 0x888e), eth(b'\0'*30, 0x8847), eth(b'\x01\x00' + b'\0'*40, 0x88f7)])
pcap('sll', [b'\0\0\x03\x04\0\x06' + M1 + b'\0\0' + b'\x08\x00' + ip4(1, b'\x08\0\0\0\0\1\0\1'),
             b'\0\0\0\x01\0\x06' + M1 + b'\0\0' + b'\x86\xdd' + ip6(58, b'\x80\0\0\0\0\0\0\0')], dlt=113)
pcap('null', [struct.pack('<I', 2) + ip4(6, tcp(2)), struct.pack('<I', 30) + ip6(17, udp(1, 2, b'x'))], dlt=0)
pcap('raw', [ip4(1, b'\x08\0\0\0\0\1\0\1'), ip6(6, tcp(2))], dlt=12)
rt = b'\0\0\x0c\0\x04\x80\0\0\x02\0\x18\0'
pcap('wifi', [rt + b'\x80\0\0\0' + b'\xff'*6 + M1 + M1 + b'\0\0' + b'\0'*8 + b'\x64\0\x11\0\0\4home\1\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\3\1\6',
              rt + b'\x40\0\0\0' + b'\xff'*6 + M1 + b'\xff'*6 + b'\0\0\0\4home\1\x04\x02\x04\x0b\x16',
              rt + b'\x88\1\0\0' + M2 + M1 + M2 + b'\0\0\0\0' + b'\xaa\xaa\3\0\0\0\x08\0' + ip4(1, b'\x08\0\0\0\0\1\0\1')], dlt=127)

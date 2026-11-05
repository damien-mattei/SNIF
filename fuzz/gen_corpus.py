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
# lo0 of macOS leaves the IP checksum at 0; any other wrong value stays a bad checksum
lo = ip4(6, tcp(2))
pcap('lo0_cksum', [struct.pack('<I', 2) + lo[:10] + b'\0\0' + lo[12:],
                   struct.pack('<I', 2) + lo[:10] + b'\xbe\xef' + lo[12:]], dlt=0)
pcap('raw', [ip4(1, b'\x08\0\0\0\0\1\0\1'), ip6(6, tcp(2))], dlt=12)
rt = b'\0\0\x0c\0\x04\x80\0\0\x02\0\x18\0'
pcap('wifi', [rt + b'\x80\0\0\0' + b'\xff'*6 + M1 + M1 + b'\0\0' + b'\0'*8 + b'\x64\0\x11\0\0\4home\1\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\3\1\6',
              rt + b'\x40\0\0\0' + b'\xff'*6 + M1 + b'\xff'*6 + b'\0\0\0\4home\1\x04\x02\x04\x0b\x16',
              rt + b'\x88\1\0\0' + M2 + M1 + M2 + b'\0\0\0\0' + b'\xaa\xaa\3\0\0\0\x08\0' + ip4(1, b'\x08\0\0\0\0\1\0\1')], dlt=127)

# ---- the decoders the first campaign did not reach ----
def U(sp, dp, d): return eth(ip4(17, udp(sp, dp, d)))
def T(dp, d): return eth(ip4(6, tcp(0x18, d, dp=dp)))
def llc(d, dst=M2): return eth(d, len(d), d=dst)   # 802.3: length instead of a type
def snap(oui, pid, d, dst=M2): return llc(b'\xaa\xaa\x03' + oui + struct.pack('>H', pid) + d, dst)

isis = lambda t, hl, b: b'\xfe\xfe\x03\x83' + bytes([hl, 1, 0, t, 1, 0, 3]) + b
hello_tlv = b'\x01\x02\x49\x00' + b'\x81\x01\xcc' + b'\x84\x04' + IP1 + b'\x89\x03abc'
pcap('isis', [llc(isis(15, 27, b'\x01' + b'\1'*6 + b'\0\x1e' + struct.pack('>H', 40) + b'\x40' + b'\1'*7 + hello_tlv), b'\x01\x80\xc2\0\0\x14'),
              llc(isis(18, 27, struct.pack('>H', 60) + b'\x04\xb0' + b'\1'*8 + struct.pack('>I', 1) + b'\0\0\x03' +
                       b'\x89\x03abc' + b'\x87\x09' + b'\0\0\0\x0a\x18\x0a\0\0'), b'\x01\x80\xc2\0\0\x14')])
nf5 = struct.pack('>HHIIIIBBH', 5, 1, 1000, 1700000000, 0, 1, 0, 0, 0) + IP1 + IP2 + b'\0'*4 + struct.pack('>HHIIIIHHBBBBHHBBH', 1, 2, 10, 1000, 0, 1, 80, 443, 0, 0x18, 6, 0, 0, 0, 24, 24, 0)
tmpl = struct.pack('>HHHH', 0, 16, 300, 2) + struct.pack('>HHHH', 8, 4, 12, 4)
nf9 = struct.pack('>HHIIII', 9, 2, 1000, 1700000000, 1, 1) + tmpl + struct.pack('>HH', 300, 12) + IP1 + IP2
ipfix_b = struct.pack('>HH', 2, 16) + struct.pack('>HH', 300, 2) + struct.pack('>HHHH', 8, 4, 12, 4) + struct.pack('>HH', 300, 12) + IP1 + IP2
ipfix = struct.pack('>HHIII', 10, 16 + len(ipfix_b), 1700000000, 1, 1) + ipfix_b
sf = struct.pack('>II', 5, 1) + IP1 + struct.pack('>IIII', 0, 1, 1000, 1) + struct.pack('>II', 1, 44) + struct.pack('>IIIIIIII', 1, 1, 256, 1, 0, 1, 2, 1) + struct.pack('>III', 1, 12, 4) + b'abcd' + b'\0'*4
pcap('flows', [U(4000, 2055, nf5), U(4000, 2055, nf9), U(4000, 4739, ipfix), U(4000, 6343, sf)])
rtp = struct.pack('>BBHII', 0x80, 0, 1, 160, 0x11223344) + b'\xff'*40
rtpx = struct.pack('>BBHII', 0x90, 111, 1, 160, 0x11223344) + b'\xbe\xde\0\1\x10\xaa\0\0' + b'\xff'*20
rtcp = struct.pack('>BBHI', 0x80, 200, 6, 0x11223344) + b'\0'*20
pcap('rtp', [U(5004, 5006, rtp), U(40000, 50000, rtpx), U(5005, 5007, rtcp)])
sni = b'\0\0' + struct.pack('>H', 9) + struct.pack('>HBH', 7, 0, 4) + b'test'
exts = sni + b'\0\x10\0\5\0\3\2h2' + b'\0\x2b\0\3\2\3\4'
ch = b'\3\3' + b'\1'*32 + b'\0' + b'\0\2\x13\1' + b'\1\0' + struct.pack('>H', len(exts)) + exts
hs = b'\1' + struct.pack('>I', len(ch))[1:] + ch
sh = b'\3\3' + b'\2'*32 + b'\0' + b'\x13\1\0\0\0'
pcap('tls', [T(443, b'\x16\3\1' + struct.pack('>H', len(hs)) + hs),
             T(443, b'\x16\3\3' + struct.pack('>H', len(sh) + 4) + b'\2' + struct.pack('>I', len(sh))[1:] + sh),
             T(443, b'\x17\3\3\0\5abcde'), T(443, b'\x15\3\3\0\2\2\x28')])
lcp = b'\xff\x03\xc0\x21\x01\x01\0\x0e\x01\x04\x05\xd4\x03\x04\xc0\x23\x05\x06\0\0\0\1'[:18]
ppp_set = [lcp, b'\xff\x03\x80\x21\x01\x01\0\x0a\x03\x06' + IP1, b'\xff\x03\x80\x57\x01\x01\0\x0e\x01\x0a' + b'\1'*8,
           b'\xff\x03\x80\xfd\x01\x01\0\x04', b'\xff\x03\xc0\x23\x01\x01\0\x0a\x03abc\x01x',
           b'\xff\x03\xc2\x23\x01\x01\0\x0a\x01z\x03abc'[:14], b'\xff\x03\x00\x21' + ip4(1, b'\x08\0\0\0\0\1\0\1')]
pcap('ppp', ppp_set, dlt=9)
pcap('ppp_serial', ppp_set[:2], dlt=50)
pcap('pppoe', [eth(b'\x11\x09\0\0\0\x0c\x01\x01\0\0\x01\x03\0\4abcd', 0x8863),
               eth(b'\x11\0\0\1\0\x0a' + ppp_set[0][2:], 0x8864)])
pcap('cisco', [snap(b'\0\0\x0c', 0x2000, b'\x02\xb4\0\0\0\1\0\7router1', b'\x01\0\x0c\xcc\xcc\xcc'),
               snap(b'\0\0\x0c', 0x2003, b'\x01\x01\0\4home' + b'\0'*28 + b'\0\0\0\1', b'\x01\0\x0c\xcc\xcc\xcc'),
               snap(b'\0\0\x0c', 0x2004, b'\x01\0\1\0\x0ahome\0\0\0\2\0\5\x03\0\3\0\5\x45', b'\x01\0\x0c\xcc\xcc\xcc'),
               snap(b'\0\0\x0c', 0x0111, b'\x21\x01\0\0\0\1\0\x08port\0\0\0\0', b'\x01\0\x0c\xcc\xcc\xcc'),
               U(1589, 1589, b'\1\1\0\0\0\0\0\1\0\0\x0c\x01\0\4' + IP1),
               eth(ip4(17, udp(1985, 1985, b'\0\0\0\x08\x0a\x64\1\0cisco\0\0\0' + IP2)))])
pcap('hp_lacp', [eth(b'\0\0\x60\0\0\0\0\0', 0x887b), eth(b'\1\0\xa0\0\0\0\0\0\0\0', 0x88e1),
                 eth(b'\1\1\1\x14' + b'\0'*106, 0x8809), eth(b'\x01\x00\x00\x00\x00\x00\x00\x00', 0x88e5),
                 eth(b'\0\x2b\x46\0' + b'\0'*8, 0x8902), eth(b'\xff\xff\0\x1e\0\4' + b'\0'*24, 0x8137),
                 eth(b'\1\0\0\5\1\1\0\5\1', 0x888e), eth(b'\2\3\0\x5f\x02\x00\x8a\0\x10' + b'\0'*90, 0x888e)])
pcap('apps', [U(1000, 500, b'\1'*16 + b'\0'*8 + b'\x21\x20\x22\x08\0\0\0\0\0\0\0\x1c\0\0\0\0'),
              U(1000, 4500, b'\0\0\0\0' + b'\1'*16), U(1000, 51820, b'\1\0\0\0' + b'\0'*144), U(1000, 1194, b'\x38' + b'\0'*20),
              U(1701, 1701, b'\xc8\x02\0\x14\0\1\0\1\0\0\0\0\x80\x08\0\0\0\0\0\1'), U(1000, 2152, b'\x30\xff\0\x1c\0\0\0\1' + ip4(1, b'\x08\0\0\0\0\1\0\1')),
              U(3544, 3544, ip6(59, b'')), U(1000, 3784, b'\x20\xc0\3\x18\0\0\0\1\0\0\0\1\0\0\0\0\0\0\0\0\0\0\0\0'),
              U(521, 521, b'\2\1\0\0' + I6a + b'\0\0\x40\1'), T(445, b'\0\0\0\x20\xfeSMB' + struct.pack('<H', 64) + b'\0'*58),
              T(389, b'\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\0\x80\0'), T(88, b'\0\0\0\6\x6a\4\x30\2\1\0'), U(1000, 88, b'\x6a\4\x30\2\1\0'),
              T(1883, b'\x10\x10\0\4MQTT\4\2\0\x3c\0\4test'), T(111, b'\x80\0\0\x28\0\0\0\1\0\0\0\0\0\0\0\2\0\1\x86\xa0\0\0\0\2\0\0\0\0' + b'\0'*16),
              T(3389, b'\3\0\0\x0b\6\xe0\0\0\0\0\0'), T(5900, b'RFB 003.008\n'), T(502, b'\0\1\0\0\0\6\1\3\0\0\0\1'),
              T(646, b'\0\1\0\x1e\x0a\0\0\1\0\0\1\0\0\x14\0\0\0\1\1\0\0\x04\0\x0f\0\0\4\1\0\4' + IP1),
              T(25, b'EHLO x\r\n'), T(21, b'USER x\r\n'), T(53, b'\0\x21' + dns()),
              eth(ip4(132, struct.pack('>HHII', 1, 2, 1, 0) + b'\1\0\0\x14' + b'\0'*16)), eth(ip4(88, b'\2\5\0\0\0\0\0\0\0\0\0\1\0\0\0\0\0\0\0\1')),
              eth(ip4(51, bytes([1, 4, 0, 0]) + b'\0'*20 + b'\x08\0\0\0\0\1\0\1'))])
ptpm = b'\0\x02\0\x2c' + b'\0'*40
pcap('ptp', [U(319, 319, ptpm), eth(ptpm, 0x88f7)])
nfl = b'\2\0\0\1' + struct.pack('<HH', 8, 1) + struct.pack('>HBB', 0x0800, 0, 0) + struct.pack('<HH', 4 + 28, 9) + ip4(1, b'\x08\0\0\0\0\1\0\1')
pcap('nflog', [nfl], dlt=239)
usbh = struct.pack('<QBBBBHBBqiIII', 1, 0x53, 2, 0x80, 1, 1, 0, 0, 1700000000, 0, 0, 8, 8) + b'\x80\x06\0\1\0\0\x12\0' + b'\0'*16 + b'\x12\1\0\2\0\0\0\x40'
pcap('usb', [usbh], dlt=220)
pcap('usb48', [usbh[:48] + usbh[64:]], dlt=189)
pcap('chdlc', [b'\x0f\0\x08\0' + ip4(1, b'\x08\0\0\0\0\1\0\1'), b'\x8f\0\x80\x35\0\0\0\0' + b'\0'*14], dlt=104)
pcap('dot11', [b'\x80\0\0\0' + b'\xff'*6 + M1 + M1 + b'\0\0' + b'\0'*12 + b'\0\4home', b'\xd4\0\0\0' + M1, b'\x08\x03\0\0' + M1 + M2 + M1 + b'\0\0' + M2 + b'\xaa\xaa\3\0\0\0\x08\0' + ip4(1, b'\x08\0\0\0\0\1\0\1')], dlt=105)
pcap('fddi', [b'\x50' + M1 + M2 + b'\xaa\xaa\3\0\0\0\x08\0' + ip4(1, b'\x08\0\0\0\0\1\0\1')], dlt=10)
pcap('tokenring', [b'\x10\x40' + M1 + M2 + b'\xaa\xaa\3\0\0\0\x08\0' + ip4(1, b'\x08\0\0\0\0\1\0\1')], dlt=6)
pcap('slip', [b'\0'*16 + ip4(1, b'\x08\0\0\0\0\1\0\1')], dlt=8)
pcap('pflog', [struct.pack('>IB', 61, 2) + b'\0'*56 + ip4(1, b'\x08\0\0\0\0\1\0\1')], dlt=117)
pcap('sll2', [b'\x08\0\0\0\0\0\0\2\0\1\4\6' + M1 + b'\0\0' + ip4(1, b'\x08\0\0\0\0\1\0\1')], dlt=276)

S.N.I.F : Seek Network Interface Frames

Author: Damien MATTEI (Nice / FRANCE) , email: damien.mattei@gmail.com

common options:

-i interface ex: -i eth1

-r : resolve IP in DNS names

-v :  verbose mode

-f file : read the packets from a pcap (tcpdump) file instead of an interface

-x : dump the packets in hexadecimal and ASCII

-1 : one line by packet, the main line of each layer in its color (and
     its symbol with -S), as compact as tcpdump:

     10:57:03.123456  IP 192.168.1.30 > 192.168.1.1  UDP 41234 > 53 (domain)
       DNS query 0x1a2b  Question: apple.com A

-w file : write the packets to a pcap file (not shown, unless --print)
     -C size : a new file every size million bytes;  -G seconds : a new
     file every seconds (name with strftime);  -W count : a ring of files
     with -C, a stop after count files with -G

-A : dump the packets in ASCII;  -F file : read the filter from a file;
-Z user : started as root, run as this user once the capture is open

-D : list the interfaces;  -Q in|out|inout : direction of the packets;
-# : number of each packet;  -B size : kernel buffer in KiB

-I : Wi-Fi monitor mode: all the 802.11 frames of the channel (beacons,
     associations, WPA handshakes...); it may cut the Wi-Fi connection

--absolute : absolute TCP sequence numbers; by default they are relative
     to the start of the connection, as in tcpdump (seq 1:518, ack 1)

--tcpdump : one line by packet in the format of tcpdump, in colors:

     11:15:16.018629 IP acer.36322 > www.gnu.org.https: Flags [S], seq 242255833, win 64800, options [mss 1440,sackOK,TS val 1 ecr 0,nop,wscale 7], length 0
     11:15:14.946033 IP acer.33753 > livebox.home.domain: 61632+ A? wikipedia.org. (31)

     The names come without any traffic: the name of this machine,
     /etc/hosts, and the DNS, mDNS and LLMNR answers seen in the capture
     (tcpdump sends reverse DNS queries, that appear in its own capture)

-t : no time stamps. The time stamps are to the microsecond; as in
     tcpdump, -tt shows the seconds since 1970, -ttt the time since the
     previous packet, -tttt the date and time ISO 8601, -ttttt the time
     since the first packet

-8 : use only the 8 basic colors. By default, when the terminal says it
     knows the palette of 256 colors (TERM=xterm-256color, or COLORTERM
     set, as in xfce4-terminal, gnome-terminal, konsole), softer colors
     are used (see color.h), a shade for the first line of each layer
     and a darker one for its details:

     layer                       256 colors                  8 colors
     link (Ethernet, Wi-Fi...)   soft green, grey green      green
     network (IP, IPv6, ARP)     golden yellow, dark gold    yellow
     ICMP, ICMPv6, IGMP          light red, brick red        red
     TCP, SCTP                   turquoise, dark turquoise   cyan
     UDP                         cornflower blue, steel blue blue
     applications                pale magenta, orchid        magenta
     tunnels (GRE, VXLAN...)     orange, dark orange         magenta
     routing (OSPF, BGP...)      light purple, dark purple   magenta

-T rtp : decode the UDP datagrams as RTP and RTCP, as tcpdump -T rtp.
     Without it, RTP and RTCP have no port of their own and are
     recognized by their header (the extensions of WebRTC, the even ports
     and usual codecs of the SIP phones), carefully to avoid mistaking
     other traffic for them

-S : show a symbol before the first line of each layer, which helps
     without colors (-s, or the output in a file): in UTF-8 when the
     locale is (LANG=fr_FR.UTF-8 for instance), in ASCII otherwise

     link ▪ #   network ◆ @   ICMP ✖ !   transport ▸ >
     application ✻ *   tunnel ◎ =   routing ✦ +

-K : don't verify TCP and UDP checksums. Without -K, the checksums of the
     packets sent by us are not verified anyway: the network card computes
     them after the capture (checksum offloading). They are recognized by
     the hardware address of the capture interface, or by the direction
     given by a Linux cooked capture (-i any).

snif -h gives the list of all the options.

decoded protocols (the layers are shown in different colors):

link layer   : Ethernet (vendor of the cards), 802.3/LLC/SNAP, VLAN 802.1Q
               and QinQ, PPPoE, PPP (LCP, IPCP, IPV6CP, CCP, PAP, CHAP,
               EAP), Linux cooked captures (SLL, SLL2),
               NFLOG (Linux firewall), USB (usbmon), Wi-Fi 802.11 and radiotap, EAPOL/EAP, Token Ring, FDDI,
               Spanning Tree (STP, RSTP, MSTP, PVST+), LLDP, CDP, Cisco VTP,
               DTP, UDLD and VQP, LACP and
               the slow protocols, CFM 802.1ag and Y.1731, MACsec, MPLS,
               HomePlug 1.0 and AV (power line),
               ARP/RARP
network      : IPv4 (options), IPv6 (extension headers), ICMP, ICMPv6
               (neighbor discovery, MLD), IGMP, IPX (RIP, SAP), AH, ESP,
               GRE, ERSPAN, IP-in-IP, 6in4
transport    : TCP (options), UDP, SCTP
routing      : OSPF v2/v3, IS-IS, BGP, RIP, RIPng, EIGRP, PIM, VRRP, CARP, HSRP, BFD,
               LDP (MPLS labels, pseudowires)
tunnels, VPN : VXLAN, Geneve, L2TP, Teredo, GTP-U, IKE v1/v2, ESP in UDP,
               WireGuard, OpenVPN
applications : DNS, mDNS, LLMNR, DHCP, DHCPv6, NTP, SSDP, TLS (server name,
               versions, key exchange, certificate), QUIC, HTTP, SIP, RTSP,
               SMTP, FTP, POP3, IMAP, SSH, Telnet, SNMP, syslog, TFTP,
               NetBIOS, SMB, LDAP, Kerberos, RADIUS, STUN/TURN, NetFlow (v1,
               v5, v6, v7, v9), IPFIX, sFlow, PTP (IEEE 1588, also over
               Ethernet), RTP/RTCP (and SRTP/SRTCP headers),
               MQTT, CoAP,
               ONC RPC/NFS, RDP, VNC, Modbus/TCP, WS-Discovery, Tuya
               (smart devices), Dropbox LAN sync

snif does not reassemble the TCP streams: a message cut over several
segments is decoded only in its first segment.

the arguments following the options make a capture filter, in the syntax
of tcpdump (man pcap-filter), ex:

snif -i wlp0s20f3 port 53
snif -f capture.pcap 'host 192.168.1.1 and not tcp'

live capture needs root privileges (sudo ./snif), or the capture
capabilities given to the program once after each build:

sudo setcap cap_net_raw,cap_net_admin=eip ./snif

reading a pcap file with -f needs no privileges.


compilation:

./configure && make

after a modification of configure.ac or Makefile.am, regenerate them with:

autoreconf -fi && ./configure && make

the data files (ethernet vendor codes and port numbers) can be updated
with the scripts of the contrib directory (see contrib/readme).


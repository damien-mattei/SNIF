S.N.I.F : Seek Network Interface Frames

Author: Damien MATTEI (Nice / FRANCE) , email: damien_mattei@users.sourceforge.net

common options:

-i interface ex: -i eth1

-r : resolve IP in DNS names

-v :  verbose mode

-f file : read the packets from a pcap (tcpdump) file instead of an interface

-x : dump the packets in hexadecimal and ASCII

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
               and QinQ, PPPoE, PPP, Linux cooked captures (SLL, SLL2),
               Wi-Fi 802.11 and radiotap, EAPOL/EAP, Token Ring, FDDI,
               Spanning Tree (STP, RSTP, MSTP, PVST+), LLDP, CDP, LACP and
               the slow protocols, MPLS, HomePlug 1.0 and AV (power line),
               ARP/RARP
network      : IPv4 (options), IPv6 (extension headers), ICMP, ICMPv6
               (neighbor discovery, MLD), IGMP, IPX (RIP, SAP), AH, ESP,
               GRE, ERSPAN, IP-in-IP, 6in4
transport    : TCP (options), UDP, SCTP
routing      : OSPF v2/v3, BGP, RIP, RIPng, EIGRP, PIM, VRRP, HSRP, BFD
tunnels, VPN : VXLAN, Geneve, L2TP, Teredo, GTP-U, IKE v1/v2, ESP in UDP,
               WireGuard, OpenVPN
applications : DNS, mDNS, LLMNR, DHCP, DHCPv6, NTP, SSDP, TLS (server name,
               versions, key exchange, certificate), QUIC, HTTP, SIP, RTSP,
               SMTP, FTP, POP3, IMAP, SSH, Telnet, SNMP, syslog, TFTP,
               NetBIOS, SMB, LDAP, Kerberos, RADIUS, STUN/TURN, MQTT, CoAP,
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


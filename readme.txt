S.N.I.F : Seek Network Interface Frames

Author: Damien MATTEI (Nice / FRANCE) , email: damien_mattei@users.sourceforge.net

common options:

-i interface ex: -i eth1

-r : resolve IP in DNS names

-v :  verbose mode

-f file : read the packets from a pcap (tcpdump) file instead of an interface

-K : don't verify TCP and UDP checksums. Without -K, the checksums of the
     packets sent by us are not verified anyway: the network card computes
     them after the capture (checksum offloading). They are recognized by
     the hardware address of the capture interface, or by the direction
     given by a Linux cooked capture (-i any).

snif -h gives the list of all the options.

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


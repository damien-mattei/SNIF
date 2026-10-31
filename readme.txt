S.N.I.F : Seek Network Interface Frames

Author: Damien MATTEI (Nice / FRANCE) , email: damien_mattei@users.sourceforge.net

common options:

-i interface ex: -i eth1

-r : resolve IP in DNS names

-v :  verbose mode

-f file : read the packets from a pcap (tcpdump) file instead of an interface

-K : don't verify TCP and UDP checksums (the network card may compute
     the checksum of the outgoing packets after the capture)

snif -h gives the list of all the options.


compilation:

./configure && make

after a modification of configure.ac or Makefile.am, regenerate them with:

autoreconf -fi && ./configure && make

the data files (ethernet vendor codes and port numbers) can be updated
with the scripts of the contrib directory (see contrib/readme).


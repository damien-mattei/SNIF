#!/bin/sh
#
# this script update the ethernet and port informations
# (var/ieee_ethercodes.dat and var/portnumbers.dat)
#
# it is better to run this script in the var directory
#
# usage:
#
#   ../contrib/updatevar.sh
#        download the Wireshark manuf file (generated weekly from the IEEE
#        registries, please do not download it more than once a week)
#
#   ../contrib/updatevar.sh oui.csv mam.csv oui36.csv iab.csv
#        convert the official IEEE registries instead, the IEEE web site
#        rejects downloads from scripts so get them with a web browser:
#          https://standards-oui.ieee.org/oui/oui.csv     (MA-L, 24 bits)
#          https://standards-oui.ieee.org/oui28/mam.csv   (MA-M, 28 bits)
#          https://standards-oui.ieee.org/oui36/oui36.csv (MA-S, 36 bits)
#          https://standards-oui.ieee.org/iab/iab.csv     (IAB,  36 bits)
#        (a copy may also exist in /usr/share/ieee-data/ , package ieee-data)

MANUF_URL=https://www.wireshark.org/download/automated/data/manuf.gz

PORTS_URL=https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv

# where are the preformat_*.pl scripts ?
CONTRIB=`dirname "$0"`

ETHERFILE=ieee_ethercodes.dat

# the new files must have at least this number of lines to replace the old ones
MINLINES=10000

PORTSFILE=portnumbers.dat

MINPORTS=5000

echo "Retrieving the ethernet vendor codes:"

if [ $# -eq 0 ]; then

    curl -fsSL "$MANUF_URL" | gunzip | "$CONTRIB/preformat_ethercodes.pl" > $ETHERFILE.new

else

    "$CONTRIB/preformat_ethercodes.pl" "$@" > $ETHERFILE.new

fi

if [ $? -eq 0 ] && [ `wc -l < $ETHERFILE.new` -ge $MINLINES ]; then

    mv -f $ETHERFILE.new $ETHERFILE
    echo "`wc -l < $ETHERFILE` ethernet vendor codes written in $ETHERFILE"

else

    echo "Failed to build the ethernet vendor codes, $ETHERFILE not modified"
    rm -f $ETHERFILE.new

fi

echo "Retrieving port numbers:"

# IANA Service Name and Transport Protocol Port Number Registry
curl -fsSL "$PORTS_URL" | "$CONTRIB/preformat_ports_iana.pl" > $PORTSFILE.new

if [ $? -eq 0 ] && [ `wc -l < $PORTSFILE.new` -ge $MINPORTS ]; then

    mv -f $PORTSFILE.new $PORTSFILE
    echo "`wc -l < $PORTSFILE` port numbers written in $PORTSFILE"

else

    echo "Failed to build the port numbers, $PORTSFILE not modified"
    rm -f $PORTSFILE.new

fi

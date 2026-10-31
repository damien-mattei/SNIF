#!/usr/bin/perl -w

# read the ethernet vendor codes on STDIN (or in the files given as arguments)
# and convert them in a 2 columns file with ethernet code and constructor,
# separator of output file is tab
#
# accepted input formats (can be mixed):
#
#  - Wireshark manuf file (generated weekly from the IEEE registries):
#    https://www.wireshark.org/download/automated/data/manuf.gz
#    read this:   00:55:DA:10/28<TAB>KoolPOS<TAB>KoolPOS Inc.
#
#  - IEEE registries in CSV format (oui.csv, mam.csv, oui36.csv, iab.csv)
#    https://standards-oui.ieee.org/oui/oui.csv (download them with a web browser)
#    read this:   MA-M,0055DA1,KoolPOS Inc.,address...
#
# return that: 0055DA1<TAB>KoolPOS Inc.
#
# the length of the code gives the size of the block:
# 6 hex digits = 24 bits (MA-L), 7 = 28 bits (MA-M), 9 = 36 bits (MA-S, IAB)
#
# run like that:
# cd var
# ../contrib/preformat_ethercodes.pl manuf > ieee_ethercodes.dat
# ../contrib/preformat_ethercodes.pl oui.csv mam.csv oui36.csv iab.csv > ieee_ethercodes.dat

use strict; # it's always better to be strict when coding ;-)

my $max_name_len = 200; # snif reads lines of 255 chars max

my %vendor; # ethernet code => constructor name

# clean a constructor name: no tab, no CR, no multiple spaces
sub clean_name {
    my $name = shift;
    $name =~ s/[\t\r\n]/ /g;
    $name =~ s/\s+/ /g;
    $name =~ s/^ //;
    $name =~ s/ $//;
    $name = substr($name, 0, $max_name_len);
    return $name;
}

while (my $line = <>) {

    chomp $line;
    $line =~ s/\r$//;

    # Wireshark manuf: address block, short name, long name
    if ($line =~ /^([0-9A-Fa-f]{2}(?:[:\-.][0-9A-Fa-f]{2})+)(?:\/(\d+))?\s*\t([^\t]*)(?:\t(.*))?$/) {

        my ($addr, $bits, $short, $long) = ($1, $2, $3, $4);

        $bits = 24 unless defined $bits;
        next if ($bits % 4); # not on a hex digit boundary

        $addr =~ s/[:\-.]//g;
        my $code = uc(substr($addr, 0, $bits / 4));
        next if (length($code) != $bits / 4);

        my $name = (defined $long && $long =~ /\S/) ? $long : $short;
        $name = clean_name($name);
        $vendor{$code} = $name if ($name ne '');

    }

    # IEEE CSV: Registry,Assignment,Organization Name,Organization Address
    elsif ($line =~ /^(?:MA-L|MA-M|MA-S|IAB),([0-9A-Fa-f]+),("(?:[^"]|"")*"|[^,]*)/) {

        my ($code, $name) = (uc($1), $2);

        if ($name =~ /^"(.*)"$/) { # remove quotes
            $name = $1;
            $name =~ s/""/"/g;
        }

        $name = clean_name($name);
        $vendor{$code} = $name if ($name ne '');

    }

    # anything else (comments, headers, empty lines) is skipped
}

foreach my $code (sort keys %vendor) {
    print $code, "\t", $vendor{$code}, "\n";
}

#!/usr/bin/perl -w

# read the IANA Service Name and Transport Protocol Port Number Registry
# in CSV format on STDIN (or in the files given as arguments)
# and convert it in a 3 columns file with port number, service name
# and description, separator of output file is tab
#
# the registry can be downloaded here:
# https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv
#
# read this:   ssh,22,tcp,The Secure Shell (SSH) Protocol,...
# return that: 22<TAB>ssh<TAB>The Secure Shell (SSH) Protocol
#
# when TCP and UDP use the same port for different services,
# the TCP one is kept (then UDP, then other transport protocols)
#
# run like that:
# cd var
# ../contrib/preformat_ports_iana.pl service-names-port-numbers.csv > portnumbers.dat

use strict; # it's always better to be strict when coding ;-)

my $max_desc_len = 200; # snif reads lines of 255 chars max

my %rank = ( 'tcp' => 0, 'udp' => 1 ); # preferred transport protocols

my %service; # port number => [ rank, name, description ]

# clean a field: no tab, no CR/NL, no multiple spaces
sub clean_field {
    my $field = shift;
    $field =~ s/\s+/ /g;
    $field =~ s/^ //;
    $field =~ s/ $//;
    return $field;
}

# read the whole file, quoted fields may contain commas and new lines
my $csv = do { local $/; <> };
$csv = '' unless defined $csv;

my @record; # fields of the current record
my $line = 0; # record number

while ($csv =~ /\G("(?:[^"]|"")*"|[^,\r\n]*)(,|\r?\n|\z)/gc) {

    my ($field, $sep) = ($1, $2);

    if ($field =~ /^"(.*)"$/s) { # remove quotes
        $field = $1;
        $field =~ s/""/"/g;
    }

    push @record, $field;

    next if ($sep eq ','); # record not finished

    $line++;

    # Service Name,Port Number,Transport Protocol,Description,...
    my ($name, $port, $proto, $desc) = @record;
    @record = ();

    last if ($sep eq '' && !defined $port); # end of input

    next if ($line == 1); # header
    next unless defined $desc;

    $name = clean_field($name);
    $desc = clean_field($desc);
    $proto = lc(clean_field($proto));

    # skip Unassigned, Reserved, De-registered... (they have no service name)
    next if ($name eq '');
    next unless ($port =~ /^(\d+)(?:-(\d+))?$/);

    my ($first, $last) = ($1, defined $2 ? $2 : $1);

    $desc = $name if ($desc eq '');
    $desc = substr($desc, 0, $max_desc_len);

    my $r = exists $rank{$proto} ? $rank{$proto} : 2;

    for my $p ($first .. $last) {
        # keep the preferred protocol, the first one seen if same rank
        next if (exists $service{$p} && $service{$p}[0] <= $r);
        $service{$p} = [ $r, $name, $desc ];
    }

    last if ($sep eq ''); # end of input
}

foreach my $p (sort { $a <=> $b } keys %service) {
    print $p, "\t", $service{$p}[1], "\t", $service{$p}[2], "\n";
}

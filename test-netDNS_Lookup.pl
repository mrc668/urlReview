#!/usr/bin/perl

use Net::DNS;
use URI;
use strict;
use warnings;
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Status qw(:constants :is status_message);
use Data::Dumper;
use URI::Encode;
use JSON;

our $mispAPIKey=q();
our @artifacts;
push @INC, q(.);
require ".env";
	die("misp key empty.") if $mispAPIKey eq "";

require "urlReviewSubs.pl";

our $LogFile = q(test-netDNS_Lookup.log);
my @expected = qw(
	24.89.85.117
	142.3.31.17
);
push @artifacts, q(24.89.85.117);
push @expected, qq(24.89.85.117 is already in artifacts and should noe be added by netDNS_Lookup.);

print "Expected:\n" . join("\n", @expected) . "\n\n";
netDNS_Lookup(qq(sal001675.is.uregina.ca));
netDNS_Lookup(qq(monitor.calnek.com));
print "\nResults\n\n";
print join("\n",@artifacts), "\n";


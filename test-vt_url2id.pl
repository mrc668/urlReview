#!/usr/bin/perl

use URI;
use strict;
use warnings;
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Status qw(:constants :is status_message);
use Data::Dumper;
use URI::Encode;
use JSON;

our $vtAPIKey=q();
push @INC, q(.);
require ".env";
	die("key empty.") if $vtAPIKey eq "";

require "urlRevieSubs.pl";

our $LogFile = q(test-vt_url2id.log);
my $id = vt_url2id(q(https://www.uregina.ca));
print "vt_url2id() = $id\n";


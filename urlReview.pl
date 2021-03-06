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

my $URI_Encode     = URI::Encode->new( { encode_reserved => 1 } );
my $BaseName = $URI_Encode->encode($ARGV[0]);
our $LogFile = sprintf("%s-%s.log", 
	substr($URI_Encode->encode($ARGV[0]),0,48),
	time()
);
	


openURL($ARGV[0]);


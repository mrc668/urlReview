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

our $mispAPIKey=q();
push @INC, q(.);
require ".env";
	die("misp key empty.") if $mispAPIKey eq "";

require "urlReviewSubs.pl";

our $LogFile = q(test-misp.log);
#check_misp("canada-packrec-b2efb2.ingress-comporellon.ewp.live");
check_misp("https://ueduca.000webhostapp.com/");
check_misp("195.142.132.154");


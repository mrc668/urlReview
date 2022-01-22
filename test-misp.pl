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

require "urlRevieSubs.pl";

our $LogFile = q(test-misp.log);
misp_api("cyberwise.biz");


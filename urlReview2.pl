#!/usr/bin/perl

push @INC, q(.);

use URI;
use strict;
use warnings;
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Status qw(:constants :is status_message);
use Data::Dumper;
use URI::Encode;
use JSON;
use Net::DNS;
require "urlReviewSubs.pl";

our $vtAPIKey=q();
push @INC, q(.);
require ".env";
	die("key empty.") if $vtAPIKey eq "";


our @artifacts;
push @artifacts, $ARGV[0];
# read from argv[0]

my $URI_Encode     = URI::Encode->new( { encode_reserved => 1 } );
my $BaseName = $URI_Encode->encode($artifacts[0]);
our $LogFile = sprintf("%s-%s.log", 
	substr($URI_Encode->encode($artifacts[0]),0,48),
	time()
);
	

sub analyze_artifact {
	my ($art) = @_;

	analyze_url($art) if $art =~ m/^http/;
	analyze_ip($art) if $art =~ m/^[0-9\.]*$/;
	analyze_name($art) if $art !~ m/[:\/]/   and $art =~ m/[a-z]+/;
}

sub analyze_url {
	my ($art) = @_;
	print "\nAnalyzing url: $art\n";
	print "="x40 . "\n";
	my $uri = URI->new($art);
	my @log = (qq(analyze_url($art)));

	my $dom = $uri->host;
	if( grep({ $dom eq $_ } @artifacts) ) {
		print "$dom is already in \@artifacts\n";
	} else {
		print "adding $dom to \@artifacts\n";
		push @artifacts, $dom;
		netDNS_Lookup($dom);
	}

	if ( openURL($art) == 200 ) {

		# check url against VT
		#vt_api( $uri->as_string);

		# check url against cyber gordon

		#   check for word press
		#   if yes - check for exposed admin interfaces: https://yourdomain.com/wp-admin https://yourdomain.com/wp-login.php
		detectWordPress($uri->host);
	
		#   check for joomla
		#   check for cpanel
	
		#   check for security contact
		wellKnown($uri->host);
	
		#   compare output against browser variations
		# if no:
		#   add new location to artifacts
	} else {
		print "Not checking for wordpress\n";
	}


	# check url against misp
	check_misp($art);


}

sub analyze_ip {
	my ($art) = @_;
	my @log = (qq(analyze_ip($art)));

	print "\nAnalyzing ip: $art\n";
	print "="x40 . "\n";
	if( 
		( $art eq q(99.83.179.4) ) ||
		( $art eq q(75.2.78.236) ) ) {
		print "Its CIRA-Malware detected. Skipping tests.\n";
		push @log, "Its CIRA-Malware detected. Skipping tests.";
	} else {
		# check ip against VT

		# check ip against misp
		whoisIP($art);
		check_misp($art);

		# check ip against cyber gordon
	}
}

sub analyze_name {
	my ($art) = @_;

	print "\nAnalyzing name: $art\n";
	print "="x40 . "\n";
	# check name against VT
	# check name against misp
	check_misp($art);
	check_sans_domain($art);

	# check name against cyber gordon
	# check for http[s]://name/contact
	# check certificate chain on https - who signed it, is it valid, CN.
	# check whois

}


my $i=0;
while ( $i <= $#artifacts ) {
	analyze_artifact( $artifacts[$i] );
	$i++;
}


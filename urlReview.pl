#!/usr/bin/perl

use URI;
use strict;
use warnings;
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Status qw(:constants :is status_message);
use Data::Dumper;

our $vtAPIKey=q();
push @INC, q(.);
require ".env";
	die("key empty.") if $vtAPIKey eq "";


open(debugLog,">urlReview.log");
print debugLog "="x40 . "\n";
print debugLog "start log\n";
print debugLog "="x40 . "\n";


sub logToDebug {
	my ($msg) = @_;

	my @stack = caller(0);
	#print Dumper \@stack;
	printf debugLog "%s:%s\n", $stack[1], $stack[2];

	printf debugLog "%s\n", $msg;
	printf debugLog "-"x40 . "\n";
} # logToDebug

sub detectWordPress {
	my($host) = @_;
	my @log=(q(detectWordPress()));
	my $url = "";
	my $ua = LWP::UserAgent->new(); # no reason to not follow redirect

	for my $proto (qw(https http)) {
		for my $dir (qw( . wp wordpress wordPress WordPress Wordpress wp-admin WP-Admin WP-ADMIN wp/wp-admin )) {
			for my $file (qw( . License.txt )) {
				$url = sprintf("%s://%s/%s/%s",$proto,$host,$dir,$file);
				my $req = HTTP::Request->new(GET => $url);
				my $res = $ua->request($req);
				push @log, "status " . $res->code . " " . $url;
				if( $res->code == 200 ) {
					#print "may be WP.\n";
					#push @log, "may be WP, $url has content.";
					my $content = $res->content;
					if( $content =~ m/WordPress/ ) {
						print "$host seems to be a word press site.\n";
						logToDebug join("\n",@log);
						return;
					} # if word press
				} # if status 200
			} # file
		} # dir
	} # proto

	logToDebug join("\n", @log, "does not appear to be word press on $host");
	print "does not appear to be word press on $host\n";

	return;
} # well known

sub wellKnown {
	my($host) = @_;
	my $url = "";
	my $ua = LWP::UserAgent->new(); # No reason to not follow redirects
	my @log=(q(wellKnown()));

	for my $proto (qw(https http)) {
		for my $dir (qw( wellknown .wellknown .)) {
			for my $file (qw( .security .security.txt security.txt )) {
				$url = sprintf("%s://%s/%s/%s",$proto,$host,$dir,$file);
				push @log, "Checking " . $url;
				my $req = HTTP::Request->new(GET => $url);
				my $res = $ua->request($req);
				if( $res->code == 200 ) {
					my $content = $res->content;
					print "security.txt: $url \n";
					print $content if length($content) < 1000;
					push @log, "security.txt";
					push @log, $content;
					logToDebug join("\n",@log);
					return;
				} # if
			} # file
		} # dir
	} # proto

	logToDebug join("\n", @log, "Failed to find security.txt on $host");
	print "Failed to find security.txt on $host\n";

	return;
} # well known

sub theJigIsUp {
	printf "Its www.cira.ca. The link is no longer interesting as it is known to be bad.\n";
	logToDebug sprintf "Its www.cira.ca. The link is no longer interesting as it is known to be bad.\n";
	exit 0;
} # the jig is up

sub openURL {
	my ($passedURL) =  @_;
	my $uri = URI->new($passedURL);
	my @log = (qq(openURL($passedURL)));

	#printf "proto: %s\n", $uri->scheme;
	#printf "host: %s\n", $uri->host;
	#printf "path: %s\n", $uri->path;
	#printf "full: %s\n", $uri->as_string;
	# check for www.cira.ca.
	theJigIsUp if $uri->host eq "www.cira.ca";
	printf "-"x40 . "\n";
	printf "reviewing: %s\n", $uri->as_string;
	push @log, sprintf "reviewing: %s", $uri->as_string;


	# Create a user agent object
	my $ua = LWP::UserAgent->new((max_redirect=>0));
	$ua->agent(q(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36));

	# Create a request
	my $req = HTTP::Request->new(GET => $uri->as_string);

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);

	# review result
	printf "Status code: %s\n" , $res->code ;
	push @log, "Status code: " . $res->code ;

	if( $res->code == 200 ) {

		# Check the outcome of the response
		my $content = $res->content;
		push @log, sprintf "Page content:\n%s", $content;
		logToDebug join("\n",@log);

		wellKnown($uri->host);
		detectWordPress($uri->host);
		vt_api( $uri->as_string);

	} elsif( $res->code == 301 || $res->code == 302 ) {
		printf "301 redirect to %s\n", $res->header("Location");
		push @log, "Location: " . $res->header("Location");
		logToDebug join("\n",@log);
		openURL($res->header("Location"));
		return;

	} else {
		push @log, "Unhandled status code";
		logToDebug join("\n",@log);
		die "Unahndled status code: $res->code";
	}
} # openURL()

sub vt_api {
	my($vtQuery) = @_;
	my @log = (qq(vt_api($vtQuery)));
	die("key not defined.")  if ! defined($vtAPIKey);
	die("key empty.") if $vtAPIKey eq "";
	push @log, sprintf "have vt API key, checking: %s", $vtQuery;


	# Create a user agent object
	my $ua = LWP::UserAgent->new();
	$ua->agent(q(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36));

	# Create a request
	#  curl --request POST --url "https://www.virustotal.com/api/v3/urls" --header "x-apikey: 983f75a3d73e933648e274a04242885b7e2d309223ac564814ed9fa20a5dd803" --form "url=www.supportme1800.com"
	my $req = HTTP::Request->new(
		POST => q(https://www.virustotal.com/api/v3/urls), 
		[ q(url) => $vtQuery ]
	);
	$req->header( q(x-apikey) => $vtAPIKey );
	#$req->header( q(content-length) => 12 + length($req->as_string) );
	$req->header( q(content-length) );

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);
	print Dumper $res;

	# review result
	printf "VT Status code: %s\n" , $res->code ;
	push @log, "VT Status code: " . $res->code ;

	if( $res->code == 200 ) {

		# Check the outcome of the response
		my $content = $res->content;
		push @log, sprintf "VT Content:\n%s", $content;
		logToDebug join("\n",@log);

	} else {
		print "Something went wrong in VT\n";
		push @log,  "Something went wrong in VT\n";
		logToDebug join("\n",@log);
	}

} # vt_url


openURL($ARGV[0]);


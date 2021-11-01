#!/usr/bin/perl

use URI;
use strict;
use warnings;
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Status qw(:constants :is status_message);
use Data::Dumper;

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

sub wellKnown {
	my($host) = @_;
	my $url = "";
	my $ua = LWP::UserAgent->new((max_redirect=>0));
	my @log=(q(wellKnown()));

	for my $proto (qw(http https)) {
		for my $dir (qw( wellknown .wellknown .)) {
			for my $file (qw( .security .security.txt security.txt )) {
				$url = sprintf("%s://%s/%s/%s",$proto,$host,$dir,$file);
				push @log, "Checking " . $url;
				my $req = HTTP::Request->new(GET => $url);
				my $res = $ua->request($req);
				if( $res->code == 200 ) {
					my $content = $res->content;
					print "security.txt\n";
					print $content;
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

sub openURL {
	my ($passedURL) =  @_;
	my $uri = URI->new($passedURL);
	my @log = (qq(openURL($passedURL)));

	#printf "proto: %s\n", $uri->scheme;
	#printf "host: %s\n", $uri->host;
	#printf "path: %s\n", $uri->path;
	#printf "full: %s\n", $uri->as_string;
	printf "-"x40 . "\n";
	printf "reviewing: %s\n", $uri->as_string;
	push @log, sprintf "reviewing: %s", $uri->as_string;


	# Create a user agent object
	my $ua = LWP::UserAgent->new((max_redirect=>0));
	$ua->agent("Contact Milton Calnek for more information");

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

	} elsif( $res->code == 301 ) {
		printf "301 redirect to %s\n", $res->header("Location");
		push @log, "Location: " . $res->header("Location");
		logToDebug join("\n",@log);
		openURL($res->header("Location"));
		return;

	} else {
		push @log, "Unhandled status code";
		logToDebug join("\n",@log);
		die;
	}



} # openURL()

openURL($ARGV[0]);


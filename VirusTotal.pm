#
# VirusTotal
#
# This package was insipred by Chistopher Frenz's perl script at:
#    http://perlgems.blogspot.com.es/2012/05/using-virustotal-api-v20.html
#
# Package is (C) Copyright Michelle Sullivan (SORBS) <michelle@sorbs.net> 2013
#

package VirusTotal;

use strict;

use LWP::UserAgent;
use JSON;

use Digest::SHA qw(sha1_hex sha256_hex);
use Digest::MD5 qw(md5_hex);
use List::Util qw(first);

use base qw(Exporter);

my $ID = q$Id: VirusTotal.pm 3164 2014-01-07 12:31:37Z michelle $;
my $VERSION = sprintf("%d.%d.%d.%d.%d.%d", $ID =~ /(\d+)-(\d+)-(\d+) (\d+):(\d+):(\d+)Z/);
my $TESTSTRING = "X5O\!P\%\@AP[4\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE\!\$H+H*";
my $INTERNALAGENT = sprintf("%s-MIS/0.%d", $ID =~ /Id:\s+(\w+)\.pm\s+(\d+)\s+/);

warn("[" . localtime(time()) . "] VirusTotal Revision: $VERSION (Agent: $INTERNALAGENT)\n");

sub new
{
        my $class = shift;
        my $this = {};
        my %arg = @_;

        $this->{DEBUG} = (exists $arg{debug} ? $arg{debug} : 0);
	$this->{FNLEN} = 64;

	my %scanhash = ();

	$this->{'ua'} = undef;
	$this->{'conn'} = undef;
	$this->{'scanhash'} = \%scanhash;
	
        bless ($this, $class);

        return $this;
}

sub init
{
	my $self = shift;
	$self->apiagent();
	$self->scanapi();
	$self->reportapi();
	$self->apikey();
}


sub debug
{
	my $self = shift;
	if (@_) {$self->{DEBUG} = $_[0]};
	return $self->{DEBUG};
}

sub conn_proxy
{
	my $self = shift;
	if (@_) {$self->{PROXY} = $_[0]};
	return $self->{PROXY};
}

sub apiagent
{
	my $self = shift;
	if (@_) {$self->{AGENTSTRING} = $_[0]};
	$self->{AGENTSTRING} = $INTERNALAGENT if (!defined $self->{AGENTSTRING});
	return $self->{AGENTSTRING};
}

sub conn_cache
{
	my $self = shift;
	if (@_) {$self->{CONNCACHE} = $_[0]};
	$self->{CONNCACHE} = 0 if (!defined $self->{CONNCACHE});
	return $self->{CONNCACHE};
}

sub allowlong
{
	my $self = shift;
	if (@_)
	{
		if ($_[0])
		{
			$self->{FNLEN} = 256;
		} else {
			$self->{FNLEN} = 64;
		}
	}
	return $self->{FNLEN};
}

sub cache
{
	my $self = shift;
	if (@_) {$self->{CACHE} = $_[0]};
	# if cache use is true, but the cache is not defined then init it
	if (!defined $self->{CACHE} and $self->conn_cache())
	{
		$self->{CACHE} = $self->init_cache();
	}
	# return the cache object, this could be undef if caching is not defined.
	return $self->{CACHE};
}
	
sub init_cache
{
	use LWP::ConnCache;

	my $self = shift;
	return $self->{CACHE} if defined $self->{CACHE};

	my $cache = LWP::ConnCache->new;
	$cache->total_capacity($self->cache_limit());
	return $cache;
}

sub cache_check
{
	my $self = shift;

	# if connection cache is not being used return true regardless
	return 1 if (!$self->conn_cache());

	# if the cache is not initialised return an error
	if (!defined $self->cache())
	{
		warn("Connection Cache is enabled but not intiialised!");
		return undef;
	}

	# Prune dead entries
	$self->cache->prune();
	return 1;
}

sub cache_limit
{
	my $self = shift;
	if (@_) {$self->{CACHELIMIT} = $_[0]};
	$self->{CACHELIMIT} = 1 if (!defined $self->{CACHELIMIT});
	return $self->{CACHELIMIT};
}

sub reportapi
{
	my $self = shift;
	if (@_) {$self->{VTREPORTAPI} = $_[0]};
	$self->{VTREPORTAPI} = "https://www.virustotal.com/vtapi/v2/file/report" if (!defined $self->{VTPREPORTAPI});
	return $self->{VTREPORTAPI};
}

sub scanapi
{
	my $self = shift;
	if (@_) {$self->{VTSCANAPI} = $_[0]};
	$self->{VTSCANAPI} = "https://www.virustotal.com/vtapi/v2/file/scan" if (!defined $self->{VTPSCANAPI});
	return $self->{VTSCANAPI};
}

sub apikey
{
	my $self = shift;
	if (@_) {$self->{APIKEY} = $_[0]};
	$self->{APIKEY} = undef if (!defined $self->{APIKEY});
	return $self->{APIKEY};
}

sub timeout
{
	my $self = shift;
	if (@_) { $self->{CONNTIMEOUT} = $_[0] };
	$self->{CONNTIMEOUT} = 30 if (!defined $self->{CONNTIMEOUT});
	return $self->{CONNTIMEOUT};
}

# Public method for accessing VirusTotal
sub scan
{
	my $self = shift;
	my $file = shift;
	my ($filename, $infected, $description) = (undef, undef, undef);
	my $tmpfile = 0;
	my $result = 0;
	warn("Entered scan()...") if $self->debug();
	if (length($file) > $self->allowlong() && $file !~ /\//)
	{
		$tmpfile++;
	} else {
		if ( -r $file && $file !~ /\.\./ )
		{
			# this is a filename and I can read it (and does not contain '..')
			$filename = $file;
		} else {
			$tmpfile++;
		}
	}
	if ($tmpfile)
	{
		$filename = "/tmp/nofilename-$$.tmp";
		open FILE, ">$filename";
		while (<$file>)
		{
			print FILE;
		}
		close FILE;
	}

	warn("Filename for scanning is: $filename") if $self->debug();
	if ($self->_connect())
	{
		warn("Connected to VT, scanning...") if $self->debug();
		# We are connected we can proceed....
		#
		open FILE, "<$filename";
		my $scankey = sha256_hex(<FILE>);
		close FILE;
		
		#
		# Check the internal checksums against the hash, if found we don't need to submit to VT
		# If not found we need to call the private method _submit() and actually submit it
		# If it is found we can call the private method _result() to get any results.
		if (exists $self->{'scanhash'}->{$scankey})
		{
			warn("Found a hash.. checking for a result..") if $self->debug();
			($infected, $description) = $self->_result($scankey);
			# return any result or undef if we have to wait for a result...
			if (!defined $infected)
			{
				# an error occurred, could be that the file has not completed scanning
				$description = "Please try later..";
			}
		} else {
			warn("Did not find a hash.. submitting for a scan...") if $self->debug();
			# scan key not found, so we need to submit it...
			$result = $self->_submit($scankey, $filename);
			if (defined $result)
			{
				# scan submission was successful, pause 15 seconds then check to see if there is a response
				if ($result ne 1)
				{
					warn("Scan returned something other than done so pausing 15 seconds...") if $self->debug();
					sleep 15;
				}
				($infected, $description) = $self->_result($scankey);
				# return any result or undef if we have to wait for a result...
				if (!defined $infected)
				{
					warn("Result check was an error, tempfailing...") if $self->debug();
					# an error occurred, could be that the file has not completed scanning
					$description = "Please try later..";
				}
			}
		}
	} else {
		# Not connected (and unable to connect) so return an error
		warn("Not connected to VirusTotal API, check your configuration!");
		$infected = undef;
		$description = "Not connected to VirusTotal API, check your configuration!";
	}
	unlink($filename) if ($tmpfile);
	return ($infected, $description);
}

# Private method to test the connection state and if not connected/tested to try a connection.
sub _connect
{
	my $self = shift;
	if (!ref $self or !ref $self->{'scanhash'})
	{
		die("You cannot call _connect() before calling new() (and you shouldn't do it!)");
	}

	if (defined $self->{'valid_conn'} && $self->{'valid_conn'} && defined $self->{'ua'})
	{
		# We have previously connected
		return $self->{'valid_conn'};
	}

	if (!defined $self->{'valid_conn'})
	{
		# No valid connection tried, so setup LWP
		if (!defined $self->{'ua'})
		{
			$self->{'ua'} = LWP::UserAgent->new(
				ssl_opts => { verify_hostname => 1 },
				agent => $self->apiagent(),
				timeout => $self->timeout(),
				conn_cache => $self->cache(),
			);
			if (defined $self->conn_proxy())
			{
				$self->{'ua'}->proxy('https', $self->conn_proxy());
			}
		}
		$self->{'valid_conn'} = 0;
	}
	# A connection was previously tried and failed, or this is a new connection
	if (!$self->{'valid_conn'} and $self->{'last_conn_check'} < (time() - 300))
	{
		# test the connection by sending the EICAR string..
		warn("Connecting to " . $self->reportapi() . " for the EICAR test..") if $self->debug();
		my $response = $self->{'ua'}->post( $self->reportapi(),
			Content_Type => 'multipart/form-data',
			Content => [
					'apikey' => $self->apikey(),
					'resource' => sha256_hex($TESTSTRING),
				],
			);
		if (!$response->is_success)
		{
			my $a = ( $response->status_line =~ /403 Forbidden/ ) ? " (Have you set your API key?)" : "";
			warn("Unable to connect to VirusTotal using " . $self->scanapi() . " error: " . $response->status_line . "$a\n");
		} else {
			my $results=$response->content;
			warn("Parsing test response: $results") if $self->debug();
			# pulls the sha256 value out of the JSON response
			# Note: there are many other values that could also be pulled out
			my $json = JSON->new->allow_nonref;
			my ($decjson, $sha, $respcode) = (undef, undef, undef);
			eval {
				$decjson = $json->decode($results);
			};
			if (defined $decjson)
			{
				# if json->decode() fails it will call croak, so we catch it and display the returned text
				$sha = $decjson->{"sha256"};
				$respcode = $decjson->{"response_code"};
				if (defined $sha && $sha ne "")
				{
					# we were able to submit successfully so we can set valid_conn to true
					$self->{'scanhash'}->{'test'}->{'key'} = $sha;
					$self->{'scanhash'}->{'test'}->{'submitted'} = sprintf("%d", $decjson->{"scanid"} =~ /^[1234567890abcdef]+-(\d+)$/);
					$self->{'scanhash'}->{'test'}->{'last_checked'} = sprintf("%d", $decjson->{"scanid"} =~ /^[1234567890abcdef]+-(\d+)$/);
					$self->{'scanhash'}->{'test'}->{'infected'} = $decjson->{"positives"};
					$self->{'scanhash'}->{'test'}->{'result'} = first { $_->{detected} } values %{ $decjson->{scans} };
					$self->{'valid_conn'} = 1;
					warn("Validated connection...") if $self->debug();
				} else {
					warn("Unable to parse test, VirusTotal responded with: $results");
				}
			}
		}
		$self->{'last_conn_check'} = time();
	}
	return $self->{'valid_conn'};
}

# Private method, will send the request to VirusTotal
sub _submit
{
	#Code to submit a file to Virus Total
	my $self = shift;
	my $res = undef;
	warn("Entered _submit()") if $self->debug();
	die ("You can't call this directly! Use the scan() method!") if (!ref $self);
	die ("You cannot call _submit() before calling new() (and you shouldn't do it!") if (!ref $self->{'scanhash'});

	if (!defined $self->{'valid_conn'} && !$self->{'valid_conn'})
	{
		warn("Not connected to VirusTotal, please check your connection before calling _submit()!");
		return $res;
	}

	my $scankey = shift; # This is our internally generated scan key to be used to lookup the result key
	my $file = shift; # This is the file name and location of the file to check

START:	warn("Sending file ($file)..") if $self->debug();
	my $response = $self->{'ua'}->post(
		$self->scanapi,
    		Content_Type => 'multipart/form-data',
    		Content => [
			'apikey' => $self->apikey(),
    			'file' => [$file]
		]
  	);
	if (!$response->is_success)
	{
		warn("Unable to post to '" . $self->scanapi() . "' error: " . $response->status_line . "\n");
		return $res;
	}
	my $results=$response->content;
	
	warn("Got response: $results") if $self->debug();
	#pulls the sha256 value out of the JSON response
	#Note: there are many other values that could also be pulled out
	my $json = JSON->new->allow_nonref;   
	my ($decjson, $sha, $respcode) = (undef, undef, undef);
	eval {
		$decjson = $json->decode($results);
	};
	if (defined $decjson)
	{
		# if json->decode() fails it will call croak, so we catch it and display the returned text
		$sha = $decjson->{"sha256"};
		$respcode = $decjson->{"response_code"};
		if (defined $respcode)
		{
			warn("Got response code $respcode") if $self->debug();
			if ($respcode eq "1")
			{
				# we were able to submit successfully and we got a report embedded
				$self->{'scanhash'}->{$scankey}->{'key'} = $sha;
				$self->{'scanhash'}->{$scankey}->{'submitted'} = sprintf("%d", $decjson->{"scanid"} =~ /^[1234567890abcdef]+-(\d+)$/);
				$self->{'scanhash'}->{$scankey}->{'last_checked'} = sprintf("%d", $decjson->{"scanid"} =~ /^[1234567890abcdef]+-(\d+)$/);
				$self->{'scanhash'}->{$scankey}->{'infected'} = $decjson->{"positives"};
				$self->{'scanhash'}->{$scankey}->{'result'} = first { $_->{detected} } values %{ $decjson->{scans} };
				$self->{'valid_conn'} = 1;
			} elsif ($respcode eq "-2" or $respcode eq "0") {
				# we were able to submit successfully and we got a response indicating queued
				$self->{'scanhash'}->{$scankey}->{'key'} = $sha; 
				$self->{'scanhash'}->{$scankey}->{'submitted'} = time();
				$self->{'scanhash'}->{$scankey}->{'last_checked'} = 0;
				$self->{'scanhash'}->{$scankey}->{'infected'} = undef;
				$self->{'scanhash'}->{$scankey}->{'result'} = $decjson->{"verbose_msg"};
				$self->{'valid_conn'} = 1;
			} elsif ($respcode eq "-1") {
				warn("Transient Error occured, restarting...\n");
				warn("Got response code -1 (so restarting..)") if $self->debug();
				goto START;
			} else {
				warn("Got response code $respcode (" . $decjson->{"verbose_msg"} . ")") if $self->debug();
				$self->{'scanhash'}->{$scankey}->{'result'} = $decjson->{"verbose_msg"};
			}
		} else {
			warn("Unable to parse $scankey, VirusTotal responded with: $results");
		}
	} else {
		warn("Unable to parse $scankey, VirusTotal responded with: $results");
		warn("JSON decoder returned: $decjson [$@]");
	}
	return $respcode;
}

# Private method, will get the request from VirusTotal
sub _result
{
	#Code to retrieve a result from VirusTotal
	my $self = shift;
	warn("Entered _result()") if $self->debug();
	die ("You can't call this directly! Use the scan() method!") if (!ref $self);
	die ("You cannot call _result() before calling new() (and you shouldn't do it!") if (!ref $self->{'scanhash'});

	my $scankey = shift; # This is our internally generated scan key to be used to lookup the result key

	if (!defined $self->{'valid_conn'} && !$self->{'valid_conn'})
	{
		warn("Not connected to VirusTotal, please check your connection before calling _result()!");
		return undef;
	}

	if (!exists $self->{'scanhash'}->{$scankey} || !defined $self->{'scanhash'}->{$scankey}->{'key'})
	{
		warn("Attempted to retrieve a result for a key that doesn't exist!");
		return undef;
	}

	# Check to see if we checked in the last 5 minutes.  If we did return the same result.
	unless ($self->{'scanhash'}->{$scankey}->{'last_checked'} && $self->{'scanhash'}->{$scankey}->{'last_checked'} > (time() - 300))
	{
		# Code to retrieve the results that pertain to a submitted file by hash value
		# FIXME: Original code had neither content_type or content .. are they needed (probably not, but should we include) for readability?
RESTART:	warn("Sending filehash ($scankey)..") if $self->debug();
		my $response = $self->{'ua'}->post(
			$self->reportapi(),
			Content_Type => 'multipart/form-data',
			Content => [
				'apikey' => $self->apikey(),
				'resource' => $scankey
			]
		);
	
		if (!$response->is_success)
		{
			warn("Unable to post to '" . $self->reportapi() . "' error: " . $response->status_line . "\n");
			return (undef, undef);
		}
		my $results=$response->content;
		warn("Got response: $results") if $self->debug();
		
		# pulls the sha256 value out of the JSON response
		# Note: there are many other values that could also be pulled out
		my $json = JSON->new->allow_nonref;
		my ($decjson, $sha, $respcode) = (undef, undef, undef);
		eval {
			$decjson = $json->decode($results);
		};
		if (defined $decjson)
		{
			# if json->decode() fails it will call croak, so we catch it and display the returned text
			$sha = $decjson->{"sha256"};
			$respcode = $decjson->{"response_code"};
			if (defined $respcode)
			{
				if ($respcode eq "1")
				{
					# we were able to submit successfully so we can set valid_conn to true
					$self->{'scanhash'}->{$scankey}->{'key'} = $sha;
					$self->{'scanhash'}->{$scankey}->{'submitted'} = sprintf("%d", $decjson->{"scanid"} =~ /^[1234567890abcdef]+-(\d+)$/);
					$self->{'scanhash'}->{$scankey}->{'last_checked'} = sprintf("%d", $decjson->{"scanid"} =~ /^[1234567890abcdef]+-(\d+)$/);
					$self->{'scanhash'}->{$scankey}->{'infected'} = $decjson->{"positives"};
					$self->{'scanhash'}->{$scankey}->{'result'} = first { $_->{detected} } values %{ $decjson->{scans} };
					$self->{'valid_conn'} = 1;
					warn("Got response code $respcode") if $self->debug();
				} elsif ($respcode eq "-2" or $respcode eq "0") {
					# we were able to submit successfully and we got a response indicating queued
					$self->{'scanhash'}->{$scankey}->{'key'} = $sha; 
					$self->{'scanhash'}->{$scankey}->{'submitted'} = time();
					$self->{'scanhash'}->{$scankey}->{'last_checked'} = 0;
					$self->{'scanhash'}->{$scankey}->{'infected'} = undef;
					$self->{'scanhash'}->{$scankey}->{'result'} = $decjson->{"verbose_msg"};
					$self->{'valid_conn'} = 1;
					warn("Got response code $respcode") if $self->debug();
				} elsif ($respcode eq "-1") {
					warn("Transient Error occured, restarting...\n");
					warn("Got response code $respcode (transient error, restarting)") if $self->debug();
					goto RESTART;
				} else {
					warn("Got unknown response code $respcode") if $self->debug();
					$self->{'scanhash'}->{$scankey}->{'result'} = $decjson->{"verbose_msg"};
				}
			} else {
				warn("Unable to parse $scankey, VirusTotal responded with: $results");
			}
		} else {
			warn("Unable to parse $scankey, VirusTotal responded with: $results");
		}
	}
	return ($self->{'scanhash'}->{$scankey}->{'infected'}, $self->{'scanhash'}->{$scankey}->{'result'}->{'result'});
}

1;

__END__

=head1 NAME

VirusTotal - Interface for accessing the VirusTotal APIv2

=head1 SYNOPSIS

        use VirusTotal;

        my $VT=VirusTotal->new();

        $VT->apikey("YourAPIKeyHere");
        $VT->conn_cache(1);

        my ($infected, $description) = $VT->scan("/tmp/file.txt");

        if (!defined $infected)
        {
                my $error = (defined $description) ? $description : "Unknown error";
                die("An error occured: $error\n");
        } elsif ($infected) {
                print "Virus found: $description\n";
        } else {
                print "File didn't have any detected virus..\n";
        }

=head1 DESCRIPTION

This is a simple to use interface to the VirusTotal API (v2) for checking
viruses against multiple Anti-Virus databases.

=head1 METHODS

=head2 new ( [ debug => [0|1] ], [ allowlong => [0|1] ] )

Create a new VirusTotal object, with optional configuration options:

=over 4

=item debug

True or false to output debug data (default: 0)

=item allowlong

True or false to allow or disallow long filename support (default: 0)

When set to false L<VirusTotal> will assume any filename over 64 characters
long with no '/' char is actually file data.  When set to True this limit
is increased to 256 chars.

B<Note:> Any file name including '..' will automatically be treated as
filedata rather than as a filename to prevent many hack attempts.  Of course
/etc/passwd is not caught along with a whole host of other file-path
hacks, so becarful with your implementation!

=back

=head2 debug ( 0 | 1 )

Will turn off/on debug information (default: off)

=head2 conn_proxy ( $proxystring )

Sets the URL of a proxy server to use for requests.

=head2 apiagent ( $agentstring )

Sets the string to use as a User-Agent when connecting to the VirusTotal API

=head2 conn_cache ( 0 | 1 )

Will turn off/on use of L<LWP:ConnCache> (default: off)

=head2 allowlong ( 0 | 1 )

Will turn off/on whether to allow long (upto 256) characters before
assuming the bytes passed are actually a file to scan.

=head2 cache ( $handler )

Pass an external connection cache handler to LWP (normally you wouldn't use
this instead just setting conn_cache() to true.)

=head2 cache_check ( )

Will prune dead connections from the connection cache (if any)
will return true if conn_cache is not set.

=head2 cache_limit ( $limit )

Sets the maximum number of cached connections in the connection cache.

=head2 reportapi ( $report_API_URL )

Sets/Gets the report API URL (default: https://www.virustotal.com/vtapi/v2/file/report )

=head2 scanapi ( $scan_API_URL )

Sets/Gets the file subission API URL (default: https://www.virustotal.com/vtapi/v2/file/scan )

=head2 apikey ( $apikey )

Sets/Gets the API key to use when connecting to VirusTotal you B<MUST> set
this or the API will return an Error and the module will Croak.

=head2 timeout ( $timeout )

Sets/Gets the connection timeout in seconds (default: 30 seconds)

=head2 scan ( $file )

Invoke a connection to the API and will sent the file specified by $file, or
if the file does not appear to be a filename ( > 64 bytes )  will write it
to a temporary file and submit that.

B<NOTE:> This is not thread safe!  The tempfile created uses the process-id.

=head1 DEPENDENCIES

L<VirusTotal>, L<LWP::UserAgent>, L<JSON>, L<Digest::SHA>

=head1 AUTHOR

Michelle Sullivan (michelle@sorbs.net)

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2013 SORBS & Proofpoint Inc.

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License, version 2, or
(at your option) any later version.


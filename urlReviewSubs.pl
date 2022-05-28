1;

sub logToDebug {
	my ($msg) = @_;

	open(debugLog,">>$LogFile") or die ("Failed to open debug log: $!");

	print debugLog "-"x40 . "\n";
	my @stack = caller(0);
	printf debugLog "%s:%s\n", $stack[1], $stack[2];
	print debugLog "."x40 . "\n";

	printf debugLog "%s\n", $msg;
	printf debugLog "^"x40 . "\n";
	close(debugLog);
} # logToDebug

sub detectWordPress {
	my($host) = @_;
	print "detecting wordpress on $host\n";
	my @log=(q(detectWordPress()));
	my $url = "";
	my $ua = LWP::UserAgent->new(); # no reason to not follow redirect

	for my $proto (qw(https http)) {
		for my $dir (qw( . wp wordpress wordPress WordPress Wordpress wp-admin WP-Admin WP-ADMIN wp/wp-admin )) {
			for my $file (qw( . License.txt )) {
				$url = sprintf("%s://%s/%s/%s",$proto,$host,$dir,$file);
				print "Guess $url\n";
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
} # detectWordPress

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

sub netDNS_Lookup {
	my ($passedHost) =  @_;
	my @log = (qq(netDNS_Lookup($passedHost)));
	my $res   = Net::DNS::Resolver->new;
	my $reply = $res->search($passedHost, "A");
	my @response = ();
	 
	if ($reply) {
		foreach my $rr ($reply->answer) {
			if( $rr->can("address") ) {
				push @response, $rr->address;
				push @log, sprintf "Found IP: %s\n", $rr->address if $rr->can("address");
				if ( ! grep({ $rr->address  eq $_ } @artifacts) ) {
					push @artifacts, $rr->address ;
					push @log, sprintf "adding IP %s to artifacts\n", $rr->address;
				} # if not in artifacts
			} # if rr can address
		} # foreach
	} else {
		push @log, sprintf("query failed: %s\n", $res->errorstring);
	}
	logToDebug join("\n",@log);
	return @response;
} # Net::DNS Lookup

sub openURL {
	my ($passedURL) =  @_;
	my $uri = URI->new($passedURL);

	#printf "proto: %s\n", $uri->scheme;
	#printf "host: %s\n", $uri->host;
	#printf "path: %s\n", $uri->path;
	#printf "full: %s\n", $uri->as_string;
	# check for www.cira.ca.
	if($uri->host eq "www.cira.ca") {
		theJigIsUp ;
		return;
	}
	my @log = (qq(openURL($passedURL)));
	
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
	logToDebug join("\n",@log);
	@log=();

	if( $res->code == 200 ) {

		# Check the outcome of the response
		my $content = $res->content;
		push @log, sprintf "Page content:\n%s", $content;
		logToDebug join("\n",@log);
		@log=();

	} elsif( $res->code == 301 || $res->code == 302 ) {
		printf "301 redirect to %s\n", $res->header("Location");
		push @log, "301 redirect: Location: " . $res->header("Location");
		logToDebug join("\n",@log);
		push @artifacts, $res->header("Location");
		return;

	} else {
		push @log, "Unhandled status code";
		push @log, sprintf("%s", Dumper $res);
		logToDebug join("\n",@log);
		print Dumper $res;
		die "Unahndled status code: $res->code";
	}
} # openURL()


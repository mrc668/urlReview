1;

sub logToDebug {
	my ($msg) = @_;

	open(debugLog,">>$LogFile") or die ("Failed to open debug log: $!");
	#print debugLog "="x40 . "\n";
	#print debugLog "start log\n";
	#print debugLog "="x40 . "\n";

	print debugLog "-"x40 . "\n";
	my @stack = caller(0);
	print debugLog "-"x40 . "\n";
	#print Dumper \@stack;
	printf debugLog "%s:%s\n", $stack[1], $stack[2];

	printf debugLog "%s\n", $msg;
	printf debugLog "^"x40 . "\n";
	close(debugLog);
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

sub netDNS_Lookup {
	my ($passedHost) =  @_;
	my @log = (qq(netDNS_Lookup($passedHost)));
	use Net::DNS;
	my $res   = Net::DNS::Resolver->new;
	my $reply = $res->search($passedHost, "A");
	my @response = ();
	 
	if ($reply) {
		foreach my $rr ($reply->answer) {
			push @response, $rr->address if $rr->can("address");
			push @log, sprintf "Found IP: %s\n", $rr->address if $rr->can("address");
		}
	} else {
		push @log, sprintf("query failed: %s\n", $res->errorstring);
	}
	logToDebug join("\n",@log);
	return @response;
} # Net::DNS Lookup

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
	my @serverIPs = netDNS_Lookup($uri->host);
	push @log, sprintf("IP: %s", join(", ", @serverIPs));
	print "Server IPs: ",  join(", ", @serverIPs), "\n";


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

		wellKnown($uri->host);
		detectWordPress($uri->host);
		vt_api( $uri->as_string);
		foreach my $ip (@serverIPs) { vt_api( $ip,{'obj'=>'ip_addresses'} ); }
		#foreach my $ip (@serverIPs) { vt_api( $ip); }

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

sub vt_url2id {
} #url to id

sub vt_api {
	my($vtQuery,$opts) = @_;
	my @log = (qq(vt_api($vtQuery)));
	die("key not defined.")  if ! defined($vtAPIKey);
	die("key empty.") if $vtAPIKey eq "";
	push @log, sprintf "have vt API key, checking: %s", $vtQuery;
	#push @log, sprintf("%s", Dumper $opts) if defined( $opts);
	push @log, sprintf("www.virustotal.com: %s",$vtQuery);

	$opts->{'obj'} = q(urls) if ! defined $opts->{'obj'};
	# if it is url object, then get id.
	$vtQuery = vt_url2id($vtQuery) if $opts->{'obj'} eq q(urls);
	
	# what object do I have? Write query
	my $vtURI = sprintf("https://www.virustotal.com/api/v3/%s/%s", $opts->{'obj'}, $vtQuery);
	push @log, q(VT URI);
	push @log, $vtURI;

	# Create a user agent object
	my $ua = LWP::UserAgent->new();
	$ua->agent(q(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36));

	my $header = [
	 	'x-apikey' => $vtAPIKey
	];

	my $req = HTTP::Request->new( "GET", $vtURI, $header);

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);
	#push @log, q(Request to  VT);
	#push @log, sprintf("%s", Dumper $res);

	my $json = JSON->new->allow_nonref;
	my $vt_analysis = $json->decode( $res->content );
	logToDebug join("\n",@log);

	vt_report_ip($vt_analysis,$vtQuery) if$opts->{'obj'} eq 'ip_addresses';


} # vt_api

sub vt_report_ip {
	my($data, $vtQuery) = @_;
	print "\nVirusTotal Report for $vtQuery\n";
	print "-"x40, "\n";
	printf "RIR: %s\n", $data->{'data'}->{'attributes'}->{'regional_internet_registry'};
	printf "Security Vendors Reporting:\n";
	foreach (keys(%{ $data->{'data'}->{'attributes'}->{'last_analysis_stats'} })) {
		printf "%s: %s\n", $_, $data->{'data'}->{'attributes'}->{'last_analysis_stats'}->{$_};
	}

	my @log = (qq(vt_api($vtQuery)));
	push @log, "v"x40;
 	push @log, sprintf("%s", Dumper $data);
	push @log, "^"x40;
	logToDebug join("\n",@log);
} 


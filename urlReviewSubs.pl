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
				#print "Guess $url\n";
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
					print $content if length($content) < 3000;
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
		printf "Content length: %s\n", length($content) ;
		push @log, "Content length: " . length($content) ;
		push @log, sprintf "Page content:\n%s", $content;
		logToDebug join("\n",@log);
		@log=();

	} elsif( $res->code == 301 || $res->code == 302 ) {
		printf "301 redirect to %s\n", $res->header("Location");
		push @log, "301 redirect: Location: " . $res->header("Location");
		logToDebug join("\n",@log);
		push @artifacts, $res->header("Location");

	} else {
		printf "Unhandled status code: %s\n", $res->code;
		push @log, "Unhandled status code";
		push @log, sprintf("%s", Dumper $res);
	}

	logToDebug join("\n",@log);
	return($res->code == 200);
} # openURL()

sub check_misp {
	my($mispQuery,$opts) = @_;
	my @log = (qq(misp_api($mispQuery)));
	die("key not defined.")  if ! defined($mispAPIKey);
	die("key empty.") if $mispAPIKey eq "";
	push @log, sprintf "have misp API key, checking: %s", $mispQuery;
	#push @log, sprintf("%s", Dumper $opts) if defined( $opts);
	push @log, sprintf("tf.canssoc.ca: %s",$mispQuery);
	my $json = JSON->new->allow_nonref;
	push @log, sprintf(q(time stamp: enter subroutine: %s), time());

	my $header = [
	 	'Authorization' => $mispAPIKey,
		'Accept' => 'application/json',
		'Content-type' => 'application/json'
	];
	#print "header\n";
	#print Dumper $header;

	my $data = $json->encode({
		#"searchall" => $mispQuery, # event
		"value" => $mispQuery, # attribute
		"includeContext" => 0,
		"requested_attributes" => qw(event_id)
	});
	push @log, Dumper $data;
	#print "data\n";
	#print Dumper $data;
	#my $req = HTTP::Request->new( "POST", q(https://tf.canssoc.ca/attributes/restSearch), $header, $data);
	my $req = HTTP::Request->new( "POST", q(https://tf.canssoc.ca/events/restSearch), $header, $data);
	my $ua = LWP::UserAgent->new();

	push @log, sprintf(q(time stamp: make request: %s), time());
	my $res = $ua->request($req);
	push @log, sprintf(q(time stamp: return from request: %s), time());
	die( "no res content") if ! defined $res->content || $res->content eq "";
	#push @log, q(Response from  MISP);
	#push @log, sprintf("%s", Dumper $res);

	push @log, sprintf(q(time stamp: exit subroutine: %s), time());
	my $misp_analysis = $json->decode( $res->content );
	push @log, q(misp analysis decoded);
	push @log, Dumper $misp_analysis->{'response'}->[0]->{'Event'}->{'Attribute'}->[0]->{'event_id'};

	foreach my $e (@{$misp_analysis->{'response'}}) {
		if( $e->{'Event'}->{'Attribute'}->[0]->{'event_id'} =~ m/\d+/) {
			printf qq(https://tf.canssoc.ca/events/view/%s\n), $e->{'Event'}->{'Attribute'}->[0]->{'event_id'} ;
			push @log, sprintf qq(https://tf.canssoc.ca/events/view/%s\n), $e->{'Event'}->{'Attribute'}->[0]->{'event_id'} ;
		} # if event
	} #foreach result

	logToDebug join("\n",@log);
	return();
} # check_misp_url

sub callback {
	my($tag, %attr) = @_;
	#return if $tag ne 'img';  # we only look closer at <img ...>
	#push(@imgs, values %attr);
	print "tag $tag\n";
	print "opts\n", Dumper %attr;
} 

																		         
sub parsePage {
	my ($content) = @_;
	use HTML::LinkExtor;
	my $p =  HTML::LinkExtor->new(\&callback);
	$p->parse($content);
} # parse page



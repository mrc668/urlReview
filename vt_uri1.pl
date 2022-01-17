sub vt_api1 {
	my($vtQuery,$opts) = @_;
	my @log = (qq(vt_api($vtQuery)));
	die("key not defined.")  if ! defined($vtAPIKey);
	die("key empty.") if $vtAPIKey eq "";
	push @log, sprintf "have vt API key, checking: %s", $vtQuery;
	push @log, sprintf("%s", Dumper $opts) if defined( $opts);
	push @log, sprintf("www.virustotal.com: %s",$vtQuery);

	my $objectType = "urls";
	$objectType = $opts->{"obj"} if defined( $opts->{"obj"}) && $opts->{'obj'} eq q(ip_addresses);
	push @log, sprintf "object type: %s", $objectType;


	# Create a user agent object
	my $ua = LWP::UserAgent->new();
	$ua->agent(q(Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36));

	# Create a request
	#  curl --request POST --url "https://www.virustotal.com/api/v3/urls" --header "x-apikey: 983f75a3d73e933648e274a04242885b7e2d309223ac564814ed9fa20a5dd803" --form "url=www.supportme1800.com"

	my $header = [
	 	'x-apikey' => $vtAPIKey
	];

	my $data = sprintf(q(url=%s), $vtQuery );
	$data = sprintf(q(ip_addresses=%s), $vtQuery ) if defined( $opts->{"obj"}) && $opts->{'obj'} eq q(ip_addresses);
	my $req = HTTP::Request->new( "POST", sprintf(q(https://www.virustotal.com/api/v3/%s),$objectType), $header, $data);

	# Pass request to the user agent and get a response back
	my $res = $ua->request($req);
	push @log, q(Request to  VT);
	push @log, sprintf("%s", Dumper $res);

	# review result
	#printf "VT Status code: %s\n" , $res->code ;
	push @log, "VT Status code: " . $res->code ;

	if( $res->code == 200 ) {

		# Check the outcome of the response
		my $content = $res->content;
		my $json = JSON->new->allow_nonref;
		my $vt_analysis = $json->decode( $content );
		#print Dumper $vt_analysis;
		push @log, sprintf "VT Content:\n%s", $content;


		$req = HTTP::Request->new( "GET", sprintf(q(https://www.virustotal.com/api/v3/analyses/%s),$vt_analysis->{data}->{id}), $header );
		#print Dumper $req;
		push @log, q(Request to  VT);
		push @log, sprintf("%s", Dumper $res);

		# Pass request to the user agent and get a response back
		$res = $ua->request($req);
		#print Dumper $res;
		$content = $res->content;
		push @log, sprintf "VT Content:\n%s", $content;


		logToDebug join("\n",@log);
		print "$content\n";

	} else {
		print "Something went wrong in VT\n";
		push @log,  "Something went wrong in VT\n";
		push @log, sprintf("%s", Dumper $req);
		logToDebug join("\n",@log);
	}

} # vt_url


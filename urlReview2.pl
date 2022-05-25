#!/usr/bin/perl


my @artifacts;
push @artifacts, q(http://508ma.com/zc/cqwmall?user=patty.niebergall@uregina.ca);
# read from argv[0]


sub analyze_artifact {
	my ($art) = @_;

	analyze_url($art) if $art =~ m/^http/;
	analyze_ip($art) if $art =~ m/^[0-9\.]*$/;
	analyze_name($art) if $art !~ m/[:\/]/   and $art =~ m/[a-z]+/;
}

sub analyze_url {
	my ($art) = @_;

	print "Analyzing url: $art\n";
	my $newart = q(https://508ma.com/zc/cqwmall?user=patty.niebergall@uregina.ca);
	my $dom = q(508ma.com); # isolate host name
	my $ip = q(68.65.122.222); # ip of host

	push @artifacts, $dom unless grep({ $dom eq $_ } @artifacts);
	push @artifacts, $ip unless grep({ $ip eq $_ } @artifacts);
	push @artifacts, $newart unless grep({ $newart eq $_ } @artifacts);
	# check url against VT
	# check url against misp
	# check url against cyber gordon
	# is this the last redirection?
	# if yes:
	#   check for word press
	#   if yes - check for exposed admin interfaces: https://yourdomain.com/wp-admin https://yourdomain.com/wp-login.php
	#   check for joomla
	#   check for cpanel
	#   check for security contact
	#   compare output against browser variations
	#   check certificate chain on https - who signed it, is it valid, CN.
	# if no:
	#   add new location to artifacts
}

sub analyze_ip {
	my ($art) = @_;

	print "Analyzing ip: $art\n";
	# check ip against VT
	# check ip against misp
	# check ip against cyber gordon
}

sub analyze_name {
	my ($art) = @_;

	print "Analyzing name: $art\n";
	# check name against VT
	# check name against misp
	# check name against cyber gordon
	# check for http[s]://name/contact

}


my $i=0;
while ( $i <= $#artifacts ) {
	analyze_artifact( $artifacts[$i] );
	$i++;
}


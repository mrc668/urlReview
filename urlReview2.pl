#!/usr/bin/perl


my @artifacts;
push @artifacts, q(http://508ma.com/zc/cqwmall?user=patty.niebergall@uregina.ca);


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
	my $dom = q(508ma.com);
	my $ip = q(68.65.122.222);

	push @artifacts, $dom unless grep({ $dom eq $_ } @artifacts);
	push @artifacts, $ip unless grep({ $ip eq $_ } @artifacts);
	push @artifacts, $newart unless grep({ $newart eq $_ } @artifacts);
}

sub analyze_ip {
	my ($art) = @_;

	print "Analyzing ip: $art\n";
}

sub analyze_name {
	my ($art) = @_;

	print "Analyzing name: $art\n";
}


my $i=0;
while ( $i <= $#artifacts ) {
	analyze_artifact( $artifacts[$i] );
	$i++;
}


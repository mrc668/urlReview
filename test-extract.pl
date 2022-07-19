#!/usr/bin/perl

use URI;
use strict;
use warnings;
use LWP::Simple;
use LWP::UserAgent;
use HTTP::Status qw(:constants :is status_message);
use Data::Dumper;
use URI::Encode;
use JSON;

our $mispAPIKey=q();
our @artifacts;
push @INC, q(.);
require ".env";
	die("misp key empty.") if $mispAPIKey eq "";

require "urlReviewSubs.pl";

our $LogFile = q(test-misp.log);
my @expected = (
q(http://www.warmcoal.sa.com/offer.php?id=314&sid=973573&h=C6TrRGiRV-i8N2YgZAldsEKJbygoh9U2V-QVvLNOj4I/Hw_3bzRVE0sW3yuTx1-QBm4HgazINu8-pMmADcSqHTTU_    T2EyNQQq9hwwr8Zf9-mhuXAEo8OCcMNLYCcxRHx4Q)
);
push @artifacts, q(http://already.in/artifacts);

my $content=q(<html>
<head>
<title>Landing Page</title>
<script src="http://www.warmcoal.sa.com/jquery-1.11.0.min.js"></script>
<script>
window.location = "http://www.warmcoal.sa.com/offer.php?id=314&sid=973573&h=C6TrRGiRV-i8N2YgZAldsEKJbygoh9U2V-QVvLNOj4I/Hw_3bzRVE0sW3yuTx1-QBm4HgazINu8-pMmADcSqHTTU_T2EyNQQq9hwwr8Zf9-mhuXAEo8OCcMNLYCcxRHx4Q";
window.location = "http://already.in/artifacts"
</script>
</head>
<body>
<!-- Global site tag (gtag.js) - Google Analytics -->
<script async src="https://www.googletagmanager.com/gtag/js?id=UA-22484186-3"></script>
<script>
<script async src="https://"></script>
<script>
window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('js', new Date());

gtag('config', 'UA-22484186-3');
</script>
</body>
</html>);

print "Expected:\n" . join("\n", @expected) . "\n\n";
parsePage($content);
print "\nResults\n\n";
print join("\n",@artifacts), "\n";


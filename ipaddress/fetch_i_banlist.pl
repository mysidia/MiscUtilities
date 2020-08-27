#!/usr/bin/perl
#
# Create local banlist from url

# Copyright (C) 2008 Mysidia 


use LWP::UserAgent;
use NetAddr::IP qw(:aton);
use POSIX;
use IO::Socket;
use IO::Handle;
use Storable;
$ua = LWP::UserAgent->new;
$ua->agent("HB-BL-Fetcher/0.1 ");
$ua->protocols_allowed( ['https'] );
$ua->credentials( '', 'PAdmin', $ENV{BL_C_USERNAME}, $ENV{BL_C_PASSWORD});
$str = '';


my $req = HTTP::Request->new(POST => 'https://'.$ENV{BL_URLHOST}.'/admin/get_ip_bans.php');
$req->content_type('application/x-www-form-urlencoded');
$req->content('query=libwww-perl&mode=dist');

# Pass request to the user agent and get a response back
my $res = $ua->request($req);

# Check the outcome of the response
if ($res->is_success) {
    $str = 'ipban_' . strftime("%Y%d%m_%H%M_%s", gmtime);
    open(F, ">/var/bans/txt/" . $str . ".txt\n");
    print F ${$res->content_ref};
    close F;


    open(F, ">/var/bans/" . $str . ".bin\n")
       || die "Error fetching ip banlist to  /var/bans/${str}.bin";
    for $line ( split(/[ \n]+/, ${$res->content_ref}) ) {
         if ($line =~ /\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*/) {
              syswrite F, '\004', 1;
              syswrite F, inet_aton($1), 4;
         } elsif ( $line =~ /^\s*(\S+)\s*$/ ) {
              syswrite F, '\006', 1;
             $ipobj = new NetAddr::IP($1);
              syswrite F, $ipobj->aton(), 16;
         } else {
            print STDERR '? ' . $line . "\n";
         }
    }
    close F;
}
else {
    print STDERR $res->status_line, "\n";
}

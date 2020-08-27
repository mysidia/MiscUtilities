#!/usr/bin/perl
# C Mysidia 2015

use DBI;
use CGI qw/:standard/, q/param/;
use JSON::XS;

my $dbh = DBI->connect('DBI:mysql:dbname=raddb', 'raduser', '****');

my $kv = ();
#$utf8_encoded_json_text = encode_json $perl_hash_or_arrayref;

#$kv{'id'} = param('id');
$kv{'dbcustkey'} = param('dbcustkey');

if ($kv{'id'} eq 'new' || $kv{'dbcustkey'} eq 'new') { 
print header('text/plain');

$kv{'rv'} = [ { 'id' => 'new' }  ];
#print encode_json(\%kv) . "\n";

print q!{"rv":[[{"cpe_lan_ip":null,"mode":null,"dns_sec":null,"date":"0000-00-00","dsl_use":null,"pvc_2":null,"demarc_location":null,"pvc":null,"UserName":"","user_router":null,"password":null,"clli":null,"dslcircuit_id":null,"pair":null,"slpt":null,"cpe_gateway":null,"interface":null,"dns_primary":null,"cpe_wan":null,"down":null,"id":"new","hrs":null,"line":null,"name":null,"phone_number":null,"dist":null,"port":null,"service":"dsl","dsl_type":null,"bty":null,"rmt":null,"cpe_modem_rtr_location":null,"ppp_password":"XXXXXX","np":null,"status":"active","up":null,"user_wan_sn":null,"cpe_modem_rtr":null,"axm":null,"bt":null,"site_name":"---","ppp_name":null,"access":null,"noc_router":null,"cpe_wan_png":null,"account_name":null,"vlan":null,"dbcustkey":null,"serial_nr":null,"encap":null,"cpe_lan_sn":null,"notes":"---","grp":"DSI","user_wan_png":null,"user_wan_addr":null,"cpe_wan_sn":null,"dhcp":null,"dgn":null}]]
! . "}\n";
exit(0);
}

if (!$dbh){ 
  $kv{'result'} = 'error';
  $kv{'message'} = 'Unable to access database';
}
else {
#  my $q = $dbh->prepare(q|select * from _pinfo where ppp_name = ?|);
  my $q = $dbh->prepare(q|select * from _pinfo where dbcustkey = ?|);
  my $result;

  $kv{'id'} =~ s/[%_'"]/_/g;

  if ($q) {
     # if (!$kv{'id'} || $kv{'id'} eq '' || length($kv{'id'}) < 3) {
     #     $kv{'id'} =~ s/_/x/g;
          $q->execute($kv{'dbcustkey'});
     # } else { 
     #     $q->execute( '%' . $kv{'id'} . '%',  '%' . $kv{'id'} . '%' );
     # }

      $result = $q->fetchrow_hashref;
      $kv{'rv'} = [];

      while ($result) { 
          my %rv2 = ();

          for $h (keys %{$result}) {
               $rv2{$h} = $result->{$h};
          }

          if ($rv2{'ppp_password'} ne '' &&  length($rv2{'ppp_password'}) > 3 ){
          $rv2{'ppp_password'} = 'XXXXXX';
          }

          if ($rv2{'password'} ne ''   &&  length($rv2{'password'}) > 3 ) {
          $rv2{'password'} = 'XXXXXX';
          }

          $kv{'rv'} = [ @{ $kv{'rv'} },  [{%rv2}] ];
          %rv2 = ();

          $result = $q->fetchrow_hashref;
      }  

  } else {
  $kv{'result'} = 'error';
  $kv{'message'} = 'Unable to prep query for database';
  }
}

print header('text/plain');
print encode_json(\%kv) . "\n";


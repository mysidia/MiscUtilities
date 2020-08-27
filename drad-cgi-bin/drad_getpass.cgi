#!/usr/bin/perl
# C Mysidia 2010

use DBI;
use CGI qw/:standard/, q/param/;
use JSON::XS;

my $dbh = DBI->connect('DBI:mysql:dbname=raddb', 'raduser', '*******');

my $kv = ();
#$utf8_encoded_json_text = encode_json $perl_hash_or_arrayref;

$kv{'id'} = param('dbcustkey');
if (!$dbh){ 
  $kv{'result'} = 'error';
  $kv{'message'} = 'Unable to access database';
}
else {
  my $q = $dbh->prepare(q|select id,dbcustkey,ppp_name,account_name,site_name,ppp_password from _pinfo where dbcustkey = ?|);
  my $result;

  $kv{'id'} =~ s/[%_'"]/_/g;

  if ($q) {
     # if (!$kv{'id'} || $kv{'id'} eq '' || length($kv{'id'}) < 3) {
     #     $kv{'id'} =~ s/_/x/g;
          $q->execute($kv{'id'});
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


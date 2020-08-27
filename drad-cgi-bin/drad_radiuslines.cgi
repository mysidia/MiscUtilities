#!/usr/bin/perl

use DBI;
use CGI qw/:standard/, q/param/;
use JSON::XS;

my $dbh = DBI->connect('DBI:mysql:dbname=raddb', 'raduser', '*****');
my $out = "";

my $kv = ();
#$utf8_encoded_json_text = encode_json $perl_hash_or_arrayref;

sub radiusQuote {
         my $x =shift;

         $x =~ s/([\\'"])/\\$1/g;
         return '"' . $x . '"';
}


sub BaseAddress {
        my $ip = shift;
        my $mask = shift;
        my @ip;                                                         # Array for broken up IP
        my @mask;                                                       # Array for broken up mask
        my $i;                                                          # Loop counter
        my $base;                                                       # Base address


        # Break up each dotted quad into it's 4 numbers.
        if ( ($ip !~ /\./) or ($mask !~ /\./) ) {
                return '';
        }
        @ip = split(/\./, $ip);                         # Break up the IP
        @mask = split(/\./, $mask);                     # Break up the mask
        if ( (@ip != 4) or (@mask != 4) ) {
                return '';
        }

        # Handle each of the 4 numbers.
        foreach $i (0 .. 3) {
                if ( ($ip[$i] < 0) or ($ip[$i] > 255)
                                or ($mask[$i] < 0) or ($mask[$i] > 255) ) {
                        return '';
                }
                $base .= ( scalar($ip[$i]) & scalar($mask[$i]) ) . '.';
        }
        chop $base;

        return $base;
}


sub getnetmask {
   my $bits = shift;
my %sn_to_mask = (0 => '0.0.0.0',
                 1 => '128.0.0.0',
                 2 => '192.0.0.0',
                 3 => '224.0.0.0',
                 4 => '240.0.0.0',
                 5 => '248.0.0.0',
                 6 => '252.0.0.0',
                 7 => '254.0.0.0',
                 8 => '255.0.0.0',
                 9 => '255.128.0.0',
                10 => '255.192.0.0',
                11 => '255.224.0.0',
                12 => '255.240.0.0',
                13 => '255.248.0.0',
                14 => '255.252.0.0',
                15 => '255.254.0.0',
                16 => '255.255.0.0',
                17 => '255.255.128.0',
                18 => '255.255.192.0',
                19 => '255.255.224.0',
                20 => '255.255.240.0',
                21 => '255.255.248.0',
                22 => '255.255.252.0',
                23 => '255.255.254.0',
                24 => '255.255.255.0',
                25 => '255.255.255.128',
                26 => '255.255.255.192',
                27 => '255.255.255.224',
                28 => '255.255.255.240',
                29 => '255.255.255.248',
                30 => '255.255.255.252',
                31 => '255.255.255.254',
                32 => '255.255.255.255');

 return $sn_to_mask{$bits} || 32;
}


#$kv{'id'} = param('id');
$kv{'dbcustkey'} = param('dbcustkey');
$kv{'ppp_name'} = param('ppp_name');
$kv{'hidepw'} = param('hidepw') || 0;


if ($kv{'id'} eq 'new' || $kv{'dbcustkey'} eq 'new') { 
print header('text/plain');

$kv{'rv'} = [ { 'id' => 'new' }  ];
#print encode_json(\%kv) . "\n";
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
          my %r;
          my $wan_ip = "";
          my $wan_sn;

          for $h (keys %{$result}) {
               $rv2{$h} = $result->{$h};
          }

          $result = $q->fetchrow_hashref;
          %r = %rv2;

          if ($r{grp} eq 'XXXX') { 
              if (  $r{dsl_type}  eq 'stnd'  ) {
                  next;
              }
          }
          if ($r{service} eq 'dsl' && ( lc($r{encap}) !~ /^pppo[ae]$/ || $r{ppp_name} eq '???')) {
              next;
          }
          if ($r{service} eq 'dsl' && lc($r{dsl_type}) !~ /^(stnd)|(cust)|(~~~)$/i &&  $r{dsl_type} && $r{dsl_type} ne '') {
              next;
          }

#print STDERR "{}" . $r{status} . "{}\n";
          if ( $r{status} =~ /^inactive$/i || $r{status} =~ /^suspended$/i ) {
              next;
          }


          if ( ( ( $r{ppp_name} eq '???') and ($r{status} =~ m/^(new|inactive)$/i) ) 
                 or ($r{ppp_name} eq '~~~') ) {
              next;
          }

          $wan_ip = $r{cpe_wan};
          $wan_sn = $r{cpe_wan_sn};


          if ($r{'status'} eq 'password') {
                $out .=   sprintf(qq[%s          Auth-Type := Accept \n],       radiusQuote( $r{'ppp_name'} ));
          } else {
             if (!$kv{'hidepw'}) {
                $out .=   sprintf(qq[%s          Cleartext-Password := %s \n],  radiusQuote( $r{'ppp_name'} ),  radiusQuote( $r{'ppp_password'} ));
             } else {
                $out .=   sprintf(qq[%s          Cleartext-Password := %s \n],  radiusQuote( $r{'ppp_name'} ),  '**PASSWORDS HIDDEN***');
             }
          }

          $out .= sprintf(qq[\tService-Type = Framed-User,\n]) ;
          $out .= sprintf(qq[\tFramed-Protocol = PPP,\n]) ;
          if ($r{'service'} eq 'dial' || $r{'service'} eq 'dialup') {
              $out .= sprintf(qq[\tFramed-MTU = 1500,\n]) ;
          }
          $out .= sprintf(qq[\tFramed-Routing = None,\n]) ;

          if ($wan_ip eq '???' && lc($r{status}) eq 'new'  ) {
              $wan_ip = '127.0.0.1';
          }
          if (  $r{status} =~ m/^(Cancel|Inactive|Suspend)$/i ) {
              $wan_ip = '127.0.0.1';
          }

          if ($wan_ip eq '~~~' && $r{service} eq 'dialup') {
              $wan_ip =  '255.255.255.254';
          }

          if ($wan_ip eq '???') {
              next;
          }

          if ($wan_ip eq '127.0.0.1') {
              $wan_sn = 32;
          }

          $out .= sprintf(qq[\tFramed-IP-Address = %s,\n], ($wan_ip)) ;

          $out .= sprintf(qq[\tFramed-IP-Netmask = %s,\n], ( getnetmask($wan_sn) )) ;


          if (  ($r{status} ne 'inactive' && $r{status} ne 'suspended') &&  ($r{service} ne 'dialup')  &&   ($r{mode} eq 'rte') && ($r{'cpe_wan_ip'} ne '127.0.0.1') && length($r{'cpe_lan_ip'}) > 3  ) {

              my $cpe_lan_ip = $r{'cpe_lan_ip'};
              my $cpe_lan_netid = BaseAddress($cpe_lan_ip,  getnetmask($r{cpe_lan_sn}) );

              #$out .= sprintf(qq[\tFramed-Route = %s %s %s,\n],  $cpe_lan_netid, getnetmask($r{cpe_lan_sn}),  $wan_ip  ) ;
              $out .= sprintf(qq[\tFramed-Route = %s,\n], radiusQuote(sprintf("%s %s %s", $cpe_lan_netid, getnetmask($r{cpe_lan_sn}),  $wan_ip))  ) ;
          }
          $out .= sprintf(qq[\tFall-Through = No\n]) ;

                # Not needed now (0 = continuous):  Session-Timeout = 21600,
                # Not needed now (0 = continuous):  Idle-Timeout = 900

      }  

  } else {
  $kv{'result'} = 'error';
  $kv{'message'} = 'Unable to prep query for database';
  }
}

print header('text/plain');
print "#HTTP POST to https://%BASE/cgi-bin/drad_radiuslines.cgi\n #DATA:" . encode_json(\%kv) . "\n#ANSWER: \n";
print $out;


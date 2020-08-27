#!/usr/bin/perl

use DBI;
use CGI qw/:standard/, q/param/;
use JSON::XS;
use Net::CIDR;

my %approved_netmask = (
'1.2.3.4' => { ppp_name => 'example@example.com', sn => 32 }
);

my %approved_routes = ( 
 '192.168.0.0' => { ppp_name => 'test2@example.com', sn => 24}

);



my $dbh = DBI->connect('DBI:mysql:dbname=raddb', 'raduser', '********',  {AutoCommit => False});

my $kv = ();
$sdata = param('savedata');

$sv = decode_json $sdata;
#$sv = {};
#$sv->{'service'}='dsl';
my %sv2 = ();

#$utf8_encoded_json_text = encode_json $perl_hash_or_arrayref;

$kv{'id'} = param('id');
$kv{'action'} = param('action');
$kv{'dbcustkey'} = param('dbcustkey');
$kv{'orig_ppp_name'} = param('orig_ppp_name');

if (!$dbh){ 
  $kv{'result'} = 'error';
  $kv{'message'} = 'Unable to access database';
}
else {
  my $q;
  my $result;

  $kv{'id'} =~ s/[%_'"]/_/g;

  $kv{'result'} = 'error';
  $kv{'message'} = 'SORRY: Function Not Implemented: ' .  $sdata;


  my @dslFields = ( 'dbcustkey', 'service', 'account_name', 'site_name', 'grp', 'status', 'date', 'dsl_type', 'down', 'up', 'noc_router', 'interface', 'encap', 'ppp_name', 'ppp_password', 'cpe_gateway',
                                       'cpe_wan', 'cpe_wan_sn', 'cpe_wan_png', 'dns_primary', 'dns_sec', 'pvc', 'vlan', 'clli', 'rmt', 'slpt', 'axm', 'np',
                                        'pvc_2', 'bty', 'pair', 'line', 'dgn', 'phone_number', 'dslcircuit_id', 'dsl_use', 'dist', 'bt', 'demarc_location', 'access', 'cpe_modem_rtr_location', 'cpe_modem_rtr',
                                        'serial_nr', 'port', 'name', 'password', 'mode', 'cpe_lan_ip', 'cpe_lan_sn', 'dhcp', 'user_wan_addr', 'user_wan_sn', 'user_wan_png', 'user_router', 'notes' );

  my @dialFields = ( 'dbcustkey', 'service', 'account_name', 'site_name', 'grp', 'status', 'date', 'hrs', 'ppp_name', 'ppp_password', 'cpe_wan', 'cpe_wan_png', 'notes' );


  for(@dslFields){ 
       $sv2{$_} = undef;
  }

  for(@dialFields) {
       $sv2{$_} = undef;
  }


  if ($sv->{'service'} eq 'dsl') {
      @ffset =  @dslFields ;
  } elsif ($sv->{'service'} eq 'dialup') {
      @ffset = @dialFields;
  } else {
      @ffset = ();
  }

  for (@ffset) { 
         $sv2{$_} =  $sv->{$_};
  }


  ###
     my @alwaysRequired = ('ppp_name', 'ppp_password',  'service', 'grp', 'status', 'cpe_wan', 'cpe_wan_sn');
     my @dslRequired = ( 'encap', 'dsl_type' );
     my $fail = 0;

     if ($sv2{'service'} eq 'dialup' && $sv2{'cpe_wan_sn'} eq '') {
         $sv2{'cpe_wan_sn'} = 32;
    }

     for(@alwaysRequired) {
           if ($sv2{$_} eq '' || !defined($sv2{$_}) || !exists($sv2{$_})) { 
                 $kv{'result'} = 'Failure';
                 $kv{'message'} = 'Missing Required Field: ' . $_;
                 $fail = 1;

                 print header('text/plain');
                 print encode_json(\%kv) . "\n";
                 exit(0);
           }
     }

     if ($sv2{'service'} eq 'dsl') {


        for(@dslRequired) {
           if ($sv2{$_} eq '' || !defined($sv2{$_}) || !exists($sv2{$_})) {
                 $kv{'result'} = 'Failure';
                 $kv{'message'} = 'Missing Required Field: ' . $_;
                 $fail = 1;
           
                 print header('text/plain');
                 print encode_json(\%kv) . "\n";
                 exit(0);
           }
        }

     }


   if ( ( $sv2{'cpe_wan_sn'} =~ /^[-]?\d+/ )  && int($sv2{'cpe_wan_sn'}) < 32  ) {
           $apr = $approved_netmasks{ $sv2{'cpe_wan'} };

           if (!$apr || $apr->{'sn'} != $sv2{'cpe_wan_sn'}) {
                $kv{'result'} = 'Failure';
                $kv{'message'} = 'Validation on entry of a Non /32 Netmask.  WAN IP Does not appear in an validated networks list.';

                 print header('text/plain');
                 print encode_json(\%kv) . "\n";
                 exit(0);
           }
 
           if (  $apr->{'ppp_name'} && $apr->{'ppp_name'} != '---' && $apr->{'ppp_name'} != $sv2{'ppp_name'}   ) {
                $kv{'result'} = 'Failure';
                $kv{'message'} = 'Non /32 CPE WAN range is already pre-assigned to ' . $apr->{'ppp_name'};


                 print header('text/plain');
                 print encode_json(\%kv) . "\n";
                 exit(0);
           }

   } elsif ( $sv2{'cpe_wan_sn'} ne '32' ) {
        $sv2{'cpe_wan_sn'} = '';
   }


    if (lc($sv2{'mode'}) eq 'rte') {
            my $apr = $approved_routes{  $sv2{'cpe_lan_ip'}  };

           if (!$apr || $apr->{'sn'} != $sv2{'cpe_lan_sn'}) {
                $kv{'result'} = 'Failure';
                $kv{'message'} = 'Extra prefix to be routed to user is not currently in the valid routes list.';
                print header('text/plain');
                print encode_json(\%kv) . "\n";
                exit(0);
           }

           if ($apr->{'ppp_name'} != $sv2{'ppp_name'}) {
                $kv{'result'} = 'Failure';
                $kv{'message'} = 'The route is for ' . $apr->{'ppp_name'};
                print header('text/plain');
                print encode_json(\%kv) . "\n";
                exit(0);
           }

    }



  ###

  my $updateQuery = 'UPDATE _pinfo SET ';
  my $insertQuery = 'INSERT INTO _pinfo ';
  my $insertSet1 = ''; 
  my $insertSet2 = '';
  my $first = 1;
  my @dataList = ();
  my $y = 0;

  for(@ffset){ 
           next if ($_ eq 'id' || $_ eq 'dbcustkey');

           if ($_ =~ /_password$/ || $_ eq 'password') {
                next if ($sv2{$_} eq 'XXXXXX' || $sv2{$_} =~ /^XXX+/);
           }

           if ($first == 0) {
                $updateQuery .= ", ";
                $insertSet1 .= ', ';
                $insertSet2 .= ', ';
           }
           $updateQuery .= (" " . $_ . " =  ?" );

           $insertSet1 .= $_;
           $insertSet2 .= ' ? ';

           if ($_ eq 'ppp_name' && $sv2{'ppp_name'} !~ /\@/) {
 
                if ( $kv{'action'} eq 'new' || $kv{'orig_ppp_name'} =~ /\@/) {
                     $kv{'result'} = 'Failure';
                     $kv{'message'} = "Data field " . $sv2{$_} . "  username is missing the @ sign.\n";
                     print header('text/plain');
                     print encode_json(\%kv) . "\n";
                     exit(0);
                }
           }

           if ($sv2{'ppp_name'} =~ /\@/) { 

               if ($sv2{'ppp_name'} !~ /^[a-zA-Z0-9].+\@[a-zA-Z0-9]+/) {
                   $kv{'result'} = 'Failure';
                    $kv{'message'} = 'PPP Username should be of the form user@example.com';
                     print header('text/plain');
                     print encode_json(\%kv) . "\n";
                     exit(0);
               }
           }


           if ($_ eq 'ppp_name' || $_ eq 'cpe_wan' || $_ eq 'cpe_wan_sn' || $_ eq 'cpe_lan_sn') {
                 if ($sv2{$_} =~ /[`%<>\[\]#^\/:\(\)\"\'\$]/) {
                    $kv{'result'} = 'Failure';
                    $kv{'message'} = "Data field " . $sv2{$_} . "  contains invalid characters.\n";
                    print header('text/plain');
                    print encode_json(\%kv) . "\n";
                    exit(0);
                 }
           }

           if (($_ eq 'cpe_wan' || $_ eq 'cpe_lan_ip') && $s2v{$_} ne '' && $sv2{$_} ne '~~~' && $sv2{$_} ne '???') {
               my $ip1 = Net::CIDR::cidrvalidate($sv2{$_});

               if (!defined($ip1)) {
                    $kv{'result'} = 'Failure';
                    $kv{'message'} = "Data field " . $sv2{$_} . "  not a valid IP address.\n";
                    print header('text/plain');
                    print encode_json(\%kv) . "\n";
                    exit(0);
               }
           }


           if ($sv2{$_} && $sv2{$_} ne '' && $sv2{$_} !~ /^[ '%a-zA-Z0-9+"`|~<>\$\[\]#^\/:\(\)!=*.\@_?,&\t-]+$/) { 
              $kv{'result'} = 'Failure';
              $kv{'message'} = "Data field " . $sv2{$_} . "  contains invalid characters.\n";

              print header('text/plain');
              print encode_json(\%kv) . "\n";
              exit(0);
           }
           

           $dataList[$y++] = $sv2{$_};
           $first = 0;
  }

  if ($kv{'action'} ne 'new')
 {
      $updateQuery .= " WHERE id=" . $dbh->quote( $kv{'id'} ) . "  AND dbcustkey=" .  $dbh->quote( $kv{'dbcustkey'} );
  } else {
       $insertQuery = 'INSERT INTO _pinfo (' . $insertSet1 . ') VALUES (' . $insertSet2 . ')';
  }

  #$q = $dbh->prepare(q|select * from _pinfo where ppp_name = ?|);

  if ($kv{'action'} ne 'new') {
      $q = $dbh->prepare($updateQuery); 
  } else {
      $q = $dbh->prepare($insertQuery); 

      print STDERR "KV: ${insertQuery}\n";
  }

  $kv{'message'} = $updateQuery;

  if ($q) {
      $dbh->begin_work;
      my $answer;

      $answer = $q->execute(@dataList); 

      if ( $answer && $dbh->commit() ) {
          $kv{'result'} = 'Success';
          $kv{'message'} = 'Changes have been committed to database';

          system("/bin/touch /tmp/rad_changed");
          #system("(set -o noclobber ; echo >/tmp/rad_changed )");
      } else { 
          $kv{'result'} = 'Failure';
          $kv{'message'} = 'Changes were not successfully saved:' . $dbh->errstr;
      }

  } else {
  $kv{'result'} = 'error';
  $kv{'message'} = 'Unable to prep query for database';
  }
}

print header('text/plain');
print encode_json(\%kv) . "\n";


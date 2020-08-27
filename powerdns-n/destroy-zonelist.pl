#!/usr/bin/perl
# C Mysidia, 2010
#
# This script will remove DNS zones whose names are listed in the given text file.
#
use DBI;
use YAML;
use POSIX;
use Text::CSV_XS;
my ($csv, $dbq_getdomain, $dbq_zonerecords_withtype, $y, $dbh) = Text::CSV_XS->new;
my ($dbu_delete_zonerecords_any, $dbu_add_zonerecord, $dbu_update_soa, $soa_content, $soa_id, $soa_newcontent);

if ($#ARGV <0  || $ARGV[0] !~ /^(?:[_a-zA-Z0-9]+\.)?[_a-zA-Z0-9]+$/) {
  die "Usage: $0 <filename>\n";
}

open my $csvfile, "<:encoding(ascii)", $ARGV[0] or die "Unable to open csvfile: $!\n";

$y = YAML::LoadFile('/usr/local/etc/pdnscreds.yaml');
# cat >>/usr/local/etc/pdscreds.yaml <<END
# user: exaxmple
# pass: example
# END

$dbh = DBI->connect('DBI:mysql:dbname=pdns', $y->{'user'}, $y->{'pass'},  {AutoCommit => false});

unless ($dbh) {
  die 'Error: ' . $DBI::errstr;
}

###
$dbq_getdomain = $dbh->prepare(q|SELECT * from domains where name = ? FOR UPDATE|);
$dbq_zonerecords_withtype = $dbh->prepare(q|SELECT * from records where domain_id = ? and name = ?  and type = ? FOR UPDATE|);
$dbq_getrecords = $dbh->prepare(q|SELECT * from records WHERE domain_id = ? and name = ? FOR UPDATE|);
$dbu_delete_zonerecords_any = $dbh->prepare(q|DELETE FROM records where domain_id = ? and name like ?|);

$dbi_history = $dbh->prepare(q|INSERT INTO za_history (`when`,user,action,object,data) VALUES (NOW(),?,?,?,?)|);
$dbq_rmdomain = $dbh->prepare(q|DELETE FROM domains where name=? AND id=?|);


###

while (my $csvrow = $csv->getline ($csvfile)) {
     my $target_domain = $csvrow->[0];
     my $target_domainid = 0;

     $dbh->begin_work() 
         || die "Unable to open database transaction block";

          print "Q: (SELECT * from domains where name = ?  FOR UPDATE)   Parameters: (" . $dbh->quote($target_domain) .  " )\n";
          $dbq_getdomain->execute ( $target_domain ) 
                 || die "Could not execute required SQL query: " . $dbh->errstr;

          $domain_found = 0;
          if(my $sqlrow = $dbq_getdomain->fetchrow_hashref) {
               $domain_found = 1;
               $target_domainid = $sqlrow->{'id'};

               print "[Found Result, target_domain=" . $target_domain . ",  target_domainid=$target_domainid ]\n\n";
               $dbq_getdomain->finish;
          }

          if ($domain_found == 0) {
              print "SKIP: Domain ${target_domain} could not be found in the database.\n";
              $dbh->rollback;
              next;
          }


          print "Q: (SELECT * from records where domain_id = ? and name = ?" . 
                  "  and type = ? FOR UPDATE)  Parameters: (${target_domainid}," . $dbh->quote($target_domain) . ",'SOA')\n";

          unless ( $dbq_zonerecords_withtype->execute( $target_domainid, $target_domain, 'SOA'  ) ) {
              die "Could not execute query to get SOA record for ${target_domain}:" . $dbh->errstr . "\n";
          }
          
          if (my $sqlrow =  $dbq_zonerecords_withtype->fetchrow_hashref) {
              $soa_content = $sqlrow->{'content'};
              $soa_id = $sqlrow->{'id'};
              $dbq_zonerecords_withtype->finish;
              $soa_newcontent = $soa_content;

              if ($soa_content =~ /^\s*(\S+\s+\S+)\s+(\d++)\s+(\d+\s+\d+\s+\d+\s+\d+)\s*/) {
                  $soa_newcontent = $1 . " " . ( int($2)+1 ) . " " . $3;
              }

              print "[Found: SOA for ${target_domainid} from  [${soa_content}]  TO  [${soa_newcontent}]]\n";
              #$dbu_replace_soa->execute( $soa_newcontent,  $soa_id, $target_domainid, $target_domain );
          } else {
              print "SKIP: Domain ${target_domain}:  NO SOA RECORD FOUND!\n";
              $dbh->rollback;
              next;
          }

          print "\n\nPre-Requisites Passed.  This zone can be acted upon.\n\n";

          print "The following zone is about to be deleted:\n";

          # $dbq_getrecords = $dbh->prepare(q|SELECT * from records WHERE domain_id = ? and name = ? FOR UPDATE|);
          #print "q:(SELECT * from records WHERE domain_id = ? and name = ? FOR UPDATE) Parameters: (${target_domainid},$dbh->quote($target_domain))\n";
          if ( $dbq_getrecords->execute($target_domainid, $target_domain) ) { 
                     printf "RId=%10s,  DId=%10s   %15s %5s %-7s (p=%3s) %s  %s  %s   %s\n",
                            'RecordNum', 'DomainNum', 'Name', 'TTL', 'TYPE', 'PRIORITY', 'CONTENT', 'CHANGE_DATE', 'ORDERNAME', 'AUTH';

                 while(my $sqlrow = $dbq_getrecords->fetchrow_hashref) {
                     printf "RId=%10d,  DId=%10d   %15s %5d %-7s (p=%3d) %s  %s  %s   %s\n",
                        $sqlrow->{'id'},  $sqlrow->{'domain_id'}, $sqlrow->{'name'}, $sqlrow->{'ttl'}, 
                        $sqlrow->{'type'},  $sqlrow->{'prio'},
                        $dbh->quote($sqlrow->{'content'}),
                        $sqlrow->{'change_date'}, $sqlrow->{'ordername'},
                        $sqlrow->{'auth'}
                          ;
                 }
          }


          print "\n";
          print "U: (DELETE FROM records where domain_id = ? and name like ?)  Parameters: (${target_domainid}," . $dbh->quote('%' . $target_domain) . ")\n";
          unless ( $uu = $dbu_delete_zonerecords_any->execute( $target_domainid, '%' . $target_domain ) ) {
                 print "ACTION FAILED; SKIP ${target_domain}\n";
                 $dbh->rollback;
                 next;
          }

          print "U: (DELETE FROM domains where name=? AND id=?) Parameters: (" . $dbh->quote($target_domain) . ", ${target_domainid})\n";
          unless ( $dbq_rmdomain && ( $uu = $dbq_rmdomain->execute( $target_domain, $target_domainid )) ) {
                 print "ACTION FAILED; SKIP ${target_domain}\n";
                 $dbh->rollback;
                 next;
          }

          if ($uu != 1) {
               print "Error: Deleted more than one record\n";
                $dbh->rollback;
               next;
          }

          print "I: (INSERT INTO za_history (`when`,user,action,object,data) VALUES (?,?,?,?) )\n" 
               . "Parameters: (NOW(),'console', 'PURGE ZONE'," . $dbh->quote($target_domain) . "),"
                     . q[s:0:"";] . ",?)\n";

          unless ( $dbi_history && $dbi_history->execute('console', 'PURGE ZONE', $target_domain, q[s:0:"";]) ) {
                 print "ACTION FAILED; SKIP ${target_domain}\n";
                 $dbh->rollback;
                 next;
          }

      print "${target_domain} TRANSACTION BLOCK READY\n\n";



      if ( $dbh->commit() ) {
          print ";; ${target_domain} COMMIT SUCCESS\n";
          print "++ ${target_domain} DONE\n";
      } else {
          print ";; ${target_domain} COMMIT FAILED\n";
      }

      #$dbh->rollback()
      #    || die "Unable to cancel transaction.\n";


}





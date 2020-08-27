#!/usr/bin/perl
# C Mysidia 2007

use DBI;
use strict;
use POSIX;
use Date::Calc qw(Today_and_Now);
#use Date::Parse;
#use Date::Format;
use Danga::Socket;
use ParaDNS;
use CGI;

my $DB_USER = 'perror';
my $DB_PASS = '**********';

open(H, ">>/home/errorparse/errorparse.cmdbuf");

sub hashitems {
   my $hash = shift;
   my @items = @_;
   my @result = ();

   for(@items) {
        push @result, $hash->{$_};
   }
   @result;
}

#my $dbh = DBI->connect("DBI:mysql:dbname=perror", $DB_USER, $DB_PASS, { AutoCommit => 1})
# || die "Unable to connect to database";
my $curtime = time();
my $xtime = time();
my $row = undef;
my %data = ();
if ( $xtime % 300 > 0 ) {
     $xtime -= ($xtime % 300);
}

#my $q_allcounts = $dbh->prepare(q|SELECT * from msgcounts LEFT JOIN mhosts ON (msgcounts.server=mhosts.servername) WHERE first_time >= ? ORDER BY server |);
#my $q_recent = $dbh->prepare(q|SELECT * from msgcounts WHERE first_time >= ? AND server = ? |);
#my $q_cupdate = $dbh->prepare(q|UPDATE msgcounts SET first_time=?, last_time=?, count=?, server=?, select1=?, select2=?, loggerupdate=?, xmls=?, misc=? WHERE id=?|);
#my $q_cinsert = $dbh->prepare(q|INSERT INTO msgcounts (first_time, last_time, count, server, select1, select2, loggerupdate, xmls, misc) VALUES(?,?,?,?,?,?,?,?,?)|);
my $server_name = 'UNKNOWN';
my $from_address = $ENV{SENDER};
my $record_host = 'UNKNOWN';
my $hostid = 0;
my %hostdata;
my $msgtype = 'UNKNOWN';

#my $q_host_getlist = $dbh->prepare(q|SELECT * from mhosts|);


if ( $ENV{EXT2} =~ /^(\S+)/ ) {
     $record_host = $1;
     $record_host =~ s/_/./g;     
}
elsif ( $from_address =~ /[^@]+\@(\S+)/ ) {
     $record_host = $1;
}

###########

open F,">>/home/errorparse/errorparse.out";
print F "\n";
print F "X-From-Addr: " . $from_address . "\n";
print F "X-Ext2: " .$ENV{EXT2} . " :: ${record_host}\n";
print F "X-Info: " . $_ . " " . $data{$_} . "\n"  for (qw(first_time last_time count server));
while($_ = <STDIN>)
{
  if ($msgtype eq 'UNKNOWN')
  {
#    Function: xml_socketopen(), line 2105
# Description: Failed to open socket: Connection timed out110

      if ( /^\s*Function: xml_socketopen/ ) {
          $msgtype = 'xmls';

          print F " **XMLS\n";
      }
      elsif ( /^\s*Description: Unable to connect.* 10\.1\./ ) {
             print F " **SELECT1\n";
             $msgtype = 'select1';


      }
      elsif ( /^Unable to connect.* 192\.168\.$/ ) {
            $msgtype = 's2';
      }
      elsif ( /^\s*Description: CREATE/ ||  /^\s*Description: UPDATE/ ||  /^\s*Description: INSERT/ ) {
             print F " **LU\n";
             $msgtype = 'update_db_lo';
      }
      elsif (  /select(\d)/ ) {
            print F " **SELECT${1}\n";
            $msgtype = 'select' . $1;
      }
      elsif ( /loggerupdate/ ) {
            print F " **update_db_lo\n";
            $msgtype = 'loggerupdate';
      }
  }
  print F $_;
}
close F;
###########

print H "H " . $record_host . " " . $msgtype . " " . time() . "\n";

#system("/usr/bin/perl /home/errorparse/stats_put.pl");
close(H);
exit(0);

#$q_allcounts->execute($xtime);
#
#open(F, ">/home/errorparse/stats.new") || die "Error opening stats.new";
#while( $row = $q_allcounts->fetchrow_hashref ) {
# print F "" . $row->{servernum} . " " . $row->{count} . "\n";
#}
#close F; # || die "Error writing stats.new";
#
#rename "/home/errorparse/stats.new", "/home/errorparse/stats";
#
#.1.3.6.1.4.1.18689.8.1

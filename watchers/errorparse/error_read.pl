#!/usr/bin/perl

# Copyright (C) 2007 Mysidia 


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
my $DB_PASS = '****';

sub hashitems {
   my $hash = shift;
   my @items = @_;
   my @result = ();

   for(@items) {
        push @result, $hash->{$_};
   }
   @result;
}

my $dbh = DBI->connect("DBI:mysql:dbname=perror", $DB_USER, $DB_PASS, { AutoCommit => 1})
 || die "Unable to connect to database";
my $curtime = time();
my $xtime = time();
my $row = undef;
my %data = ();
if ( $xtime % 300 > 0 ) {
     $xtime -= ($xtime % 300);
}

my $q_allcounts = $dbh->prepare(q|SELECT * from msgcounts LEFT JOIN mhosts ON (msgcounts.server=mhosts.servername) WHERE first_time >= ? ORDER BY server |);
my $q_recent = $dbh->prepare(q|SELECT * from msgcounts WHERE first_time >= ? AND server = ? |);
my $q_cupdate = $dbh->prepare(q|UPDATE msgcounts SET first_time=?, last_time=?, count=?, server=?, select1=?, select2=?, loggerupdate=?, xmls=?, misc=? WHERE id=?|);
my $q_cinsert = $dbh->prepare(q|INSERT INTO msgcounts (first_time, last_time, count, server, select1, select2, loggerupdate, xmls, misc) VALUES(?,?,?,?,?,?,?,?,?)|);
my $server_name = 'UNKNOWN';
my $from_address = $ENV{SENDER};
my $record_host = 'UNKNOWN';
my $hostid = 0;
my %hostdata;
my $msgtype = 'UNKNOWN';

my $q_host_getlist = $dbh->prepare(q|SELECT * from mhosts|);


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
      elsif ( /^\s*Description: Unable to connect.* 192\.168\....\.9/ ) {
             print F " **SELECT1\n";
             $msgtype = 'select1';
# Description: Unable to connect to database: 192.168.....9: Lost connection to MySQL server during query


      }
      elsif ( /^Unable to connect.* 192\.168\....\.8$/ ) {
            $msgtype = 'select2';
      }
      elsif ( /^\s*Description: CREATE/ ||  /^\s*Description: UPDATE/ ||  /^\s*Description: INSERT/ ) {
             print F " **LOGGERUPDATE\n";
             $msgtype = 'loggerupdate';
      }
      elsif (  /select(\d)/ ) {
            print F " **SELECT${1}\n";
            $msgtype = 'select' . $1;
      }
      elsif ( /loggerupdate/ ) {
            print F " **LOGGERUPDATE\n";
            $msgtype = 'loggerupdate';
      }
  }
  print F $_;
}
close F;
###########

$q_host_getlist->execute();
while ( $row = $q_host_getlist->fetchrow_hashref )
{
        if ( $row->{hostname} eq $record_host ) {
             $server_name = $row->{servername};
             $hostid = $row->{servernum};
             $q_host_getlist->finish;
             last;
        }
}


$q_recent->execute($xtime, $server_name);
if ( $row = $q_recent->fetchrow_hashref ) {
     %data = %{$row};
     $q_recent->finish;

     $data{count}++;
     $data{last_time} = time();
     if ( $msgtype ne 'UNKNOWN' ) {
         $data{$msgtype}++;
     } else {
         $data{misc}++;
     }

     $q_cupdate->execute(hashitems(\%data, qw(first_time last_time count server select1 select2 loggerupdate xmls misc id)));
}
else
{
    $data{id} = undef;
    $data{first_time} = time();
    $data{last_time} = time();
    $data{count} = 1;
    $data{server} = $server_name;
    $data{select1} = 0;
    $data{select2} = 0;
    $data{loggerupdate} = 0;
    $data{xmls} = 0;
    $data{misc} = 0;

     if ( $msgtype ne 'UNKNOWN' ) {
         $data{$msgtype}++;
     } else {
          $data{misc}++;
     }

    $q_cinsert->execute(hashitems(\%data, qw(first_time last_time count server select1 select2 xmls misc loggerupdate)));
}

system("/usr/bin/perl /home/errorparse/stats_put.pl");
exit(0);

$q_allcounts->execute($xtime);

open(F, ">/home/errorparse/stats.new") || die "Error opening stats.new";
while( $row = $q_allcounts->fetchrow_hashref ) {
 print F "" . $row->{servernum} . " " . $row->{count} . "\n";
}
close F; # || die "Error writing stats.new";

rename "/home/errorparse/stats.new", "/home/errorparse/stats";

#.1.3.6.1.4.1.18689.8.1

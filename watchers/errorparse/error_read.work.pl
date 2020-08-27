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

#open(H, ">>/home/errorparse.cmdbuf");

rename "/home/errorparse/errorparse.cmdbuf", "/home/errorparse/errorparse.cmdbuf.work.$$";
open(H, "</home/errorparse/errorparse.cmdbuf.work.$$") || die "/home/errorparse/errorparse.cmdbuf.work.$$ could not be opened: $!";


my $DB_USER = 'perror';
my $DB_PASS = '****';
my ($hk, $mtk, $hit_data);

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
my $line;
my %hit_data;
my %servername;

my $q_host_getlist = $dbh->prepare(q|SELECT * from mhosts|);
my %hit_data_lt;

if ( $ENV{EXT2} =~ /^(\S+)/ ) {
     $record_host = $1;
     $record_host =~ s/_/./g;     
}
elsif ( $from_address =~ /[^@]+\@(\S+)/ ) {
     $record_host = $1;
}

###########


while($_ = <H>)
{
    if ($_ =~ /^H (\S+) (\S+) (\S+)/) {
          if (!exists($hit_data{$1}) || !exists($hit_data{$1}->{$2})) {
               $hit_data{$1}->{_last_time} = $3;
               if ( !exists($hit_data{$1}->{_count}) ) {
                   $hit_data{$1}->{_count} = 1;
               } else {
                   $hit_data{$1}->{_count}++;
               }
               $hit_data{$1}->{$2}=1;
          } else {
               $hit_data{$1}->{_count}++;
               $hit_data{$1}->{_last_time} = $3;
               $hit_data{$1}->{$2}++;
          }
    }
}


close H;


###########
$q_host_getlist->execute();
while ( $row = $q_host_getlist->fetchrow_hashref )
{
       $servername{$row->{hostname}} = $row->{servername};
}


for $hk ( keys %hit_data )
{
     if (exists($servername{$hk})) {
         $server_name = $servername{$hk};
     } else {
         $server_name = 'unknown';
     }

     $q_recent->execute($xtime, $server_name);
     if ( $row = $q_recent->fetchrow_hashref ) {
          %data = %{$row};
          $q_recent->finish;

          $data{count} += $hit_data{$hk}->{_count};
          if ( !exists($data{last_time} ) || ($hit_data{$hk}->{_last_time} >= $data{last_time}) ) { 
              $data{last_time} = $hit_data{$hk}->{_last_time};
          }

          for $mtk ( keys %{$hit_data{$hk}} ) {
              next if ($mtk =~ /^_/);

              if ( $mtk ne 'UNKNOWN' ) {
                  $data{$mtk} += $hit_data{$hk}->{$mtk};
              } else {
                  $data{misc} += $hit_data{$hk}->{$mtk};
              }
          }

          $q_cupdate->execute(hashitems(\%data, qw(first_time last_time count server select1 select2 loggerupdate xmls misc id)));
     }
     else
     {
         %data = ();
         $data{id} = undef;
         $data{first_time} = $hit_data{$hk}->{_last_time};
         $data{last_time} = $hit_data{$hk}->{_last_time};
         $data{count} = $hit_data{$hk}->{_count};
         $data{server} = $server_name;
         $data{select1} = 0;
         $data{select2} = 0;
         $data{loggerupdate} = 0;
         $data{xmls} = 0;
         $data{misc} = 0;

         for $mtk ( keys %{$hit_data{$hk}} ) {
             next if ($mtk =~ /^_/);
             if ( $mtk ne 'UNKNOWN' ) {
                 $data{$mtk} += $hit_data{$hk}->{$mtk};
             } else {
                 $data{misc} += $hit_data{$hk}->{$mtk};
             }
         }

        $q_cinsert->execute(hashitems(\%data, qw(first_time last_time count server select1 select2 xmls misc loggerupdate)));
     }
}

unlink("/home/errorparse/errorparse.cmdbuf.work.$$");
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

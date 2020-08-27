#!/usr/bin/perl

# Copyright (C) 2008 Mysidia 


use CGI qw/:all/;
use Math::GMP;
use Math::BigFloat;
print header;
print start_html();

print q!
 <style>
   .evenrow { background: lightgray; }
   .warning { background: orange; }
   .caution { background: yellow; }
   .alert   { background: red; }
   .oddrow { }
 </style>
!;




my $pixtools;
my $pixwork;
my $project = '';
my $line;
my $ip;
my $icount=0;
my $icount_idle=0;
my %iph;
my %iph_idle;
my @output;
my @output_idle;
my %orow;
my %orow_idle;
my $row;
my $ii;
my $iclass;
my $nclass;
my $iidle;
my $ibytes; 
my %difftime;
my ($fdev,$fino,$fmode,$fnlink,$fuid,$fgid,$frdev,$fsize,$fatime,$fmtime,$fctime,$fblksize,$fblocks);

my @projlist = qw(v1a v1b v1c);

if ($ARGV[0] =~ /^v1[a-z]$/) {
     $project = $ARGV[0];
}

#if (!$project) {
#    print("arg1 missing\n");
#    exit(0);
#}

if (!exists($ENV{PIXTOOLSDIR})) {
    $ENV{PIXTOOLSDIR} = "/usr/pixtools";
}

$pixtools = $ENV{PIXTOOLSDIR};




if (!exists($ENV{PIXWORKDIR})) {
    $ENV{PIXWORKDIR} = "/var/pos/";
}

$pixwork = $ENV{PIXWORKDIR};


##################################################


for $project (@projlist)
{
     $icount = 0;
     $icount_idle = 0;

     open(F, "<${pixwork}/${project}-conn-check.lasttime")
        || die("Error: unable to open ${project}-conn-check.lasttime");


    ($fdev,$fino,$fmode,$fnlink,$fuid,$fgid,$frdev,$fsize,$fatime,$fmtime,$fctime,$fblksize,$fblocks) =
        stat("${pixwork}/${project}-conn-check.lasttime");

     $difftime{$project} = time() - $fmtime;


     while($line = <F>)
     {
         chomp $line;
     
         if (split(/ /, $line)) {
             $ip = $_[2];

     #TCP out 66.249.72.49:48409 in 69.46.226.141:80 idle 0:00:01 Bytes 837 flags UI
     # 0   1          2           3   4               5    6      7     8   9     10

             unless( $ip =~ s/(\d+\.\d+\.\d+\.\d+):(\d+)/$1/ ) {
                 $ip =~ s/([^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*):(\d+)/$1/;
             }
     
             if ($ip) {
                 if (!exists($iph{$project})) {
                     $iph{$project} = {};
                     $iph_idle{$project} = {};
                 }
                 if (!exists($iph{$project}->{$ip})) {
                     $iph{$project}->{$ip} = 0;
                     $iph_idle{$project}->{$ip} = 0
                 }

                 $iph{$project}->{$ip}++;

                 if ($_[6] =~ /^0:0[1-5]/ && $_[8] eq '0' ) {
                    $iph_idle{$project}->{$ip}++;
                 }
             }
         }
     }
     
     for ( sort { $iph{$project}->{$b} <=> $iph{$project}->{$a} } keys %{$iph{$project}} )
     {
          if ($icount++ > 10) {
                delete $iph{$project}->{$_};
          }
     }

     for ( sort { $iph_idle{$project}->{$b} <=> $iph_idle{$project}->{$a} } keys %{$iph_idle{$project}} )
     {
          if ($icount_idle++ > 10) {
                delete $iph_idle{$project}->{$_};
          }
     }
     
     close F;
     
     $orow{$project} = 0;
     $orow_idle{$project} = 0;


     for ( sort { $iph{$project}->{$b} <=> $iph{$project}->{$a} } keys %{$iph{$project}} )
     {
          unless($output[$orow{$project}]) {
               $output[$orow{$project}] = {};
          }
          
          unless( $output[$orow{$project}]->{$project}  ) {
               $output[$orow{$project}]->{$project} = [];
          }
          
          $output[$orow{$project}]->{$project} = [ $_, $iph{$project}->{$_} ];     
          $orow{$project}++;          
     }



     for ( sort { $iph_idle{$project}->{$b} <=> $iph_idle{$project}->{$a} } keys %{$iph_idle{$project}} )
     {
          unless($output_idle[$orow_idle{$project}]) {
               $output_idle[$orow_idle{$project}] = {};
          }

          unless( $output_idle[$orow_idle{$project}]->{$project}  ) {
               $output_idle[$orow_idle{$project}]->{$project} = [];
          }

          $output_idle[$orow_idle{$project}]->{$project} = [ $_, $iph_idle{$project}->{$_} ];
          $orow_idle{$project}++;
     }

}

print center(h3("* Information from last con-check run *"));
print CGI::start_table();
print caption('All port 80 Connections');

     print CGI::start_Tr();
     for $project (@projlist) {
          print th({-colspan => 2}, $project);
     }
     print CGI::end_Tr();

     print CGI::start_Tr();
     for(@projlist) {
          print th("Ip"), th("Connections");
     }
     print CGI::end_Tr();


for ( @output )
{
     $ii++;
     $row = $_;

     if ($ii%2 == 0) { $iclass = 'evenrow'; } else { $iclass = 'oddrow'; }

     print CGI::start_Tr();
     for(@projlist) {
          $nclass = $iclass;



          if ( $row->{$_}->[1] > 800 ) {
               $nclass = "alert";
          }
          elsif ( $row->{$_}->[1] > 150 ) {
               $nclass = "warning";
          }
          elsif ( $row->{$_}->[1] > 80 ) {
               $nclass = "caution";
          }

          print td({ -class => $iclass}, $row->{$_}->[0]), td({ -class => $nclass }, $row->{$_}->[1]);
     }
     print CGI::end_Tr();
}
print CGI::end_table();


print q!<hr/>!;

############################

print CGI::start_table();
print caption('Idle port 80 Connections');

     print CGI::start_Tr();
     for $project (@projlist) {
          print th({-colspan => 2}, $project);
     }
     print CGI::end_Tr();

     print CGI::start_Tr();
     for(@projlist) {
          print th("Ip"), th("Connections");
     }
     print CGI::end_Tr();


for ( @output_idle )
{
     $ii++;
     $row = $_;

     if ($ii%2 == 0) { $iclass = 'evenrow'; } else { $iclass = 'oddrow'; }
    
     print CGI::start_Tr();
     for(@projlist) {
          print td({ -class => $iclass}, $row->{$_}->[0]), td({ -class => $iclass }, $row->{$_}->[1]);
     }
     print CGI::end_Tr();
}
print CGI::end_table();




for ( keys %difftime )
{
   $n = Math::BigFloat->new($difftime{$_});
   $n->accuracy(30);
   print p("  $_   last checked " . ($n/Math::BigFloat->new(60)) .  " minute(s) ago\n");
}


print CGI::end_html();


#print CGI::start_table();
#for $project (qw(v1a v1b v1c)) {
#     for (@{$output{$project}}) {
#          print Tr(td( $_->[0]  ), td( $_->[1] ));
#    }
#}
#print CGI::end_table();



##!/bin/bash
#
#TMPFILE=/var/log/junk.last.$$
#PROJECT=$1
#. /etc/ptools.env
##/usr/bin/expect ${PIXTOOLSDIR}/conn-geta.exp > /var/log/geta-conn
#
#cat ${PIXWORKDIR}/${PROJECT}-conn-check.lasttime  | awk {'print $3'} | awk -F: {'print $1'}| grep -v "^$" | sort | uniq -c | sort -n
# | tail -n 50 > $TMPFILE
#cat $TMPFILE
#tail -n 30 $TMPFILE | awk {'print "shun "$2'}


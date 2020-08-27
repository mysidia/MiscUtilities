#!/usr/bin/perl

# Copyright (C) 2007 Mysidia 

use DBI;

#print "Hello\n";

#`/usr/bin/logger -- DEBUG stats_read.pl - $ARGV[0] $ARGV[1] $ARGV[2]`;

my $base = '.1.3.6.1.4.1.28405.20.1';

open F, "</home/errorparse/stats";
my %stats;
my $key;
my ($OID1, $OID2, $OID3);
my ($rOID1, $rOID2, $rOID3);
my ($xOID1, $xOID2, $xOID3);
my %result;

open OO, ">>/root/OO.1x";
print OO "--" . $ARGV[0] .  " " . $ARGV[1] . "\n";
#close OO;

#system("/usr/bin/logger  -- $ARGV[0] $ARGV[1]");

$stats{$base}{0}={};

$stats{$base}{$_}{0} = 0   for qw(1..6);


while( <F> ) 
{ 
     if ( /^(\S+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+) (\d+)/ ) {
         $key = $base . $2 . '.';

         $stats{$base}{1}{0} = 0;
         $stats{$base}{2}{0} = 'all servers';
         $stats{$base}{3}{0} += int($3 || 0);
         $stats{$base}{4}{0} += int($4 || 0);
         $stats{$base}{5}{0} += int($5 || 0);
         $stats{$base}{6}{0} += int($6 || 0);
         $stats{$base}{7}{0} += int($7 || 0);
#         $stats{$base}{0}{7}=10;


         $stats{$base}{1}{$2} = $2;
         $stats{$base}{2}{$2} = $1;
         $stats{$base}{3}{$2} = $3;# $2 || 0;
         $stats{$base}{4}{$2} = $4 || 0;
         $stats{$base}{5}{$2} = $5 || 0;
         $stats{$base}{6}{$2} = $6 || 0;
         $stats{$base}{7}{$2} = $7 || 0;
#         $stats{$base}{$2}{7}=10;
     }
}

my %ptrMap = (
  peServerName => 2,
  peIndex  => 1,
  peMsgCount => 3,
  peMsgcount => 3,
  peSelect1  => 4,
  peSelect2  => 5,
  LoggerUpdate => 6,
  peMiscErrs => 7,
  peXmlErrs => 8
);

if ( $ARGV[0] eq 'index') {
      print $stats{$base}{1}{$_} . "\n"  for sort {$a<=>$b} keys( %{$stats{$base}{1}});
      exit(0);
}
elsif ( $ARGV[0] eq 'query' ) { 

   if ( $ptrMap{$ARGV[1]} ) {
       print $stats{$base}{1}{$_} . ':' . $stats{$base}{$ptrMap{$ARGV[1]}}{$_}. "\n"
             for sort {$a<=>$b} keys( %{$stats{$base}{1}});
   } 
   exit(0);
}
elsif ( $ARGV[0] eq 'get' ) {
   my $ukey = int($ARGV[2]);

   if ( $ptrMap{$ARGV[1]} && defined($stats{$base}{1}{$ukey}) ) {
       print $stats{$base}{$ptrMap{$ARGV[1]}}{$ukey};
   }
   exit(0);
}


# print F "" . $row->{hostname} . " " .
#             int($row->{servernum}||0) . " " . int($row->{count}||0) . " " .
#             int($row->{select1}||0) . " " .
#             int($row->{select2}||0) . " " .
#             int($row->{loggerupdate}||0) . " " .
#             int($row->{misc}||0) .
#             "\n";

if ( $ARGV[0] eq 'query') {
#      print $stats{$base}{1}{$_} . "\n"  for sort {$a<=>$b} keys( %{$stats{$base}{1}});
      exit(0);
}


#web01.pp 1 0 0 0 0 0


if ( $ARGV[0] eq '-r' || ($ARGV[0] eq '-n' &&
                          $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.20\.1)\.(\d+)\.(\d+)/ 
                         )
      || ($ARGV[0] eq '-g' && $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.20\.1)\.(\d+)\.(\d+)/) )
{
           ($OID1,$OID2,$OID3)=();

           if ( $ARGV[1] !~ /^(\.1\.3\.6\.1\.4\.1\.28405\.20\.1)\.(\d+)\.(\d+)/ ) {
                exit(0);
           } 

           ($OID1,$OID2,$OID3)=($1,$2,$3);
           ($rOID1, $rOID2, $rOID3)=($1,$2,$3);

           if (!defined($stats{$OID1}{$OID2}{$OID3})) {
               exit(0); 
           }

           if ( $ARGV[0] eq '-n' ) {
                if ( defined($stats{$rOID1}{$rOID2}{$rOID3 + 1})  ) {
                       $rOID3++;
                }
                elsif ( defined($stats{$rOID1}{$rOID2 + 1}{0})  ) {
                       $rOID2++;
                       $rOID3=0;
                }
                else {
                       $rOID1='.1.3.6.1.4.1.28405.20.2'; #1.' . ($OID1+1);
                       $rOID2=0;
                       $rOID3=0;
                }
           }

           print   $rOID1 . "." . $rOID2 . "." . $rOID3 . "\n";
           if ($stats{$rOID1}{$rOID2}{$rOID3} =~ /^\d+$/ ) {
                print   "counter\n";
           } else {
                print   "string\n";
           }

           print   $stats{$rOID1}{$rOID2}{$rOID3} . "\n";
           exit(0);
}

if ( $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.20\.1)(?:\.(.*))?/ )
{
           $rOID1 = $1;

           if ( $2 ) {
               $rOID2 = $2;

               if ( $rOID2 =~ /^(\d+)(?:\.(.*))?/ ) {
                      $rOID2 = $1;
                      $rOID3 = $2;
               }    
           }             
}

print OO "[[]] $rOID1  $rOID2  $rOID3\n";

for $OID1 (sort{$a<=>$b} keys %stats)
{
     for $OID2 (sort{$a<=>$b} keys %{$stats{$OID1}}) {
         next if ($rOID2 && $rOID2 ne $OID2);

         for $OID3 ( sort{$a<=>$b} keys %{$stats{$OID1}{$OID2}} ) {
           next if ($rOID3 && $rOID3 ne $OID3);
           %result = ();

           ($xOID1, $xOID2, $xOID3) = ($OID1, $OID2, $OID3);

           if ( $ARGV[0] eq '-n' ) {
               if ( $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.20\.1)(?:(?:\.(\d+))?\.(\d+))?/ ) {
print OO "[" . $1 . "  " . $2 . " " . $3 . "]\n";;
                   if ( defined($stats{$xOID1}{$xOID2}{$xOID3 + 1})  ) {
                          $xOID3++;
                   }
                   elsif ( defined($stats{$xOID1}{$xOID2 + 1}{0})  ) {
                          $xOID2++;
                          $xOID3=0;
                   }
                   else {
                          $xOID1='.1.3.6.1.4.1.28405.20.2'; #1.' . ($OID1+1);
                          $xOID2=0;
                          $xOID3=0;
                   }
               }
           }
           $result{oid} = $xOID1 . "." . $xOID2 . "." . $xOID3;
           $result{type} = 'counter';
           $result{value} = $stats{$OID1}{$OID2}{$OID3};

           print   $OID1 . "." . $OID2 . "." . $OID3 .  "\n";
           if ($stats{$OID1}{$OID2}{$OID3} =~ /^\d+$/ ) {
                 print   "counter\n";
           } else {
                 print   "string\n";
           }
           print   $stats{$OID1}{$OID2}{$OID3} . "\n";
         }
     }
}

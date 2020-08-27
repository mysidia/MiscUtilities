#!/usr/bin/perl

# Copyright (C) 2007 Mysidia 

use DBI;

#print "Hello\n";

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

while( <F> ) 
{ 
     if ( /^(\S+) (\d+) (\d+) (\d+) (\d+) (\d+)/ ) {
         $key = $base . $2 . '.';

         $stats{$base}{0} = { '0' => 6 };
         $stats{$base}{0}{1} = 0;
         $stats{$base}{0}{2} = '*';
         $stats{$base}{0}{3} += int($3 || 0);
         $stats{$base}{0}{4} += int($4 || 0);
         $stats{$base}{0}{5} += int($5 || 0);
         $stats{$base}{0}{6} += int($6 || 0);
#         $stats{$base}{0}{7}=10;


         $stats{$base}{$2} = { '0' => 6 };
         $stats{$base}{$2}{1} = $2;
         $stats{$base}{$2}{2} = $1;
         $stats{$base}{$2}{3} = $3;# $2 || 0;
         $stats{$base}{$2}{4} = $4 || 0;
         $stats{$base}{$2}{5} = $5 || 0;
         $stats{$base}{$2}{6} = $6 || 0;
#         $stats{$base}{$2}{7}=10;
     }
}

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
           print   "counter\n";
           print   $stats{$OID1}{$OID2}{$OID3} . "\n";
         }
     }
}

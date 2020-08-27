#!/usr/bin/perl
use DBI;

# Copyright (C) 2008 Mysidia 


#print "Hello\n";

#`/usr/bin/logger -- DEBUG stats_read.pl - $ARGV[0] $ARGV[1] $ARGV[2]`;

my $base = '.1.3.6.1.4.1.28405.21.1';

open F, "</var/run/radius.stats";
my %stats;
my $key;
my ($OID1, $OID2);
my ($rOID1, $rOID2);
my ($xOID1, $xOID2);
my %result;
my %messages;



while( <F> ) 
{ 
    if ( /^(\S+)\s+(\d+)/ ) {
        $messages{$1}=$2;
    }
}

my %ptrMap = (
  AuthOK => 1,
  AuthFail => 2,
  Other => 3
);

for (keys %ptrMap) {
  if ( defined($messages{$_}) ) {
      $stats{$base}{$ptrMap{$_}} = $messages{$_};
  }
}

$stats{$base}{0} = join(" ", map { $_ . ":" . $messages{$_}  } (keys %messages));

if ( $ARGV[0] eq '-r' || ($ARGV[0] eq '-n' &&
                          $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.21\.1)\.(\d+)/ 
                         )
      || ($ARGV[0] eq '-g' && $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.21\.1)\.(\d+)/) )
{
           ($OID1,$OID2)=();

           if ( $ARGV[1] !~ /^(\.1\.3\.6\.1\.4\.1\.28405\.21\.1)\.(\d+)/ ) {
                exit(0);
           } 

           ($OID1,$OID2)=($1,$2);
           ($rOID1, $rOID2)=($1,$2);

           if (!defined($stats{$OID1}{$OID2})) {
               exit(0); 
           }

           if ( $ARGV[0] eq '-n' ) {
                $rOID2++;
           }

           print   $rOID1 . "." . $rOID2 . "\n";
           if ($stats{$rOID1}{$rOID2} =~ /^\d+$/ ) {
                print   "counter\n";
           } else {
                print   "string\n";
           }

           print   $stats{$rOID1}{$rOID2} . "\n";
           exit(0);
}

if ( $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.20\.1)(?:\.(.*))?/ )
{
           $rOID1 = $1;

           if ( $2 ) {
               $rOID2 = $2;
           }             
}

#print OO "[[]] $rOID1  $rOID2  $rOID3\n";

for $OID1 (sort{$a<=>$b} keys %stats)
{
     for $OID2 (sort{$a<=>$b} keys %{$stats{$OID1}}) {
         next if ($rOID2 && $rOID2 ne $OID2);

           %result = ();

           ($xOID1, $xOID2) = ($OID1, $OID2);

           if ( $ARGV[0] eq '-n' ) {
               if ( $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.21\.1)(?:(?:\.(\d+))?\.(\d+))?/ ) {
#print OO "[" . $1 . "  " . $2 . " " . $3 . "]\n";;
                   $xOID2++;
               }
           }
           $result{oid} = $xOID1 . "." . $xOID2;
           $result{type} = 'counter';
           $result{value} = $stats{$OID1}{$OID2};

           print   $OID1 . "." . $OID2 . "\n";
           if ($stats{$OID1}{$OID2} =~ /^\d+$/ ) {
                 print   "counter\n";
           } else {
                 print   "string\n";
           }
           print   $stats{$OID1}{$OID2} . "\n";

     }
}

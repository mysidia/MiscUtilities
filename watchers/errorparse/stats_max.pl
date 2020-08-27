#!/usr/bin/perl

# Copyright (C) 2007 Mysidia 

use DBI;


my $base = '.1.3.6.1.4.1.28405.20.1';

open F, "</home/errorparse/stats";
my %stats;
my $key;
my ($OID1, $OID2, $OID3);
my ($rOID1, $rOID2, $rOID3);
my ($xOID1, $xOID2, $xOID3);
my %result;

my $x = 0;

while( <F> ) 
{ 
     if ( /^(\S+) (\d+) (\d+) (\d+) (\d+) (\d+)/ ) {
          if ($2>$x){$x=$2;}
     }
}

if ( $ARGV[0] eq '-r' || ($ARGV[0] eq '-n' &&
                          $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.20\.0)/ 
                         )
      || ($ARGV[0] eq '-g' && $ARGV[1] =~ /^(\.1\.3\.6\.1\.4\.1\.28405\.20\.0)/)
       || ($ARGV[0] eq '-g') )
{
           ($OID1,$OID2,$OID3)=();

           if ( $ARGV[1] !~ /^(\.1\.3\.6\.1\.4\.1\.28405\.20\.0)/ ) {
                exit(0);
           } 

           if ( $ARGV[0] eq '-n' ) {
                print ".1.3.6.1.4.1.28405.20.1\n";
           } else {
                print ".1.3.6.1.4.1.28405.20.0\n";
           }

           print   "integer\n";
           print $x . "\n";
           exit(0);
}

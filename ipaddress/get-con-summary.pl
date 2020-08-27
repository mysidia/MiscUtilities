#!/usr/bin/perl

# Copyright (C) 2008 Mysidia 

use CGI;
my $uniq = time();
my $reget = 0;

my  ($fdev,$fino,$fmode,$fnlink,$fuid,$fgid,$frdev,$fsize,$fatime,$fmtime,$fctime,$fblksize,$fblocks) =
      stat("/var/pos/con-summary1.dat");

my $line;
my @values;
my %href;


if ($fmtime == 0 || (time() - $fmtime) >= 10) 
{  
   $reget = 1;
}
else
{
   if ( open(FILE, "</var/pos/con-summary1.dat") ) {
        while($line = <FILE>) {
             if ( $line =~ /^(\S+): (\d+)/ ) {
                  $href{$1} = $2;
             }
        }
        close FILE;

        unless( exists($href{'v2a_conn'}) && exists($href{'v2b_conn'}) && exists($href{'v1c_conn'}) ) {
             $reget = 1;
        }
   } else {
       $reget = 1;
   }
}


if ($reget == 1)
{
   open(CAPOUT, ">/var/pos/con-summary1.dat.new" . $uniq);
   open(STREAM,"/usr/local/bin/con-summary1|");

   while($line = <STREAM>)
   {
      chomp $line;
   
      if ( $line =~ /^\S+: (\d+)/ ) {
            push @values, $1;
      }
   }

   $href{'a_conn'} = $values[0]    if exists($values[0]);
   $href{'b_conn'} = $values[1]    if exists($values[1]);
   $href{'c_conn'} = $values[2]    if exists($values[2]);


   for(keys %href){
     print CAPOUT "${_}: " . $href{$_} . "\n";
   }

   close STREAM;
   close CAPOUT;

   if ( (time() - $uniq) > 5 ) {
       unlink("/var/pos/con-summary1.dat.new" . $uniq);
   } else {
       rename("/var/pos/con-summary1.dat.new" . $uniq, "/var/pos/con-summary1.dat");
   }
}




   for(keys %href){
     print "${_}: " . $href{$_} . "\n";
   }


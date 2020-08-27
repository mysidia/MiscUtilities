#!/usr/bin/perl

# Copyright (C) 2008 Mysidia 

use Date::Parse;

my $tnow = time();
my $tstok;
my $tsparsed;

my %messages = (
  AuthOK => 0,
  AuthFail => 0,
  Other  => 0,
 );

while ( <> )
{
  if ( /^(\S+\s+\S+\s+\d+\s+\d+:\d+:\d+\s+\d+)\s+:/ ) {
        next if ( /client localhost/ );

        $tstok = $1;
        $tsparsed = str2time($tstok);

        next if ( $tsparsed < ($tnow - 60 * 2 - 30) );
        next if (/No matching entry in the database for request from user/);


        if ( /: Auth: Login incorrect/ ) { 
             $messages{AuthFail}++;
        }
        elsif ( /: Auth: Login OK:/ ) {
             $messages{AuthOK}++;
        }
        else {
             $messages{Other}++;
        }
        #print;
  }
}

open F, ">/var/run/radius.stats.new" || die "Error saving radius stats [1] /var/run/radius.stats.new ";
for (keys %messages)
{
      print F $_ . " " . $messages{$_} . "\n";
}
close F || die "Error saving radius stats [2] /var/run/radius.stats.new";


rename "/var/run/radius.stats.new", "/var/run/radius.stats";

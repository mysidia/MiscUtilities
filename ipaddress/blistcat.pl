#!/usr/bin/perl

# Copyright (C) 2008 Mysidia 

use NetAddr::IP;
use IO::Socket;

open F, "<" . $ARGV[0];
$byte='';

while ( read(F,$byte,1) != 0 ) 
{
     if ($byte == '\004') {
            $ipv4addr='';
            die "Read Error"  unless read(F,$ipv4addr,4)==4;

            print inet_ntoa($ipv4addr) . "\n";
     }
     elsif ($byte == '\006') {
            die "Read Error"  unless read(F,$ipv6addr,16)==16;

            $ipobj = NetAddr::IP->new6($ipv6addr);
            print  $ipboj->short() . "\n";
     }
}

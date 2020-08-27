#!/usr/bin/perl

# Copyright (C) 2008 Mysidia 


use IO::Socket;

print inet_ntoa(pack("N",hex($ARGV[0])));

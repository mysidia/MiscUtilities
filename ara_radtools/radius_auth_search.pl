#!/usr/bin/perl

# Copyright (C) 2008 Mysidia 

use strict;
use CGI qw/:standard escapeHTML/;
my $lineout=0;
my $sublines=0;

my ($text, $X, @gzfiles);
$SIG{PIPE} = sub{};

opendir(D, "/var/log/radius");
while ($_=readdir(D) ) {
    push @gzfiles, $_ if (/^radius\.log\.[0-9]+\.gz/);
}


if ($#ARGV == -1 )
{
    print STDERR "Usage: $0 <regexp>\n";
    exit(1);
}


if ( $ARGV[0] eq 'INVALID' || $ARGV[0] !~ m/^[-a-zA-Z0-9@!_+.*\[\]? ]*$/ ) {
    print "Error: given search text is not an allowed expression.\n";
    print "Valid characters are: a-z A-Z 0-9 @!_+.*[]?<>\n";
    exit(1);
}


#$text = '\[' . $ARGV[0] . '\]';
$text = $ARGV[0];


print 'Backend executing search...';
print "radius.log:\n";
if ( open(F, "/var/log/radius/radius.log") ) {
   while (<F>) {
       next unless m/$text/;
       print;
       $lineout++;

       if ($lineout > 2000) {
            print "[[[ Error: OUTPUT Truncated at 2000 lines ]]]\n";
            last;
       }
   }
   close F;
}


if ($lineout > 2000) {
    exit(0);
}


for my $file (sort {$b<=>$a} @gzfiles)
{
    next unless ($file =~ /\.1\.gz/);

    open(F, "/bin/zcat " . $file . " |");
    $sublines=0;
    print "Extending search to: $file\n";
    while(<F>) {
        next unless m/$text/;
        $lineout++;

        print;
        if ($lineout > 2000) {
             print "[[[ Error: OUTPUT Truncated at 2000 lines ]]]\n";
             last;
        }
        $sublines++;
    }
    if ($sublines eq 0) {
          print '&nbsp;       (no results found)' . "\n";
    }
    close F;
}

print "End of Results.\n";

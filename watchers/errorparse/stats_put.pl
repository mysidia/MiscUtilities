# Copyright (C) 2007 Mysidia 


use DBI;

#print "Hello\n";

my $DB_USER = 'perror';
my $DB_PASS = '****';

my $dbh = DBI->connect("DBI:mysql:dbname=perror", $DB_USER, $DB_PASS, { AutoCommit => 1})
 || die "Unable to connect to database";
my $xtime = time() - 60*2;
my $q_allcounts = $dbh->prepare(q|SELECT * from mhosts LEFT JOIN msgcounts ON (msgcounts.server=mhosts.servername AND first_time >= ?) ORDER BY servernum |);


if ( $xtime % 240 > 0 ) {
     $xtime -= ($xtime % 240);
}


$q_allcounts->execute($xtime);

open(F, ">/home/errorparse/stats.new") || die "Error opening stats.new";
while( $row = $q_allcounts->fetchrow_hashref ) {
 print F "" . $row->{hostname} . " " . 
             int($row->{servernum}||0) . " " . int($row->{count}||0) . " " .
             int($row->{select1}||0) . " " .
             int($row->{select2}||0) . " " .
             int($row->{loggerupdate}||0) . " " .
             int($row->{misc}||0) . " " .
             int($row->{xmls}||0) . " " .
             "\n";
}
close F; # || die "Error writing stats.new";

rename "/home/errorparse/stats.new", "/home/errorparse/stats";


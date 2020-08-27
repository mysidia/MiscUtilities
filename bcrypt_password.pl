#!/usr/bin/perl
#
# Encode a password using Bcrypt
#
use Digest;
use Digest::Bcrypt;
use Digest::MD5 qw(md5_hex);

print "Enter username: ";
$username =<>;
chomp($username);

print "Enter password: ";
$password = <>;
chomp($password);

if ($username !~ /^[a-zA-Z0-9]+$/) {
   die "Invalid username";
}

if ($password !~ /^[a-zA-Z0-9]+$/) {
   die "Invalid password";
}

 my $bcrypt = Digest->new('Bcrypt');
 $bcrypt->cost(8);

 $bcrypt->salt(substr(md5_hex($username),16));
 $bcrypt->add($password);
print $bcrypt->b64digest;
print "\n";
 
  $bcrypt->reset;




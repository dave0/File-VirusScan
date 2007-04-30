#!perl -T

use Test::More tests => 1;

BEGIN {
	use_ok( 'Email::VirusScan' );
}

diag( "Testing Email::VirusScan $Email::VirusScan::VERSION, Perl $], $^X" );

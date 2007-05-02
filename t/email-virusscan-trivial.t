use Test::More tests => 14;
use Test::Exception;

use Email::Abstract;

BEGIN { 
	use_ok('Email::VirusScan');
	use_ok('Email::VirusScan::Base');
	use_ok('Email::VirusScan::Result');
}

dies_ok { Email::VirusScan->new() } 'Constructor dies with no arguments';
like( $@, qr/Must supply an 'engines' value to constructor/, '... error as expected');

dies_ok { Email::VirusScan->new({ engines => { wookie => {} }}) } 'Constructor dies with nonexistent engine';
like( $@, qr/Unable to find class Email::VirusScan::wookie for backend 'wookie'/, '... error as expected');

{ 
	package Email::VirusScan::Bogus;
	use base qw( Email::VirusScan::Base );
	sub new  { bless {}, $_[0]; }
	sub scan_path { return Email::VirusScan::Result->error( "bogus scanner looking at $_[1]" ); };
	$INC{'Email/VirusScan/Bogus.pm'} = 1;
}

my $s;
lives_ok { $s = Email::VirusScan->new({ engines => { Bogus => {} } }); } 'Constructor lives with trivial non-working engine';
my $result = $s->scan_path('/');
isa_ok( $result, 'Email::VirusScan::ResultSet');
ok( $result->is_error(), 'Result is an error' );
is_deeply( $result->get_errors(), [ 'bogus scanner looking at /' ], 'Error string is what we expected');

my $test_msg = <<'EOM';
To: postmaster
From: root
Subject: Testing

EOM

$result = $s->scan( Email::Abstract->new( $test_msg ) );
isa_ok( $result, 'Email::VirusScan::ResultSet');
ok( $result->is_error(), 'Result is an error' );
like( $result->get_errors->[0], qr{^bogus scanner looking at /tmp/(?:[A-Za-z0-9]+)$}, 'Error string is what we expected');

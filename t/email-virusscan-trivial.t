use Test::More tests => 15;
use Test::Exception;

use Email::Abstract;

BEGIN {
	use_ok('Email::VirusScan');
	use_ok('Email::VirusScan::Engine');
	use_ok('Email::VirusScan::Result');
}

dies_ok { Email::VirusScan->new() } 'Constructor dies with no arguments';
like( $@, qr/Must supply an 'engines' value to constructor/, '... error as expected');

dies_ok { Email::VirusScan->new({ engines => { wookie => {} }}) } 'Constructor dies with nonexistent engine';
like( $@, qr/Unable to find class wookie for backend 'wookie'/, '... error as expected');

{
	package Email::VirusScan::Engine::Bogus;
	use base qw( Email::VirusScan::Engine );
	sub new  { bless {}, $_[0]; }
	sub scan_path { return Email::VirusScan::Result->error( "bogus scanner looking at $_[1]" ); };
	$INC{'Email/VirusScan/Engine/Bogus.pm'} = 1;
}

my $s;
lives_ok { $s = Email::VirusScan->new({ engines => { -Bogus => {} } }); } 'Constructor lives with trivial non-working engine';
my $result = $s->scan_path('/');
isa_ok( $result, 'Email::VirusScan::ResultSet');
ok( $result->has_error(), 'Result is an error' );
my ($err) = $result->get_error();
isa_ok( $err, 'Email::VirusScan::Result');
is( $err->get_data(), 'bogus scanner looking at /', 'Error string is what we expected');

my $test_msg = <<'EOM';
To: postmaster
From: root
Subject: Testing

EOM

$result = $s->scan( Email::Abstract->new( $test_msg ) );
isa_ok( $result, 'Email::VirusScan::ResultSet');
ok( $result->has_error(), 'Result is an error' );
like( ($result->get_error)[0]->get_data, qr{^bogus scanner looking at /tmp/(?:[A-Za-z0-9]+)$}, 'Error string is what we expected');
1;

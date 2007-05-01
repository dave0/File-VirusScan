use Test::More tests => 10;
use Test::Exception;

BEGIN { 
	use_ok('Email::VirusScan');
	use_ok('Email::VirusScan::Result');
}

dies_ok { Email::VirusScan->new() } 'Constructor dies with no arguments';
like( $@, qr/Must supply an 'engines' value to constructor/, '... error as expected');

dies_ok { Email::VirusScan->new({ engines => { wookie => {} }}) } 'Constructor dies with nonexistent engine';
like( $@, qr/Unable to find class Email::VirusScan::wookie for backend 'wookie'/, '... error as expected');

{ 
	package Email::VirusScan::Bogus;
	sub new  { bless {}, $_[0]; }
	sub scan { return Email::VirusScan::Result->error( 'bogus scanner' ); };
	$INC{'Email/VirusScan/Bogus.pm'} = 1;
}

my $s;
lives_ok { $s = Email::VirusScan->new({ engines => { Bogus => {} } }); } 'Constructor lives with trivial non-working engine';
my $result = $s->scan();
isa_ok( $result, 'Email::VirusScan::ResultSet');
ok( $result->is_error(), 'Result is an error' );
is_deeply( $result->get_errors(), [ 'bogus scanner' ], 'Error string is what we expected');

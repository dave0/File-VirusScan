use Test::More tests => 15;
use Test::Exception;
use Cwd 'getcwd';
use File::Temp ();

use lib qw( t/lib );
use Eicar;

BEGIN {
	use_ok('Email::VirusScan::Engine::ClamAV::Clamscan');
}

# Existence of methods
can_ok('Email::VirusScan::Engine::ClamAV::Clamscan', qw( new scan scan_path ) );

# Constructor failures
dies_ok { Email::VirusScan::Engine::ClamAV::Clamscan->new() } 'Constructor dies with no arguments';
like( $@, qr/Must supply a 'command' config value/, ' ... error as expected');

# Constructor success
{
	my $s;
	lives_ok { $s = Email::VirusScan::Engine::ClamAV::Clamscan->new({ command => '/dev/null'}); } 'new() lives';
	isa_ok( $s, 'Email::VirusScan::Engine::ClamAV::Clamscan');
	isa_ok( $s, 'Email::VirusScan::Engine');
}

# Scan success
my $clamscan = 'clamscan';  # Better be in our path...
SKIP: {

	my $rc = system("$clamscan -V >/dev/null 2>&1");
	skip "Could not find $clamscan in path", 8 if $rc;

	my $s = Email::VirusScan::Engine::ClamAV::Clamscan->new({
		command => $clamscan,
	});

	my $result = $s->scan_path('t/');
	isa_ok( $result, 'Email::VirusScan::Result');
	ok( $result->is_error(), 'Result is an error' );
	is( $result->get_data(), 'Path t/ is not absolute', '... with expected text');

	# Try with fully-qualified path
	my $testdir = File::Temp::tempdir( TMPDIR => 1, CLEANUP => 1);
	chmod 0755, $testdir;
	lives_ok { $result = $s->scan_path( $testdir) } "scan_path($testdir) lives";
	isa_ok( $result, 'Email::VirusScan::Result');
	ok( $result->is_clean(), 'Result is clean' );
	if( ! $result->is_clean() ) {
		diag( $result->get_data() );
	}

	# Now try an EICAR
	my $msg = Eicar::eicar_message();
	$result = $s->scan( $msg );
	ok( $result->is_virus(), 'Result is a virus' );
	is( $result->get_data(), 'Eicar-Test-Signature', '... with expected text');
	if( ! $result->is_virus() ) {
		diag( $result->get_data() );
	}
}

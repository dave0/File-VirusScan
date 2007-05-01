use Test::More tests => 17;
use Test::Exception;
use Cwd 'getcwd';
use File::Temp ();

BEGIN {
	use_ok('Email::VirusScan::ClamAV::Daemon');
}

# Existence of methods
can_ok('Email::VirusScan::ClamAV::Daemon', qw( new scan scan_path ) );

# Constructor failures
dies_ok { Email::VirusScan::ClamAV::Daemon->new() } 'Constructor dies with no arguments';
like( $@, qr/Must supply a 'socket_name' config value/, ' ... error as expected');

# Constructor success
my $s;
lives_ok { $s = Email::VirusScan::ClamAV::Daemon->new({ socket_name => '/dev/null'}); } 'new() lives';
isa_ok( $s, 'Email::VirusScan::ClamAV::Daemon');
isa_ok( $s, 'Email::VirusScan::Base');

# Bad socket
dies_ok { $s->get_socket() } 'get_socket() dies (invalid socket_name given)';
like( $@, qr{Could not connect to clamd daemon at /dev/null}, '... error as expected');

# TODO: needs prompt from build process to avoid tests if no daemon available
my $sockfile = '/var/run/clamav/clamd.ctl';

SKIP: {
	skip 'No clamd socket available', 8 unless -S $sockfile;

	# Test with good socket
	$s = Email::VirusScan::ClamAV::Daemon->new({
		socket_name => $sockfile,
	});
	my $sock;
	lives_ok { $sock = $s->get_socket() } 'Real socket can be spoken to';
	$sock->close;

	# Try with unqualified path
	my $result;
	lives_ok { $result = $s->scan_path('t/') } 'scan_path() lives';
	isa_ok( $result, 'Email::VirusScan::Result');
	ok( $result->is_error(), 'Result is an error' );
	is( $result->get_data(), 'Path t/ is not absolute', '... with expected text');

	# Try with fully-qualified path
	my $testdir = File::Temp::tempdir( TMPDIR => 1, CLEANUP => 1);
	chmod 0755, $testdir;
	lives_ok { $result = $s->scan_path( $testdir) } "scan_path($testdir) lives";
	isa_ok( $result, 'Email::VirusScan::Result');
	ok( $result->is_clean(), 'Result is clean' );
}

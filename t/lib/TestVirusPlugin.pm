package TestVirusPlugin;
use strict;
use warnings;
use Test::Class;
use Test::More;
use Test::Exception;
use Email::Abstract;

use base qw( Test::Class );

sub under_test
{
	die q{Test class must implement under_test()};
}

sub required_arguments
{
	die q{Test class must implement required_arguments()}
}

sub engine
{
	my ($self) = @_;
	return $self->{engine};
}

sub _00_constructor : Test(setup => 2)
{
	my ($self) = @_;

	my $tclass = $self->under_test();

	$self->{engine} = $tclass->new(
		$self->required_arguments()
	);

	isa_ok( $self->{engine}, 'Email::VirusScan::Engine');
	isa_ok( $self->{engine}, $tclass);
}

sub expected_methods : Test(1)
{
	my ($self) = @_;

	can_ok( $self->under_test, qw( new scan scan_path ) );
}

sub scan_bogus_directory : Test(3)
{
	my ($self) = @_;
	my $s = $self->engine;

	my $result = $s->scan_path('t/');
	isa_ok( $result, 'Email::VirusScan::Result');
	ok( $result->is_error(), 'Result is an error' );
	is( $result->get_data(), 'Path t/ is not absolute', '... with expected text');
}

sub scan_empty_directory : Test(3)
{
	my ($self) = @_;

	return 'Could not run live test' if ! $self->testable_live;

	my $s = $self->engine;
	my $result;

	# Try with fully-qualified path
	my $testdir = File::Temp::tempdir( TMPDIR => 1, CLEANUP => 1);
	chmod 0755, $testdir;
	lives_ok { $result = $s->scan_path( $testdir) } "scan_path($testdir) lives";
	isa_ok( $result, 'Email::VirusScan::Result');
	ok( $result->is_clean(), 'Result is clean' );
	if( ! $result->is_clean() ) {
		diag( $result->get_data() );
	}
}

sub scan_eicar : Test(3)
{
	my ($self) = @_;

	return 'Could not run live test' if ! $self->testable_live;

	my $s = $self->engine;
	my $result;

	no warnings 'redefine';
	# If Email::VirusScan::Engine creates a temporary file, clamd
	# may not be able to read it with default permissions.  So,
	# force the file to be public for this test.
	local *Email::VirusScan::Engine::tempfile = sub {
		use File::Temp;
		my ($fh, $path) = File::Temp::tempfile();
		chmod 0644, $path;
		return ($fh, $path);
	};
	use warnings 'redefine';

	my $msg = $self->eicar_message();
	lives_ok { $result = $s->scan( $msg ) } 'Scanning eicar message lives';
	ok( $result->is_virus(), 'Result is a virus' );
	is( $result->get_data(), 'Eicar-Test-Signature', '... with expected text');
	if( ! $result->is_virus() ) {
		diag( $result->get_data() );
	}
}


# Return EICAR message for testing
sub eicar_message
{
	my $msg = <<'END';
From: <>
To: undisclosed-recipients;
Subject: EICAR test
Date: Tue, 11 Mar 2008 13:59:31 -0400
Message-ID: <asdfasdf1234@Localhost>
Content-Type: multipart/mixed; boundary="EuxKj2iCbKjpUGkD"

--EuxKj2iCbKjpUGkD
Content-Type: text/plain; charset=us-ascii
Content-Disposition: inline

Attachment contains sample EICAR virus


--EuxKj2iCbKjpUGkD
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename=virus

END

	# Intentionally split, so that this file doesn't trigger
	# virus scanners.
	$msg .= 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EIC';
	$msg .= 'AR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

	$msg .= <<'END';

--EuxKj2iCbKjpUGkD--
END

	return Email::Abstract->new($msg);
}

1;

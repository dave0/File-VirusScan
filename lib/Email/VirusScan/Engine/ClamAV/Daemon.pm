package Email::VirusScan::Engine::ClamAV::Daemon;
use strict;
use warnings;
use Carp;

use Email::VirusScan::Engine;
use base qw( Email::VirusScan::Engine );

use IO::Socket::UNIX;
use IO::Select;
use Scalar::Util 'blessed';
use Cwd 'abs_path';

use Email::VirusScan::Result;

sub new
{
	my ($class, $conf) = @_;

	if( ! $conf->{socket_name} ) {
		croak "Must supply a 'socket_name' config value for $class";
	}

	if( exists $conf->{zip_fallback} ) {
		unless( blessed( $conf->{zip_fallback} ) && $conf->{zip_fallback}->isa('Email::VirusScan::Engine') ) {
			croak q{The 'zip_fallback' config value must be an object inheriting from Email::VirusScan::Engine};
		}
	}

	my $self = {
		socket_name         => $conf->{socket_name},
		read_timeout      => $conf->{read_timeout}      || 60,
		write_timeout     => $conf->{write_timeout}     || 30,
		zip_fallback => $conf->{zip_fallback} || undef,
	};

	return bless $self, $class;
}

sub _get_socket
{
	my ($self) = @_;

	my $sock =  IO::Socket::UNIX->new( Peer => $self->{socket_name} );
	if( ! defined $sock ) {
		croak "Error: Could not connect to clamd daemon at $self->{socket_name}";
	}

	my $s = IO::Select->new();
	$s->add($sock);
	if ( ! $s->can_write( $self->{write_timeout}) ) {
		$sock->close;
		croak "Error: Timeout writing to clamd daemon at $self->{socket_name}";
	}

	$sock->print('PING');
	$sock->flush;

	if ( ! $s->can_read( $self->{read_timeout}) ) {
		$sock->close;
		croak "Error: Timeout reading from clamd daemon at $self->{socket_name}";
	}

	# Discard our IO::Select object.
	undef $s;

	my $ping_result;
	$sock->sysread( $ping_result, 256);
	chomp $ping_result;

	$sock->close();

	if( ! defined $ping_result || $ping_result ne 'PONG' ) {
		croak 'Error: clamd did not respond to PING';
	}

	# Ok, it's there.  Reconnect and return a socket we can use.
	# TODO: use SESSION / END support instead of reconnecting?
	$sock =  IO::Socket::UNIX->new( Peer => $self->{socket_name} );
	if( ! defined $sock ) {
		croak "Error: Could not connect to clamd daemon at $self->{socket_name}";
	}
	return $sock;
}

sub scan_path
{
	my ($self, $path) = @_;

	if( abs_path($path) ne $path ) {
		return Email::VirusScan::Result->error( "Path $path is not absolute" );
	}

	my $sock = eval { $self->_get_socket };
	if( $@ ) {
		return Email::VirusScan::Result->error( $@ );
	}

	if( ! $sock->print("SCAN $path\n") ) {
		$sock->close;
		return Email::VirusScan::Result->error( "Could not get clamd to scan $path" );
	}

	if( ! $sock->flush ) {
		$sock->close;
		return Email::VirusScan::Result->error( "Could not get clamd to scan $path" );
	}

	my $scan_response;
	my $rc = $sock->sysread( $scan_response, 256 );
	$sock->close();

	if( ! $rc ) {
		return Email::VirusScan::Result->error( "Did not get response from clamd while scanning $path" );
	}

	# TODO: what if more than one virus found?
	# TODO: can/should we capture infected filenames?
	if( $scan_response =~ m/: (.+) FOUND/ ) {
		return Email::VirusScan::Result->virus( $1 );
	} elsif ( $scan_response =~ m/: (.+) ERROR/ ) {
		my $err_detail = $1;

		# The clam daemon may not understand certain zip files,
		# and cannot use an external decompression tool.  The
		# standalone 'clamscan' utility can, though.  So, we
		# allow another engine to be configured as a fallback.
		# It's usually Email::VirusScan::ClamAV::ClamScan, but
		# doesn't have to be.
		if( $self->{zip_fallback}
		    && $err_detail =~ /(?:zip module failure|not supported data format)/i ) {
			return $self->{zip_fallback}->scan_path( $path );
		}
		return Email::VirusScan::Result->error( "Clamd returned error: $err_detail" );
	}

	return Email::VirusScan::Result->clean();
}

1;
__END__

=head1 NAME

Email::VirusScan::Engine::ClamAV::Daemon - Email::VirusScan backend for scanning with clamd

=head1 SYNOPSIS

    use Email::VirusScanner;
    my $s = Email::VirusScanner->new({
	engines => {
		'ClamAV::Daemon' => {
			socket_name => '/path/to/clamd.ctl',
		},
		...
	},
	...
}

=head1 DESCRIPTION

TODO

=head1 CLASS METHODS

=head2 new ( $conf )

TODO

=head1 INSTANCE METHODS

=head2 scan ( $email_abstract_obj )

TODO

=head2 scan_path ( $pathname )

TODO

=head1 DIAGNOSTICS

TODO A list of every error and warning message that the module can generate
(even the ones that will "never happen"), with a full explanation of
each problem, one or more likely causes, and any suggested remedies.

=head1 CONFIGURATION AND ENVIRONMENT

Configuration is passed in as a hashreference to the constructor,
either directly, or via Email::VirusScanner.

Required configuration settings are:

=over 4

=item socket_name

The full path to the clamd socket file

=back

Optional configuration settings are:

=over 4

=item zip_fallback

A reference to an instance of another Email::VirusScanner backend, to
be used if clamd returns 'Zip module failure'.  Typically, this will be
the ClamAV::ClamScan backend.

=back

=head1 DEPENDENCIES

L<IO::Socket::UNIX>, L<IO::Select>, L<Scalar::Util>, L<Cwd>,
L<Email::VirusScan::Result>,

=head1 AUTHOR

Dave O'Neill (dmo@roaringpenguin.com)

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

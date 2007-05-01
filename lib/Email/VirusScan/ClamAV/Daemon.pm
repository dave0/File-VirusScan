package Email::VirusScan::ClamAV::Daemon;
use strict;
use warnings;
use Carp;

use Email::VirusScan::Base;
use base qw( Email::VirusScan::Base );

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
		unless( blessed( $conf->{zip_fallback} ) && $conf->{fallback}->isa('Email::VirusScan::Base') ) {
			croak q{The 'zip_fallback' config value must be an object inheriting from Email::VirusScan::Base};
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

sub get_socket
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

sub scan
{
}

sub scan_path
{
	my ($self, $path) = @_;

	if( abs_path($path) ne $path ) {
		return Email::VirusScan::Result->error( "Path $path is not absolute" );
	}

	my $sock = eval { $self->get_socket };
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
 
Email::VirusScan::ClamAV::Daemon - <One line description of module's purpose>
 
=head1 SYNOPSIS
 
    use Email::VirusScan::ClamAV::Daemon;
    # Brief but working code example(s) here showing the most common usage(s)
 
    # This section will be as far as many users bother reading
    # so make it as educational and exemplary as possible.
  
=head1 DESCRIPTION
 
A full description of the module and its features.
May include numerous subsections (i.e. =head2, =head3, etc.) 
 
=head1 SUBROUTINES/METHODS 
 
A separate section listing the public components of the module's interface. 
These normally consist of either subroutines that may be exported, or methods
that may be called on objects belonging to the classes that the module provides.
Name the section accordingly.
 
In an object-oriented module, this section should begin with a sentence of the 
form "An object of this class represents...", to give the reader a high-level
context to help them understand the methods that are subsequently described.
 
=head1 DIAGNOSTICS
 
A list of every error and warning message that the module can generate
(even the ones that will "never happen"), with a full explanation of
each problem, one or more likely causes, and any suggested remedies.
 
=head1 CONFIGURATION AND ENVIRONMENT

A full explanation of any configuration system(s) used by the module,
including the names and locations of any configuration files, and the
meaning of any environment variables or properties that can be set.
These descriptions must also include details of any configuration
language used.
 
=head1 DEPENDENCIES

A list of all the other modules that this module relies upon, including
any restrictions on versions, and an indication whether these required
modules are part of the standard Perl distribution, part of the
module's distribution, or must be installed separately.

=head1 INCOMPATIBILITIES

A list of any modules that this module cannot be used in conjunction
with.  This may be due to name conflicts in the interface, or
competition for system or program resources, or due to internal
limitations of Perl (for example, many modules that use source code
filters are mutually incompatible).

There are no known incompatibilities with this module.
 
=head1 BUGS AND LIMITATIONS
 
There are no known bugs in this module. 
Please report problems to the author.
Patches are welcome.
 
=head1 AUTHOR
 
Dave O'Neill (dmo@roaringpenguin.com)
 
 
=head1 LICENCE AND COPYRIGHT
 
Copyright (c) 2007 Roaring Penguin Software, Inc.  All rights reserved.

package Email::VirusScan::Engine::Symantec::CSS;
use strict;
use warnings;
use Carp;

use Email::VirusScan::Engine;
use vars qw( @ISA );
@ISA = qw( Email::VirusScan::Engine );

use IO::Socket::INET;
use Cwd 'abs_path';

use Email::VirusScan::Result;

sub new
{
	my ($class, $conf) = @_;

	if( ! $conf->{host} ) {
		croak "Must supply a 'host' config value for $class";
	}

	my $self = {
		host     => $conf->{host},
		port     => $conf->{port}  || 7777,
		is_local => $conf->{is_local} || 1,
	};

	return bless $self, $class;
}

sub _get_socket
{
	my ($self) = @_;

	my $sock = IO::Socket::INET->new(
		PeerAddr => $self->{host},
		PeerPort => $self->{port},
	);
	if( ! defined $sock ) {
		croak "Error: Could not connect to CarrierScan Server on $self->{host}, port $self->{port}: $!";
	}

	# First reply line should be 220 code
	my $line = _read_line( $sock );
	unless ($line =~ /^220/) {
		croak "Error: Unexpected reply $line from CarrierScan Server";
	}

	# Next line must be version
	$line = _read_line( $sock );
	unless ($line eq '2') {
		croak "Error: Unexpected version $line from CarrierScan Server";
	}

	# OK, probably fine to use this sock
	return $sock;
}

sub scan_path
{
	my ($self, $path) = @_;

	if( abs_path($path) ne $path ) {
		return Email::VirusScan::Result->error( "Path $path is not absolute" );
	}

	my @files = eval { $self->list_files( $path ) };
	if( $@ ) {
		return Email::VirusScan::Result->error( $@ );
	}

	foreach my $file_path (@files) {
		my $result = $self->{is_local}
			? $self->_scan_path_local( $file_path )
			: $self->_scan_path_remote( $file_path );
		if( ! $result->is_clean() ) {
			return $result;
		}
	}
}

sub _scan_path_local
{
	my ($self, $path) = @_;

	my $sock = eval { $self->_get_socket };
	if( $@ ) {
		return Email::VirusScan::Result->error( $@ );
	}

	if( ! $sock->print("Version2\nAVSCANLOCAL\n$path\n") ) {
		my $err = $!;
		$sock->close;
		return Email::VirusScan::Result->error("Could not write to socket: $err");
	}

	if( ! $sock->flush ) {
		my $err = $!;
		$sock->close;
		return Email::VirusScan::Result->error("Error flushing socket: $err");
	}

	my $result = $self->_parse_server_response( $sock );
	$sock->close;
	return $result;
}

sub _scan_path_remote
{
	my ($self, $path) = @_;

	my $size = (stat($path))[7];
	unless(defined($size)) {
		return Email::VirusScan::Result->error("Cannot stat $path: $!");
	}

	my $sock = eval { $self->_get_socket };
	if( $@ ) {
		return Email::VirusScan::Result->error( $@ );
	}

	if( ! $sock->print("Version2\nAVSCAN\n$path\n$size\n") ) {
		my $err = $!;
		$sock->close;
		return Email::VirusScan::Result->error("Could not write to socket: $err");
	}

	my $fh = IO::File->new("<$path");
	if( ! $fh ) {
		return Email::VirusScan::Result->error("Cannot open $path: $!");
	}

	# Write file to socket
	while( $size > 0 ) {
		my $chunksize = ($size < 8192)
			? $size
			: 8192;

		my $chunk;
		my $nread = $fh->read($chunk, $chunksize);
		unless( defined $nread ) {
			my $err = $!;
			$sock->close;
			return Email::VirusScan::Result->error("Error reading $path: $err");
		}

		last if ($nread == 0);

		if( ! $sock->print( $chunk ) ) {
			my $err = $!;
			$sock->close;
			return Email::VirusScan::Result->error("Error writing to socket: $err");
		}

		$size -= $nread;
	}

	if( $size > 0 ) {
		my $err = $!;
		$sock->close;
		return Email::VirusScan::Result->error("Error reading $path: $err");
	}

	if( ! $sock->flush ) {
		my $err = $!;
		$sock->close;
		return Email::VirusScan::Result->error("Error flushing socket: $err");
	}

	my $result = $self->_parse_server_response( $sock );
	$sock->close;
	return $result;
}

sub _parse_server_response
{
	my ($self, $sock) = @_;

	# Get reply from server
	my $line = _read_line( $sock );

	unless( $line =~ /^230/ ) {
		return Email::VirusScan::Result->error("Unexpected response to AVSCAN or AVSCANLOCAL command: $line");
	}

	# Read infection status
	$line = _read_line( $sock );
	if( $line eq '0' ) {
		return Email::VirusScan::Result->clean();
	}

	# Skip next four lines:
	# 	- definition date
	# 	- definition version
	# 	- infection count
	# 	- filename
	$line = _read_line($sock);
	$line = _read_line($sock);
	$line = _read_line($sock);
	$line = _read_line($sock);

	# Get virus name
	$line = _read_line($sock);

	return Email::VirusScan::Result->virus($line);
}

sub _read_line
{
	my ($sock) = @_;

	chomp( my $line = $sock->getline );
	$line =~ s/\r//g;
	return $line;
}

1;
__END__

=head1 NAME

Email::VirusScan::Engine::Symantec::CSS - Email::VirusScan backend for scanning with Symantec CarrierScan Server

=head1 SYNOPSIS

    use Email::VirusScanner;
    my $s = Email::VirusScanner->new({
	engines => {
		'-Symantec::CSS' => {
			host => '127.0.0.1',
			port => 7777,
			is_local => 1,
		},
		...
	},
	...
}

=head1 DESCRIPTION

Email::VirusScan backend for scanning using Symantec CarrierScan Server

Inherits from, and follows the conventions of,
Email::VirusScan::Engine.  See the documentation of that module for
more information.

=head1 CLASS METHODS

=head2 new ( $conf )

Creates a new scanner object.  B<$conf> is a hashref containing:

=over 4

=item host

Required.

Host name or IP address of CarrierScan server

=item port

Optional.  Defaults to 7777

Port on which to connect to CarrierScan server

=item is_local

Optional.  Defaults to true.

If set, use AVSCANLOCAL to tell CarrierScan to scan the given path
directly.  If unset, use AVSCAN and transmit the file contents over the
socket for scanning.

=back

=head1 INSTANCE METHODS

=head2 scan_path ( $pathname )

Scan the path provided using CarrierScan.

Returns an Email::VirusScan::Result object.

=head1 DEPENDENCIES

L<IO::Socket::INET>, L<Cwd>,
L<Email::VirusScan::Result>,

=head1 AUTHOR

Dave O'Neill (dmo@roaringpenguin.com)

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

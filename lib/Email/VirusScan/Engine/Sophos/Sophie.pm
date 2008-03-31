package Email::VirusScan::Engine::Sophos::Sophie;
use strict;
use warnings;
use Carp;

use Email::VirusScan::Engine;
use vars qw( @ISA );
@ISA = qw( Email::VirusScan::Engine );

use IO::Socket::UNIX;
use Cwd 'abs_path';

use Email::VirusScan::Result;

sub new
{
	my ($class, $conf) = @_;

	if(!$conf->{socket_name}) {
		croak "Must supply a 'socket_name' config value for $class";
	}

	my $self = { socket_name => $conf->{socket_name}, };

	return bless $self, $class;
}

sub _get_socket
{
	my ($self) = @_;

	my $sock = IO::Socket::UNIX->new(Peer => $self->{socket_name});
	if(!defined $sock) {
		croak "Error: Could not connect to sophie daemon at $self->{socket_name}";
	}

	return $sock;
}

sub scan_path
{
	my ($self, $path) = @_;

	if(abs_path($path) ne $path) {
		return Email::VirusScan::Result->error("Path $path is not absolute");
	}

	my $sock = eval { $self->_get_socket };
	if($@) {
		return Email::VirusScan::Result->error($@);
	}

	if(!$sock->print("$path\n")) {
		$sock->close;
		return Email::VirusScan::Result->error("Could not get sophie to scan $path");
	}

	if(!$sock->flush) {
		$sock->close;
		return Email::VirusScan::Result->error("Could not get sophie to scan $path");
	}

	my $scan_response;
	my $rc = $sock->sysread($scan_response, 256);
	$sock->close();

	if(!$rc) {
		return Email::VirusScan::Result->error("Did not get response from sophie while scanning $path");
	}

	if($scan_response =~ m/^0/) {
		return Email::VirusScan::Result->clean();
	}

	if($scan_response =~ m/^1/) {
		my ($virus_name) = $scan_response =~ /^1:(.*)$/;
		$virus_name ||= 'Unknown-sophie-virus';
		return Email::VirusScan::Result->virus($virus_name);
	}

	if($scan_response =~ m/^-1:(.*)$/) {
		my $error_message = $1;
		$error_message ||= 'unknown error';
		return Email::VirusScan::Result->error($error_message);
	}

	return Email::VirusScan::Result->error('Unknown response from sophie');
}

1;
__END__

=head1 NAME

Email::VirusScan::Engine::Sophos::Sophie - Email::VirusScan backend for scanning with sophie

=head1 SYNOPSIS

    use Email::VirusScanner;
    my $s = Email::VirusScanner->new({
	engines => {
		'-Sophos::Sophie' => {
			socket_name => '/path/to/sophie.ctl',
		},
		...
	},
	...
}

=head1 DESCRIPTION

Email::VirusScan backend for scanning using Sophos's sophie daemon.

Email::VirusScan::Engine::Sophos::Sophie inherits from, and follows the
conventions of, Email::VirusScan::Engine.  See the documentation of
that module for more information.

=head1 CLASS METHODS

=head2 new ( $conf )

Creates a new scanner object.  B<$conf> is a hashref containing:

=over 4

=item socket_name

Required.

This must be a fully-qualified path to the sophie socket.  Currently,
only local sophie connections over a UNIX socket are supported.

=back

=head1 INSTANCE METHODS

=head2 scan_path ( $pathname )

Scan the path provided using sophie on a the configured local UNIX socket.

Returns an Email::VirusScan::Result object.

=head1 DEPENDENCIES

L<IO::Socket::UNIX>, L<Cwd>, L<Email::VirusScan::Result>,

=head1 SEE ALSO

L<http://www.clanfield.info/sophie/>
L<http://www.sophos.com>

=head1 AUTHOR

David Skoll (dfs@roaringpenguin.com)

Dave O'Neill (dmo@roaringpenguin.com)

Jason Englander

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

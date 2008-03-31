package Email::VirusScan::Engine::CommandAntivirus;
use strict;
use warnings;
use Carp;

use Email::VirusScan::Engine;
use vars qw( @ISA );
@ISA = qw( Email::VirusScan::Engine );

use IO::Socket::UNIX;
use IO::Select;
use Cwd 'abs_path';

use Email::VirusScan::Result;

sub new
{
	my ($class, $conf) = @_;

	if(!$conf->{command}) {
		croak "Must supply a 'command' config value for $class";
	}

	my $self = {
		command => $conf->{command},
		args    => [],
	};

	return bless $self, $class;
}

sub scan_path
{
	my ($self, $path) = @_;

	if(abs_path($path) ne $path) {
		return Email::VirusScan::Result->error("Path $path is not absolute");
	}

	my ($exitcode, $scan_response) = eval { $self->_run_commandline_scanner(join(' ', $self->{command}, @{ $self->{args} }, $path, '2>&1')); };

	if($@) {
		return Email::VirusScan::Result->error($@);
	}

	if(50 == $exitcode) {
		return Email::VirusScan::Result->clean();
	}

	if(5 == $exitcode) {
		return Email::VirusScan::Result->error('Scan interrupted');
	}

	if(101 == $exitcode) {
		return Email::VirusScan::Result->error('Out of memory');
	}

	if(52 == $exitcode) {

		# 52 == "suspicious" files
		return Email::VirusScan::Result->virus('suspicious-CSAV-files');
	}

	if(53 == $exitcode) {

		# Found and disinfected
		return Email::VirusScan::Result->virus('unknown-CSAV-virus disinfected');
	}

	if(51 == $exitcode) {
		my ($virus_name) = $scan_response =~ m/infec.*\: (\S+)/i;
		if(!$virus_name) {
			$virus_name = 'unknown-CSAV-virus';
		}
		return Email::VirusScan::Result->virus($virus_name);
	}

	# Other codes, bail out.
	return Email::VirusScan::Result->error("Unknown return code from Command Antivirus: $exitcode");
}

1;
__END__

=head1 NAME

Email::VirusScan::Engine::CommandAntivirus - Email::VirusScan backend for scanning with Command Antivirus

=head1 SYNOPSIS

    use Email::VirusScanner;
    my $s = Email::VirusScanner->new({
	engines => {
		'-CommandAntivirus' => {
			command => '/path/to/scan/command',
		},
		...
	},
	...
}

=head1 DESCRIPTION

Email::VirusScan backend for scanning using Authentium's Command Antivirus command-line scanner.

Email::VirusScan::Engine::CommandAntivirus inherits from, and follows the
conventions of, Email::VirusScan::Engine.  See the documentation of
that module for more information.

=head1 CLASS METHODS

=head2 new ( $conf )

Creates a new scanner object.  B<$conf> is a hashref containing:

=over 4

=item command

Fully-qualified path to the scan command.

=back

=head1 INSTANCE METHODS

=head2 scan_path ( $pathname )

Scan the path provided using the command provided to the constructor.
Returns an Email::VirusScan::Result object.

=head1 DEPENDENCIES

L<IO::Socket::UNIX>, L<IO::Select>, L<Scalar::Util>, L<Cwd>,
L<Email::VirusScan::Result>,

=head1 AUTHOR

Dave O'Neill (dmo@roaringpenguin.com)

David Skoll (dfs@roaringpenguin.com)

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

package Email::VirusScan::Engine::NAI::Uvscan;
use strict;
use warnings;
use Carp;

use Email::VirusScan::Engine;
use vars qw( @ISA );
@ISA = qw( Email::VirusScan::Engine );

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
		args    => [ '--mime', '--noboot', '--secure', '--allole' ],
	};

	return bless $self, $class;
}

sub scan_path
{
	my ($self, $path) = @_;

	if(abs_path($path) ne $path) {
		return Email::VirusScan::Result->error("Path $path is not absolute");
	}

	my ($exitcode, $scan_response) = eval { $self->_run_commandline_scanner(join(' ', $self->{command}, @{ $self->{args} }, $path, '2>&1'), qr/Found/,); };

	if($@) {
		return Email::VirusScan::Result->error($@);
	}

	if(0 == $exitcode) {
		return Email::VirusScan::Result->clean();
	}

	if(2 == $exitcode) {
		return Email::VirusScan::Result->error('Driver integrity check failed');
	}

	if(6 == $exitcode) {

		# "A general problem occurred" -- idiot Windoze
		# programmers... nothing else to do but pass it on
		return Email::VirusScan::Result->error('General problem occurred');
	}

	if(8 == $exitcode) {
		return Email::VirusScan::Result->error('Could not find a driver');
	}

	if(12 == $exitcode) {
		return Email::VirusScan::Result->error('Scanner tried to clean file, but failed');
	}

	if(13 == $exitcode) {

		# Finally, the virus-hit case
		#
		# TODO: what if more than one virus found?
		# TODO: can/should we capture infected filenames?

		# Sigh... stupid NAI can't have a standard message.  Go
		# through hoops to get virus name.
		$scan_response =~ s/ !+//;
		$scan_response =~ s/!+//;

		my $virus_name = '';

		for ($scan_response) {
			m/Found: EICAR test file/i && do {
				$virus_name = 'EICAR-Test';
				last;
			};
			m/^\s+Found the (\S+) .*virus/i && do {
				$virus_name = $1;
				last;
			};
			m/Found the (.*) trojan/i && do {
				$virus_name = $1;
				last;
			};
			m/Found .* or variant (.*)/i && do {
				$virus_name = $1;
				last;
			};
		}

		if($virus_name eq '') {
			$virus_name = 'unknown-NAI-virus';
		}

		return Email::VirusScan::Result->virus($virus_name);
	}

	if(19 == $exitcode) {
		return Email::VirusScan::Result->error('Self-check failed');
	}

	if(102 == $exitcode) {
		return Email::VirusScan::Result->error('User quit using --exit-on-error');
	}

	return Email::VirusScan::Result->error("Unknown return code from uvscan: $exitcode");
}

1;
__END__

=head1 NAME

Email::VirusScan::Engine::NAI::Uvscan - Email::VirusScan backend for scanning with uvscan

=head1 SYNOPSIS

    use Email::VirusScanner;
    my $s = Email::VirusScanner->new({
	engines => {
		'NAI::Uvscan' => {
			command => '/path/to/uvscan',
		},
		...
	},
	...
}

=head1 DESCRIPTION

Email::VirusScan backend for scanning using NAI's uvscan command-line scanner.

Email::VirusScan::Engine::NAI::Uvscan inherits from, and follows the
conventions of, Email::VirusScan::Engine.  See the documentation of
that module for more information.

=head1 CLASS METHODS

=head2 new ( $conf )

Creates a new scanner object.  B<$conf> is a hashref containing:

=over 4

=item command

Fully-qualified path to the 'uvscan' binary.

=back

=head1 INSTANCE METHODS

=head2 scan_path ( $pathname )

Scan the path provided using the command provided to the constructor.
Returns an Email::VirusScan::Result object.

=head1 DEPENDENCIES

L<Cwd>, L<Email::VirusScan::Result>,

=head1 SEE ALSO

L<http://www.nai.com/>

=head1 AUTHOR

David Skoll (dfs@roaringpenguin.com)

Dave O'Neill (dmo@roaringpenguin.com)

uvscan exit code information provided by Anthony Giggins

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

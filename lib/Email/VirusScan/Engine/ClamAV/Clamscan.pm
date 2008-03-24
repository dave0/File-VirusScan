package Email::VirusScan::Engine::ClamAV::Clamscan;
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
		args    => [ '--stdout', '--no-summary', '--infected' ],
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

	if(0 == $exitcode) {
		return Email::VirusScan::Result->clean();
	}

	if(1 == $exitcode) {

		# TODO: what if more than one virus found?
		# TODO: can/should we capture infected filenames?
		if($scan_response =~ m/: (.+) FOUND/) {
			return Email::VirusScan::Result->virus($1);
		} elsif($scan_response =~ m/: (.+) ERROR/) {
			my $err_detail = $1;
			return Email::VirusScan::Result->error("clamscan error: $err_detail");
		}
	}

	return Email::VirusScan::Result->error("Unknown return code from clamscan: $exitcode");
}

1;
__END__

=head1 NAME

Email::VirusScan::Engine::ClamAV::Clamscan - Email::VirusScan backend for scanning with clamscan

=head1 SYNOPSIS

    use Email::VirusScanner;
    my $s = Email::VirusScanner->new({
	engines => {
		'-ClamAV::Clamscan' => {
			command => '/path/to/clamscan',
		},
		...
	},
	...
}

=head1 DESCRIPTION

Email::VirusScan backend for scanning using ClamAV's clamscan command-line scanner.

This class inherits from, and follows the conventions of,
Email::VirusScan::Engine.  See the documentation of that module for
more information.

=head1 CLASS METHODS

=head2 new ( $conf )

Creates a new scanner object.  B<$conf> is a hashref containing:

=over 4

=item command

Fully-qualified path to the 'clamscan' binary.

=back

=head1 INSTANCE METHODS

=head2 scan_path ( $pathname )

Scan the path provided using the clamscan binary provided to the
constructor.  Returns an Email::VirusScan::Result object.

=head1 DEPENDENCIES

L<Cwd>, L<Email::VirusScan::Result>,

=head1 SEE ALSO

L<http://www.clamav.net/>

=head1 AUTHOR

David Skoll (dfs@roaringpenguin.com)
Dave O'Neill (dmo@roaringpenguin.com)

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

package File::VirusScan::Engine::FSecure::FSAV;
use strict;
use warnings;
use Carp;

use File::VirusScan::Engine;
use vars qw( @ISA );
@ISA = qw( File::VirusScan::Engine );

use Cwd 'abs_path';

use File::VirusScan::Result;

sub new
{
	my ($class, $conf) = @_;

	if(!$conf->{command}) {
		croak "Must supply a 'command' config value for $class";
	}

	my $self = {
		command => $conf->{command},
		args    => [ '--dumb', '--mime' ],
	};

	return bless $self, $class;
}

sub scan
{
	my ($self, $path) = @_;

	if(abs_path($path) ne $path) {
		return File::VirusScan::Result->error("Path $path is not absolute");
	}

	my ($exitcode, $scan_response) = eval { $self->_run_commandline_scanner(join(' ', $self->{command}, @{ $self->{args} }, $path, '2>&1')); };

	if($@) {
		return File::VirusScan::Result->error($@);
	}

	if(0 == $exitcode) {
		return File::VirusScan::Result->clean();
	}

	if(1 == $exitcode) {
		return File::VirusScan::Result->error('Abnormal termination');
	}

	if(2 == $exitcode) {
		return File::VirusScan::Result->error('Self-test failed');
	}

	if(3 == $exitcode || 6 == $exitcode) {
		my ($virus_name) = $scan_response =~ m/infec.*\: (\S+)/i;

		if($virus_name eq '') {
			$virus_name = 'unknown-FSAV-virus';
		}

		return File::VirusScan::Result->virus($virus_name);
	}

	if(8 == $exitcode) {

		# Suspicious files found
		return File::VirusScan::Result->virus('suspicious');
	}

	if(5 == $exitcode) {
		return File::VirusScan::Result->error('Scan interrupted');
	}

	if(7 == $exitcode) {
		return File::VirusScan::Result->error('Out of memory');
	}

	return File::VirusScan::Result->error("Unknown return code from fsav: $exitcode");
}

1;
__END__

=head1 NAME

File::VirusScan::Engine::FSecure::FSAV - File::VirusScan backend for scanning with fsav

=head1 SYNOPSIS

    use File::VirusScanner;
    my $s = File::VirusScanner->new({
	engines => {
		'-FSecure::FSAV' => {
			command => '/path/to/fsav',
		},
		...
	},
	...
}

=head1 DESCRIPTION

File::VirusScan backend for scanning using F-Secure's fsav command-line scanner.

File::VirusScan::Engine::FSecure::FSAV inherits from, and follows the
conventions of, File::VirusScan::Engine.  See the documentation of
that module for more information.

=head1 CLASS METHODS

=head2 new ( $conf )

Creates a new scanner object.  B<$conf> is a hashref containing:

=over 4

=item command

Fully-qualified path to the 'fsav' binary.

=back

=head1 INSTANCE METHODS

=head2 scan ( $pathname )

Scan the path provided using the command provided to the constructor.
Returns an File::VirusScan::Result object.

=head1 DEPENDENCIES

L<Cwd>, L<File::VirusScan::Result>,

=head1 SEE ALSO

L<http://www.f-secure.com/>

=head1 AUTHOR

David Skoll (dfs@roaringpenguin.com)

Dave O'Neill (dmo@roaringpenguin.com)

fsav exit code information provided by David Green

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

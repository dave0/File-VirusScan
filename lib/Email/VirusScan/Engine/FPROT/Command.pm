package Email::VirusScan::Engine::FPROT::Command;
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
		args    => [ '-DUMB', '-ARCHIVE', '-PACKED' ],
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
		return Email::VirusScan::Result->error('Unrecoverable error');
	}

	if(2 == $exitcode) {
		return Email::VirusScan::Result->error('Driver integrity check failed');
	}

	if(3 == $exitcode) {
		my ($virus_name) = $scan_response =~ m/Infection\: (\S+)/;
		$virus_name ||= 'unknown-FPROT-virus';
		return Email::VirusScan::Result->virus($virus_name);
	}

	if(5 == $exitcode) {
		return Email::VirusScan::Result->error('Abnormal scanner termination');
	}

	if(7 == $exitcode) {
		return Email::VirusScan::Result->error('Memory error');
	}

	if(8 == $exitcode) {
		return Email::VirusScan::Result->virus('FPROT-suspicious');
	}

	return Email::VirusScan::Result->error("Unknown return code: $exitcode");
}

1;
__END__

=head1 NAME

Email::VirusScan::Engine::FPROT::Command - Email::VirusScan backend for scanning with fprot

=head1 SYNOPSIS

    use Email::VirusScanner;
    my $s = Email::VirusScanner->new({
	engines => {
		'-FPROT::Command' => {
			command => '/path/to/fprot',
		},
		...
	},
	...
}

=head1 DESCRIPTION

Email::VirusScan backend for scanning using F-PROT's commandline scanner

This class inherits from, and follows the conventions of,
Email::VirusScan::Engine.  See the documentation of that module for
more information.

=head1 CLASS METHODS

=head2 new ( $conf )

Creates a new scanner object.  B<$conf> is a hashref containing:

=over 4

=item command

Required.

Path to scanner executable.

=back

=head1 INSTANCE METHODS

=head2 scan_path ( $pathname )

Scan the path provided using the configured command.

Returns an Email::VirusScan::Result object.

=head1 DEPENDENCIES

L<Cwd>, L<Email::VirusScan::Result>,

=head1 SEE ALSO

L<http://www.f-prot.com/>

=head1 AUTHOR

David Skoll (dfs@roaringpenguin.com)

Dave O'Neill (dmo@roaringpenguin.com)

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

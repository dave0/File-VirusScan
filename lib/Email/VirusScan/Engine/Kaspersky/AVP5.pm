package Email::VirusScan::Engine::Kaspersky::AVP5;
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

		# TODO: should /var/run/aveserver be hardcoded?
		args => [ '-s', '-p', '/var/run/aveserver' ],
	};

	return bless $self, $class;
}

sub scan_path
{
	my ($self, $path) = @_;

	if(abs_path($path) ne $path) {
		return Email::VirusScan::Result->error("Path $path is not absolute");
	}

	my ($exitcode, $scan_response) = eval { $self->_run_commandline_scanner(join(' ', $self->{command}, @{ $self->{args} }, $path, '2>&1'), 'INFECTED',); };

	if($@) {
		return Email::VirusScan::Result->error($@);
	}

	if(        0 == $exitcode
		|| 5 == $exitcode
		|| 6 == $exitcode)
	{

		# 0 == clean
		# 5 == disinfected
		# 6 == viruses deleted
		return Email::VirusScan::Result->clean();
	}

	if(1 == $exitcode) {

		# 1 == scan incomplete
		return Email::VirusScan::Result->error('Scanning interrupted');
	}

	if(        2 == $exitcode
		|| 4 == $exitcode)
	{

		# 2 == "modified or damaged virus"
		# 4 == virus
		my ($virus_name) = $scan_response =~ m/INFECTED (\S+)/;
		$virus_name ||= 'unknown-AVP5-virus';
		return Email::VirusScan::Result->virus($virus_name);
	}

	if(        3 == $exitcode
		|| 8 == $exitcode)
	{

		# 3 == "suspicious" object found
		# 8 == corrupt objects found (treat as suspicious
		return Email::VirusScan::Result->virus('AVP5-suspicious');
	}

	if(7 == $exitcode) {

		# 7 == AVPLinux corrupt or infected
		return Email::VirusScan::Result->error('AVPLinux corrupt or infected');
	}

	return Email::VirusScan::Result->error("Unknown return code from aveclient: $exitcode");
}

1;
__END__

=head1 NAME

Email::VirusScan::Engine::Kaspersky::AVP5 - Email::VirusScan backend for scanning with aveclient

=head1 SYNOPSIS

    use Email::VirusScanner;
    my $s = Email::VirusScanner->new({
	engines => {
		'-Kaspersky::AVP5' => {
			command => '/path/to/aveclient',
		},
		...
	},
	...
}

=head1 DESCRIPTION

Email::VirusScan backend for scanning using Kaspersky's aveclient command-line scanner.

This class inherits from, and follows the conventions of,
Email::VirusScan::Engine.  See the documentation of that module for
more information.

=head1 CLASS METHODS

=head2 new ( $conf )

Creates a new scanner object.  B<$conf> is a hashref containing:

=over 4

=item command

Fully-qualified path to the 'aveclient' binary.

=back

=head1 INSTANCE METHODS

=head2 scan_path ( $pathname )

Scan the path provided using the aveclient binary provided to the
constructor.  Returns an Email::VirusScan::Result object.

=head1 DEPENDENCIES

L<Cwd>, L<Email::VirusScan::Result>,

=head1 SEE ALSO

L<http://www.kaspersky.com/>

=head1 AUTHORS

David Skoll (dfs@roaringpenguin.com)

Dave O'Neill (dmo@roaringpenguin.com)

Enrico Ansaloni

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

package Email::VirusScan::Engine::CentralCommand::Vexira;
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
		args    => [ '-qqq', '--log=/dev/null', '--all-files', '-as' ],
	};

	return bless $self, $class;
}

sub scan_path
{
	my ($self, $path) = @_;

	if(abs_path($path) ne $path) {
		return Email::VirusScan::Result->error("Path $path is not absolute");
	}

	my ($exitcode, $scan_response) = eval { $self->_run_commandline_scanner(join(' ', $self->{command}, @{ $self->{args} }, $path, '2>&1'), qr/: (?:virus|iworm|macro|mutant|sequence|trojan) /,); };

	if($@) {
		return Email::VirusScan::Result->error($@);
	}

	if(        0 == $exitcode
		|| 9 == $exitcode)
	{

		# 0 == OK
		# 9 == Unknown file type (treated as "ok" for now)
		return Email::VirusScan::Result->clean();
	}

	if(        3 == $exitcode
		|| 5 == $exitcode)
	{
		return Email::VirusScan::Result->virus('vexira-password-protected-zip');
	}

	if(        1 == $exitcode
		|| 2 == $exitcode)
	{
		my ($virus_name) = $scan_response =~ m/: (?:virus|iworm|macro|mutant|sequence|trojan) (\S+)/;
		$virus_name ||= 'unknown-Vexira-virus';
		return Email::VirusScan::Result->virus($virus_name);
	}

	return Email::VirusScan::Result->error("Unknown return code from vexira: $exitcode");
}

1;
__END__

=head1 NAME

Email::VirusScan::Engine::CentralCommand::Vexira - Email::VirusScan backend for scanning with vexira

=head1 SYNOPSIS

    use Email::VirusScanner;
    my $s = Email::VirusScanner->new({
	engines => {
		'-CentralCommand::Vexira' => {
			command => '/path/to/vexira',
		},
		...
	},
	...
}

=head1 DESCRIPTION

Email::VirusScan backend for scanning using Central Command's Vexira command-line scanner.

Email::VirusScan::Engine::CentralCommand::Vexira inherits from, and follows the
conventions of, Email::VirusScan::Engine.  See the documentation of
that module for more information.

=head1 CLASS METHODS

=head2 new ( $conf )

Creates a new scanner object.  B<$conf> is a hashref containing:

=over 4

=item command

Fully-qualified path to the 'vexira' binary.

=back

=head1 INSTANCE METHODS

=head2 scan_path ( $pathname )

Scan the path provided using the vexira binary provided to the
constructor.  Returns an Email::VirusScan::Result object.

=head1 DEPENDENCIES

L<Cwd>, L<Email::VirusScan::Result>,

=head1 SEE ALSO

L<http://www.centralcommand.com/ts/dl/pdf/scanner_en_vexira.pdf>

=head1 AUTHOR

David Skoll (dfs@roaringpenguin.com)

Dave O'Neill (dmo@roaringpenguin.com)

John Rowan Littell

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

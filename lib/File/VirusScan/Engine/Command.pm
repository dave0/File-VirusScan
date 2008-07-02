package File::VirusScan::Engine::Command;
use strict;
use warnings;

use File::VirusScan::Engine;
use vars qw( @ISA );
@ISA = qw( File::VirusScan::Engine );

sub _run_commandline_scanner
{
	my ($self, $command, $match) = @_;

	$match = '.*' unless defined $match;

	my $fh = IO::File->new("$command |");
	unless ($fh) {
		die "Could not execute '$command': $!";
	}

	my $msg;
	while (<$fh>) {
		$msg .= $_ if /$match/oi;
	}
	$fh->close;

	return ($? >> 8, $msg);
}

1;

__END__

=head1 NAME

File::VirusScan::Engine::Command - File::VirusScan::Engine class for command-line scanners

=head1 SYNOPSIS

    use File::VirusScan::Engine::Command;
    @ISA = qw( File::VirusScan::Engine::Command );

=head1 DESCRIPTION

File::VirusScan::Engine::Command provides a base class and utility methods for
implementing File::VirusScan support for commandline virus scanners

=head1 INSTANCE METHODS

=head2 scan ( $path )

Generic scan() method.  Takes a pathname to scan.  Returns a
File::VirusScan::Result object which can be queried for status.

Generally, this will be implemented by the subclass.

=head1 UTILITY METHODS FOR SUBCLASSES

=head2 _run_commandline_scanner ( $command, $match )

Runs the command given by $command.  Returns the exit status of that
command, and a string containing any lines of output that match the
regular expression $match.

=head1 DEPENDENCIES

L<IO::File>, L<File::VirusScan::Engine>

=head1 AUTHOR

Dave O'Neill (dmo@roaringpenguin.com)

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2008 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

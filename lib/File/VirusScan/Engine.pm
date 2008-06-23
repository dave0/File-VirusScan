package File::VirusScan::Engine;
use strict;
use warnings;
use Carp;

use IO::Dir;
use IO::File;

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

sub list_files
{
	my ($self, $path) = @_;

	if(!-d $path) {
		return $path;
	}

	my $dir = IO::Dir->new($path);
	if(!$dir) {
		croak "Could not open directory $path: $!";
	}

	my @files;

	for my $name ($dir->read) {
		next if($name eq '.' || $name eq '..');
		my $full_name = "$path/$name";
		if(-f $full_name) {
			push @files, $full_name;
		} elsif(-d _ ) {
			push @files, $self->list_files($full_name);
		}
	}

	$dir->close;
	return @files;
}

1;
__END__

=head1 NAME

File::VirusScan::Engine - Engine class for File::VirusScan backends

=head1 SYNOPSIS

    use File::VirusScan::Engine;
    @ISA = qw( File::VirusScan::Engine );

=head1 DESCRIPTION

File::VirusScan::Engine provides a base class and utility methods for
implementing File::VirusScan support for various virus scanners.

=head1 INSTANCE METHODS

=head2 scan ( $path )

Generic scan() method.  Takes a pathname to scan.  Returns a
File::VirusScan::Result object which can be queried for status.

Generally, this will be implemented by the subclass.

=head1 UTILITY METHODS FOR SUBCLASSES

=head2 list_files ( $path )

Returns a list of all files below $path, recursing into directories.

Some scanners can only scan individual files, rather than understanding
directories themselves.  This gives us a lightweight way to find all
files for scanning.

Will die with "Could not open directory $path: $!" if directory cannot
be opened.

=head2 _run_commandline_scanner ( $command, $match )

Runs the command given by $command.  Returns the exit status of that
command, and a string containing any lines of output that match the
regular expression $match.

=head1 DEPENDENCIES

L<IO::Dir>, L<IO::File>

=head1 AUTHOR

Dave O'Neill (dmo@roaringpenguin.com)


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

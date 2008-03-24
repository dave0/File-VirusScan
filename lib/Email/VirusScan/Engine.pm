package Email::VirusScan::Engine;
use strict;
use warnings;
use Carp;

use Email::Abstract;
use Scalar::Util 'blessed';
use Cwd qw( abs_path cwd );
use IO::File;
use IO::Dir;
use File::Temp 'tempfile';

sub scan
{
	my ($self, $email) = @_;

	unless (blessed($email) && $email->isa('Email::Abstract')) {
		croak q{argument to scan() must be an Email::Abstract object};
	}

	my $path         = undef;
	my $tmpfile_used = 0;
	if($email->can('get_body_path')
		&& ($path = $email->get_body_path()))
	{
		if(abs_path($path) ne $path) {
			carp "Path $path is not absolute; qualifying with " . cwd();
			$path = abs_path($path);
		}
	} else {

		# No path... time to make one
		$tmpfile_used = 1;
		my $fh;
		($fh, $path) = tempfile();
		if(!$fh->print($email->as_string)) {
			$fh->close;
			croak q{Couldn't write email object to temp file};
		}

		if(!$fh->close) {
			croak "Couldn't close filehandle: $!";
		}
	}

	my $result = $self->scan_path($path);

	if($tmpfile_used) {
		if(!unlink $path) {
			carp "Couldn't unlink $path: $!";
		}
	}

	return $result;
}

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

Email::VirusScan::Engine - Engine class for Email::VirusScan backends

=head1 SYNOPSIS

    use Email::VirusScan::Engine;
    @ISA = qw( Email::VirusScan::Engine );

=head1 DESCRIPTION

Email::VirusScan::Engine provides a base class and utility methods for
implementing Email::VirusScan support for various virus scanners.

=head1 INSTANCE METHODS

=head2 scan ( $email )

Generic scan() method.  Takes an Email::Abstract object, finds its path
location or saves the contents to a file, and calls scan_path() on that
path.

May be overridden by subclass.

=head1 UTILITY METHODS FOR SUBCLASSES

=head2 list_files ( $path )

Returns a list of all files below $path, recursing into directories.

Some scanners can only scan individual files, rather than understanding
directories themselves.  This gives us a lightweight way to find all
files for scanning.

Will die with "Could not open directory $path: $!" if directory cannot
be opened.

=head1 CONFIGURATION AND ENVIRONMENT

=over 4

=item *

Uses File::Temp to generate tempfiles in $ENV{TMPDIR}, or /tmp if no
TMPDIR environment variable set.

=back

=head1 DEPENDENCIES

L<Email::Abstract>, L<Scalar::Util>, L<Cwd>, L<File::Temp>


=head1 AUTHOR

Dave O'Neill (dmo@roaringpenguin.com)


=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

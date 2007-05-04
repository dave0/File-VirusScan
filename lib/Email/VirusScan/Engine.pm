package Email::VirusScan::Engine;
use strict;
use warnings;
use Carp;

use Email::Abstract;
use Scalar::Util 'blessed';
use Cwd qw( abs_path cwd );
use File::Temp 'tempfile';

sub scan
{
	my ($self, $email) = @_; 

	unless( blessed( $email ) && $email->isa('Email::Abstract') ) {
		croak q{argument to scan() must be an Email::Abstract object};
	}

	my $path = undef;
	my $tmpfile_used = 0;
	if( $email->can('get_body_path') ) {
		# Good, it's a new enough Email::Abstract
		$path = $email->get_body_path();
		if( abs_path( $path ) ne $path ) {
			carp "Path $path is not absolute; qualifying with " . cwd();
			$path = abs_path($path);
		}
	} else {
		# No path... time to make one
		$tmpfile_used = 1;
		my $fh;
		($fh, $path) = tempfile();
		if( ! $fh->print( $email->as_string ) ) {
			$fh->close;
			croak q{Couldn't write email object to temp file};
		}

		if( ! $fh->close ) {
			croak "Couldn't close filehandle: $!";
		}
	}

	my $result = $self->scan_path( $path );

	if( $tmpfile_used ) {
		if( ! unlink $path ) {
			carp "Couldn't unlink $path: $!";
		}
	}

	return $result;
}

1;
__END__

=head1 NAME
 
Email::VirusScan::Engine - Engine class for Email::VirusScan backends
 
=head1 SYNOPSIS
 
    use Email::VirusScan::Engine;
    use base qw( Email::VirusScan::Engine );
  
=head1 DESCRIPTION

TODO
 
=head1 INSTANCE METHODS

=head2 scan ( $email )

Generic scan() method.  Takes an Email::Abstract object, finds its path
location or saves the contents to a file, and calls scan_path() on that
path.
 
=head1 DIAGNOSTICS
 
TODO A list of every error and warning message that the module can generate
(even the ones that will "never happen"), with a full explanation of
each problem, one or more likely causes, and any suggested remedies.
 
=head1 CONFIGURATION AND ENVIRONMENT

=over 4

=item * 

Uses File::Temp to generate tempfiles in $ENV{TMPDIR}, or /tmp if no
TMPDIR environment variable set.

=back
 
=head1 DEPENDENCIES

L<Email::Abstract>, L<Scalar::Util>, L<Cwd>, L<File::Temp>

=head1 INCOMPATIBILITIES

There are no known incompatibilities with this module.
 
=head1 BUGS AND LIMITATIONS
 
There are no known bugs in this module. 
Please report problems to the author.
Patches are welcome.
 
=head1 AUTHOR
 
Dave O'Neill (dmo@roaringpenguin.com)
 
 
=head1 LICENCE AND COPYRIGHT
 
Copyright (c) 2007 Roaring Penguin Software, Inc.  All rights reserved.

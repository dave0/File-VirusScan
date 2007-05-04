package Email::VirusScan;
use strict;
use warnings;
use Carp;

use Email::VirusScan::Result;
use Email::VirusScan::ResultSet;

our $VERSION = '0.002';

# We don't use Module::Pluggable.  Most users of this module will have
# one or two virus scanners, with the other half-dozen or so plugins
# going unused. 
sub new
{
	my ($class, $conf) = @_;

	if ( ! exists $conf->{engines} || ! scalar keys %{$conf->{engines}} ) {
		croak q{Must supply an 'engines' value to constructor};
	}

	my %backends;

	# Load and initialise our backend engines
	while( my ($backend, $backend_conf) = each %{ $conf->{engines} } ) {
		$backend =~ s/[^A-Za-z0-9_]//;
		my $backclass = "Email::VirusScan::Engine::$backend";
		eval qq{use $backclass;};  ## no critic(StringyEval)
		if( $@ ) {                 ## no critic(PunctuationVars)
			croak "Unable to find class $backclass for backend '$backend'";
		}

		$backends{$backend} = $backclass->new( $backend_conf );
	}

	my $self = {
		always_scan => $conf->{always_scan},
	};
	
	if( exists $conf->{order} ) {
		$self->{_backends} = [ @backends{ @{$conf->{order}} } ];
	} else {
		$self->{_backends} = [ values %backends ];
	}

	return bless $self, $class;
}

sub scan
{
	my ($self, $ea) = @_;

	my $result = Email::VirusScan::ResultSet->new();
	
	for my $back ( @{$self->{_backends}} ) {
		$result->add(
			$back->scan( $ea )
		);
		if( ! $self->{always_scan}
		    && $result->has_virus() ) {
			last;
		}
	}

	return $result;
}

sub scan_path
{
	my ($self, $path) = @_;

	my $result = Email::VirusScan::ResultSet->new();
	
	for my $back ( @{$self->{_backends}} ) {
		$result->add(
			$back->scan_path( $path )
		);
		if( ! $self->{always_scan}
		    && $result->has_virus() ) {
			last;
		}
	}

	return $result;
}

1;
__END__

=head1 NAME
 
Email::VirusScan - Unified interface for virus scanning of email messages
 
=head1 SYNOPSIS

    my $scanner = Email::VirusScan->new({
	engines => {
		'ClamAV::Daemon' => {
			socket_name => '/var/run/clamav/clamd.ctl',
		},
		'FSecure' => {
			path   => '/usr/local/bin/fsav
		},
		'FProtD' => {
			host   => '127.0.0.1',
			port   => 10200,
		}

	},

	order => [ 'ClamAV::Daemon', 'FProtD', 'FSecure' ],

	always_scan => 0,
    });

    my $mail = Email::Abstract->new( $some_mail_object );

    my $result = $scanner->scan( $mail );

    if( $result->is_clean ) {
	return 'Happiness and puppies!';
    } else {
	return 'Oh noes!  You've got ' . join(',' @{ $result->virus_names } );
    }

=head1 DESCRIPTION

This class provides a common API for scanning email objects with one or
more third party (ie: not yours, not mine) virus scanners.

=head1 METHODS

=head2 new ( { config data } ) 

Creates a new Email::VirusScan object, using configuration data in the
provided hashref. 

Required configuration options are:

=over 4

=item engines

Reference to hash of backend virus scan engines to be used, and their
specific configurations. 

Keys should be the class name of a L<Email::VirusScan::Engine> subclass,
with the L<Email::VirusScan::Engine> prefix removed.

Values should be another hash reference containing engine-specific
configuration.  This will vary by backend, but generally requires at
minimum some way of locating (socket path, host/port) or executing
(path to executable) the scanner.

=back

Optional configuration options are:

=over 4

=item order

List reference containing keys provided to B<engines> above, in the
order in which they should be called.

If omitted, backends will be invoked in hash key order.

=item always_scan

By default, Email::VirusScan will stop scanning a message after one
backend finds a virus.  If you wish to run all backends anyway, set
this option to a true value.

=back

=head2 scan ( $mail_object )

Invokes the configured scan backends on an Email::Abstract object.  Use
this if you have a Perl representation of a mail message, and you trust
your virus scanner to Do The Right Thing with a serialized
representation of it.

Returns an Email::VirusScan::Result object, which can be queried for status.

=head2 scan_path ( $directory )

Invokes the configured scan backends on the contents of the directory.
Use this if you have more than one message you wish to scan, or if you
just plain don't trust your virus scanning engine to properly unpack a
message and scan its subparts, and wish to do it yourself first.

Returns an Email::VirusScan::result object, which can be queried for status.
 
=head1 DEPENDENCIES

L<Email::Abstract>, L<Email::VirusScan::Engine>, L<Email::VirusScan::Result>

=head1 INCOMPATIBILITIES

There are no known incompatibilities with this module.
 
=head1 BUGS AND LIMITATIONS
 
There are no known bugs in this module. 
Please report problems to the author.
Patches are welcome.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Email::VirusScan 

You can also look for information at:

=over 4

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Email-VirusScan>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Email-VirusScan>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Email-VirusScan>

=item * Search CPAN

L<http://search.cpan.org/dist/Email-VirusScan>

=back
 
=head1 AUTHOR
 
Dave O'Neill (dmo@roaringpenguin.com)
David Skoll  (dfs@roaringpenguin.com>
 
=head1 LICENCE AND COPYRIGHT

Copyright 2007 Roaring Penguin Software

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

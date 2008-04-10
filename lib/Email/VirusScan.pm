package Email::VirusScan;
use strict;
use warnings;
use Carp;

use Email::VirusScan::Result;
use Email::VirusScan::ResultSet;

our $VERSION = '0.011_01';

# We don't use Module::Pluggable.  Most users of this module will have
# one or two virus scanners, with the other half-dozen or so plugins
# going unused, so there's no sense in finding/loading all plugins.
sub new
{
	my ($class, $conf) = @_;

	if(!exists $conf->{engines} || !scalar keys %{ $conf->{engines} }) {
		croak q{Must supply an 'engines' value to constructor};
	}

	my %backends;

	# Load and initialise our backend engines
	while (my ($moniker, $backend_conf) = each %{ $conf->{engines} }) {

		$moniker =~ s/[^-A-Za-z0-9_:]//;
		my $backclass = $moniker;

		substr($backclass, 0, 1, 'Email::VirusScan::Engine::') if substr($backclass, 0, 1) eq '-';

		eval qq{use $backclass;};  ## no critic(StringyEval)
		if($@) {                   ## no critic(PunctuationVars)
			croak "Unable to find class $backclass for backend '$moniker'";
		}

		$backends{$moniker} = $backclass->new($backend_conf);
	}

	my $self = { always_scan => $conf->{always_scan}, };

	if(exists $conf->{order}) {
		$self->{_backends} = [ @backends{ @{ $conf->{order} } } ];
	} else {
		$self->{_backends} = [ values %backends ];
	}

	return bless $self, $class;
}

sub scan
{
	my ($self, $ea) = @_;

	my $result = Email::VirusScan::ResultSet->new();

	for my $back (@{ $self->{_backends} }) {

		my $scan_result = eval { $back->scan($ea) };

		if($@) {
			$result->add(Email::VirusScan::Result->error("Error calling ->scan(): $@"));
		} else {
			$result->add($scan_result);
		}

		if(!$self->{always_scan}
			&& $result->has_virus())
		{
			last;
		}
	}

	return $result;
}

sub scan_path
{
	my ($self, $path) = @_;

	my $result = Email::VirusScan::ResultSet->new();

	for my $back (@{ $self->{_backends} }) {

		my $scan_result = eval { $back->scan_path($path) };

		if($@) {
			$result->add(Email::VirusScan::Result->error("Error calling ->scan(): $@"));
		} else {
			$result->add($scan_result);
		}

		if(!$self->{always_scan}
			&& $result->has_virus())
		{
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
more third party virus scanners.

Virus scanners are supported via pluggable engines under the
L<Email::VirusScan::Engine> namespace.  At the time of this release,
the following plugins are shipped with Email::VirusScan:

=over 4

=item Clam Antivirus

Scanning daemon via L<Email::VirusScan::Engine::ClamAV::Daemon>, and
commandline scanner via L<Email::VirusScan::Engine::ClamAV::Clamscan>

=item NAI UVScan

L<Email::VirusScan::Engine::NAI::Uvscan>

=item F-Secure FSAV

L<Email::VirusScan::Engine::FSecure::FSAV>

=item Trend Micro Vscan

L<Email::VirusScan::Engine::Trend::Vscan>

=item BitDefender BDC

L<Email::VirusScan::Engine::BitDefender::BDC>

=item Command Antivirus

L<Email::VirusScan::Engine::CommandAntivirus>

=item Norman Antivirus

L<Email::VirusScan::Engine::Norman::NVCC>

=item ESET

Scanning via esets_cli with L<Email::VirusScan::Engine::ESET::NOD32>

=item Symantec

Scanning via Carrier Scan server with L<Email::VirusScan::Engine::Symantec::CSS>

=item F-PROT

Scanning daemon via L<Email::VirusScan::Engine::FPROT::Daemon>, and
commandline scanner via L<Email::VirusScan::Engine::FPROT::Command>

=item Central Command Vexira

L<Email::VirusScan::Engine::CentralCommand::Vexira>

=item Sophos

Daemonized scanning using the Sophie daemon with
L<Email::VirusScan::Engine::Sophos::Sophie>.  Commandline scanning with
L<Email::VirusScan::Engine::Sophos::Sweep> or
L<Email::VirusScan::Engine::Sophos::Savscan>

=item Kaspersky

Scanning with aveserver using
L<Email::VirusScan::Engine::Kaspersky::AVP5>, or with kavscanner using
L<Email::VirusScan::Engine::Kaspersky::Kavscanner>

=back

=head1 METHODS

=head2 new ( { config data } )

Creates a new Email::VirusScan object, using configuration data in the
provided hashref.

Required configuration options are:

=over 4

=item engines

Reference to hash of backend virus scan engines to be used, and their
specific configurations.

Keys must refer to a class that implements the
L<Email::VirusScan::Engine> interface, and may be specified as either:

=over 4

=item 1.

A fully-qualified class name.

=item 2.

A name beginning with '-', in which case the '-' is removed and replaced with the L<Email::VirusScan::Engine>:: prefix.

=back

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

=head1 AUTHOR

Dave O'Neill (dmo@roaringpenguin.com)

David Skoll  (dfs@roaringpenguin.com>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

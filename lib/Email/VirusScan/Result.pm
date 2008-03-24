package Email::VirusScan::Result;
use strict;
use warnings;
use Carp;

sub new
{
	my ($class, $args) = @_;
	my $self = {

		# TODO: really should be a subclass instead of is_whatever
		is_virus => $args->{is_virus} || 0,
		is_error => $args->{is_error} || 0,
		data     => $args->{data},
	};
	return bless $self, $class;
}

sub error
{
	my ($class, $err) = @_;
	return $class->new(
		{
			is_error => 1,
			data     => $err,
		}
	);
}

sub virus
{
	my ($class, $vname) = @_;
	return $class->new(
		{
			is_virus => 1,
			data     => $vname,
		}
	);
}

sub clean
{
	my ($class) = @_;
	return $class->new({});
}

sub is_virus
{
	my ($self) = @_;
	return $self->{is_virus};
}

sub is_error
{
	my ($self) = @_;
	return $self->{is_error};
}

sub is_clean
{
	my ($self) = @_;
	return !($self->{is_virus} || $self->{is_error});
}

sub get_data
{
	my ($self) = @_;
	return $self->{data};
}

1;
__END__

=head1 NAME

Email::VirusScan::Result - <One line description of module's purpose>

=head1 SYNOPSIS

    use Email::VirusScan::Result;

    # It's good
    return Email::VirusScan::Result->clean();

    # It's bad
    return Email::VirusScan::Result->virus( 'MyDoom' );

    # It's ugly (er, an error)
    return Email::VirusScan::Result->error( "Could not execute virus scanner: $!" );

    # And, in the caller....
    if( $result->is_error() ) {
	...
    } elsif ( $result->is_virus() ) {
	...
    }

=head1 DESCRIPTION

Encapsulate all return data from a virus scan.  Currently, just holds
clean/virus/error status, along with a virus name or error message.

=head1 CLASS METHODS

=head2 clean ( )

Create a new object, with no flags set and no data.

=head2 error ( $error_message )

Create a new object with is_error flag set, and data set to
$error_message.

=head2 virus ( $virusname )

Create a new object with is_virus flag set, and data set to $virusname.

=head2 new ( \%data )

Main constructor.

=head1 INSTANCE METHODS

=head2 is_clean ( )

Returns true if neither is_error nor is_virus was set.

=head2 is_error ( )

Returns true if is_error flag was set by constructor.

=head2 is_virus ( )

Returns true if is_virus flag was set by constructor.

=head2 get_data ( )

Return data value.

=head1 AUTHOR

Dave O'Neill (dmo@roaringpenguin.com)

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2007 Roaring Penguin Software, Inc.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

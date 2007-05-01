package Email::VirusScan::Result;
use strict;
use warnings;
use Carp;

sub new
{
	my ($class, $args) = @_;
	my $self = {
		# TODO: really should be a subclass instead of is_whatever
		is_virus    => $args->{is_virus} || 0,
		is_error    => $args->{is_error} || 0,
		data        => $args->{data},
	};
	return bless $self, $class;
}

sub error
{
	my ($class, $err) = @_;
	return $class->new({
		is_error => 1,
		data     => $err,
	});
}

sub virus
{
	my ($class, $vname) = @_;
	return $class->new({
		is_virus => 1,
		data     => $vname,
	});
}

sub clean
{
	my ($class) = @_;
	return $class->new({});
}

sub is_virus
{
	my ($self) = @_;
	return $self->{is_virus}
}

sub is_error
{
	my ($self) = @_;
	return $self->{is_error}
}

sub is_clean
{
	my ($self) = @_;
	return !($self->{is_virus} || $self->{is_error} );
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
    # Brief but working code example(s) here showing the most common usage(s)
 
    # This section will be as far as many users bother reading
    # so make it as educational and exemplary as possible.
  
=head1 DESCRIPTION
 
A full description of the module and its features.
May include numerous subsections (i.e. =head2, =head3, etc.) 
 
=head1 SUBROUTINES/METHODS 
 
A separate section listing the public components of the module's interface. 
These normally consist of either subroutines that may be exported, or methods
that may be called on objects belonging to the classes that the module provides.
Name the section accordingly.
 
In an object-oriented module, this section should begin with a sentence of the 
form "An object of this class represents...", to give the reader a high-level
context to help them understand the methods that are subsequently described.
 
=head1 DIAGNOSTICS
 
A list of every error and warning message that the module can generate
(even the ones that will "never happen"), with a full explanation of
each problem, one or more likely causes, and any suggested remedies.
 
=head1 CONFIGURATION AND ENVIRONMENT

A full explanation of any configuration system(s) used by the module,
including the names and locations of any configuration files, and the
meaning of any environment variables or properties that can be set.
These descriptions must also include details of any configuration
language used.
 
=head1 DEPENDENCIES

A list of all the other modules that this module relies upon, including
any restrictions on versions, and an indication whether these required
modules are part of the standard Perl distribution, part of the
module's distribution, or must be installed separately.

=head1 INCOMPATIBILITIES

A list of any modules that this module cannot be used in conjunction
with.  This may be due to name conflicts in the interface, or
competition for system or program resources, or due to internal
limitations of Perl (for example, many modules that use source code
filters are mutually incompatible).

There are no known incompatibilities with this module.
 
=head1 BUGS AND LIMITATIONS
 
There are no known bugs in this module. 
Please report problems to the author.
Patches are welcome.
 
=head1 AUTHOR
 
Dave O'Neill (dmo@roaringpenguin.com)
 
 
=head1 LICENCE AND COPYRIGHT
 
Copyright (c) 2007 Roaring Penguin Software, Inc.  All rights reserved.

package Email::VirusScan::ResultSet;
use strict;
use warnings;
use Carp;

sub new
{
	my ($class, $args) = @_;
	my $self = {
		results => [],
	};
	return bless $self, $class;
}

sub add
{
	my ($self, $result) = @_; 
	push @{ $self->{results} }, $result;
}

sub is_virus
{
	my ($self) = @_;

	if( grep { $_->is_virus } @{$self->{results}} ) {
		return 1;
	}
	return 0;
}

sub is_error
{
	my ($self) = @_;

	if( grep { $_->is_error } @{$self->{results}} ) {
		return 1;
	}
	return 0;
}

sub is_clean
{
	my ($self) = @_;

	if( grep { $_->is_error || $_->is_virus } @{$self->{results}} ) {
		return 0;
	}
	return 1;
}

sub get_errors
{
	my ($self) = @_; 
	return [
		map { $_->get_data }
		    grep { $_->is_error }
		        @{ $self->{results} }
	]
}

1;
__END__

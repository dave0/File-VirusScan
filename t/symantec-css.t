package TestVirusScan::Symantec::CSS;
use strict;
use warnings;

use lib qw( t/lib );
use base qw( TestVirusPlugin );

use Test::More;
use Test::Exception;
use File::Temp ();

use Email::VirusScan::Engine::Symantec::CSS;

sub under_test { 'Email::VirusScan::Engine::Symantec::CSS' };
sub required_arguments {
	{ 
		host => '127.0.0.1',
		port => 7779
	}
}

sub testable_live
{
	my ($self) = @_;

	# Only testable if socket is a CSS server
	eval { $self->engine->_get_socket() };
	return ( ! $@ );
}

sub constructor_failures : Test(2)
{
	my ($self) = @_;

	dies_ok { $self->under_test->new() } 'Constructor dies with no arguments';
	like( $@, qr/Must supply a 'host' config value/, ' ... error as expected');
}

sub bogus_socket : Test(2)
{
	my ($self) = @_;

	my $s = $self->engine();

	$s->{port} = 1;

	dies_ok { $s->_get_socket() } '_get_socket() dies (invalid port given)';
	like( $@, qr/Error: Could not connect to CarrierScan Server on 127.0.0.1, port 1: Connection refused/, '... error as expected');
}

sub good_socket : Test(1)
{
	my ($self) = @_;
	my $s = $self->engine();

	return "Could not run live test" if ! $self->testable_live;

	my $sock;
	lives_ok { $sock = $s->_get_socket() } 'Real socket can be spoken to';
	$sock->close;
}

sub list_files : Test(8)
{
	my ($self) = @_;
	my $s = $self->engine();

	my $dir = File::Temp::tempdir( CLEANUP => 1 );	

	my @files = $s->_list_files( $dir );
	is( scalar @files, 0, 'Empty list from empty directory');

	`touch $dir/file1`; # I am lazy
	@files = $s->_list_files( $dir );
	is( scalar @files, 1, 'Single file in directory');
	is( $files[0], "$dir/file1", '... with correct name');

	@files = $s->_list_files( "$dir/file1" );
	is( scalar @files, 1, 'One in list from filename instead of directory');
	is( $files[0], "$dir/file1", '... with correct name');

	mkdir "$dir/subdir";
	mkdir "$dir/subdir/subsubdir";
	`touch $dir/subdir/subsubdir/file2`; # I am stil lazy
	@files = $s->_list_files( $dir );
	is( scalar @files, 2, 'Two files total below directory');
	is( $files[0], "$dir/file1", '... correct name for first');
	is( $files[1], "$dir/subdir/subsubdir/file2", '... correct name for second');
}

__PACKAGE__->runtests() unless caller();
1;

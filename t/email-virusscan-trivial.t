use Test::More tests => 5;
use Test::Exception;

BEGIN { use_ok('Email::VirusScan') }

dies_ok { Email::VirusScan->new() } 'Constructor dies with no arguments';
like( $@, qr/Must supply an 'engines' value to constructor/, '... error as expected');


dies_ok { Email::VirusScan->new({ engines => { wookie => {} }}) } 'Constructor dies with bogus engine';
like( $@, qr/Unable to find class Email::VirusScan::wookie for backend 'wookie'/, '... error as expected');

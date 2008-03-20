use strict;
use warnings;
use inc::Module::Install;

name	 'Email-VirusScan';
all_from 'lib/Email/VirusScan.pm';

build_requires 'Test::More';
build_requires 'Test::Class';
build_requires 'Test::Exception';


requires 'File::Temp';
requires 'IO::File';
requires 'IO::Dir';
requires 'Scalar::Util';
requires 'Email::Abstract';
requires 'Data::ResultSet';

# Required for some scanners, but not all
recommends 'IO::Socket::INET';
recommends 'IO::Socket::UNIX';
recommends 'IO::Select';

WriteAll;

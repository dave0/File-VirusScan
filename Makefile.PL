use strict;
use warnings;
use inc::Module::Install;

name	 'Email-VirusScan';
all_from 'lib/Email/VirusScan.pm';

build_requires 'Test::More'      => 0;

requires 'File::Temp'      => 0;
requires 'Scalar::Util'    => 0;
requires 'Email::Abstract' => 0;
requires 'Data::ResultSet' => 0;

auto_install;
WriteAll;

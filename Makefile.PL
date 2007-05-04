use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Email::VirusScan',
    AUTHOR              => q{Dave O'Neill <dmo@roaringpenguin.com>},
    VERSION_FROM        => 'lib/Email/VirusScan.pm',
    ABSTRACT_FROM       => 'lib/Email/VirusScan.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
	'File::Temp'=> 0,
	'Scalar::Util' => 0,
	'Email::Abstract' => 0,
	'Data::ResultSet' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Email-VirusScan-*' },
);

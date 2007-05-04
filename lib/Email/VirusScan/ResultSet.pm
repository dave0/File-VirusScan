package Email::VirusScan::ResultSet;
use strict;
use warnings;
use base qw( Data::ResultSet );

__PACKAGE__->make_wrappers( qw( is_virus is_error ) );

1;
__END__

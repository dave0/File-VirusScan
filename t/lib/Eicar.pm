package Eicar;

use Email::Abstract;

sub eicar_message
{
	my $msg = <<'END';
From: <>
To: undisclosed-recipients;
Subject: EICAR test
Date: Tue, 11 Mar 2008 13:59:31 -0400
Message-ID: <asdfasdf1234@Localhost>
Content-Type: multipart/mixed; boundary="EuxKj2iCbKjpUGkD"

--EuxKj2iCbKjpUGkD
Content-Type: text/plain; charset=us-ascii
Content-Disposition: inline

Attachment contains sample EICAR virus


--EuxKj2iCbKjpUGkD
Content-Type: text/plain; charset=us-ascii
Content-Disposition: attachment; filename=virus

END

	$msg .= 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EIC';
	$msg .= 'AR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
	$msg .= <<'END';

--EuxKj2iCbKjpUGkD--
END

	return Email::Abstract->new($msg);
}

1;

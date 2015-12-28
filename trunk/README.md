=OTPHP=

<wiki:toc max_depth="2" />

==Synopsis==

OTPHP is an object-oriented one-time password authentication library written
in PHP. Its OTP generation algorithm is compliant with RFC 4226,
HMAC-Based One-time Password algorithm, or HOTP. It stores client information
in SQLite databases with secure field-level encryption and secures authentication requests
with RSA asymmetic encryption. It is designed to integrate easily into existing systems
with a minimum of configuration.


==Dependencies==

PHP v5.3 or greater with support for OpenSSL and SQLite v3 (via PDO) enabled on both the client and server
  * If the Authserver.php and Authclient.php classes are used, sockets must also be enabled for PHP

==Package Manifest==
{{{
./
	install.php - The OTPHP install script (use for simple generation of secure keys and passwords and initialization of the server-side database)
	Readme.md - This file

./doc
	INSTALL - Installation and integration documentation
	TESTING - Unit testing documentation
	COPYING - GPL v3 license
	COPYING.LESSER - LGPL v3 license

./tests
	OTPServerTest.php - The PHPUnit unit test for OTPServer.php
	ClientEntityTest.php - The PHPUnit unit test for ClientEntity.php

./lib
	OTPServer.php - The authentication server class
		Functions:
			-Client authentication
			-Client creation

	OTPClient.php - The authentication client class
		Functions:
			-Authentication to server

	ClientEntity.php - The client database entity class
		Functions:
			-OTP password generation
			-Client database CRUD functions
			-Client ID generation

	AuthServer.php - A simple socket-based network wrapper for OTPServer.php
	AuthClient.php - A simple socket-based network wrapper for OTPClient.php
}}}
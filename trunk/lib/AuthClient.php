<?php
/**
 * AuthClient.php
 * $Id$
 *
 * A simple network-based authentication server to demonstrate the authentication capabilities of OTPHP
 *
 * @link https://code.google.com/p/f2-otphp/
 * @package OTPHP
 *
 * @license http://www.gnu.org/licenses/lgpl-3.0-standalone.html
 * Please see the COPYING and COPYING.LESSER files in the doc/ directory or the url above for full copyright and license information.
 * @copyright Copyright 2013 F2 Developments, Inc.
 *
 * @author Robin Klingsberg <rklingsberg@f2dev.com>
 * @author $LastChangedBy$
 *
 * @version $Revision$
 */

namespace F2Dev\OTPHP;

class AuthClient
{
	/**
	 * @constant The maximum number of bytes the auth client is willing to recieve in one stream
	 */
	const MAX_RECV_BYTES = 512;

	/**
	 * @var OTPClient	The OTPClient
	 */
	private $_o_AuthEngine;

	/**
	 * @param string	$s_ConfigPath	The path to the client's configuration file
	 */
	public function __construct($s_ConfigPath)
	{
		$this->_o_AuthEngine = new OTPClient($s_ConfigPath);

		$this->_s_ServerAddress = 'localhost';
		$this->_s_ServerPort = '8080';
	}

	/**
	 * @param string	$s_Password	(optional) The password to authenticate with (default: generated password from OTPClient)
	 */
	public function authenticate($s_Password = '')
	{
		$r_Socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

		if (false === $r_Socket)
		{
			$this->_socketError(__LINE__);
		}

		if (false === socket_connect($r_Socket, $this->_s_ServerAddress, $this->_s_ServerPort))
		{
			$this->_socketError(__LINE__);
		}

		$s_Password = (empty($s_Password))? $this->_o_AuthEngine->password : $s_Password;

		$s_AuthString = $this->_o_AuthEngine->id.'::'.$s_Password."\n";

		if (false === socket_write($r_Socket, $s_AuthString))
		{
			$this->_socketError(__LINE__);
		}

		for ($i = 0; $i < self::MAX_RECV_BYTES; $i++)
		{
			$c_Response = socket_read($r_Socket, 1);

			if (false === $c_Response)
			{
				$this->_socketError((__LINE__ - 2));
			}

			if ("\n" == $c_Response)
			{
				break;
			}

			$s_Response .= $c_Response;
		}

		switch (trim($s_Response))
		{
			case OTPClient::AUTH_SUCCESS:
				echo "Authentication succeeded with password $s_Password\n\n";
				break;
			case OTPClient::AUTH_RETRY:
				echo "Authentication failed with password $s_Password, retrying...\n\n";
				$this->authenticate();
				break;
			case OTPClient::AUTH_FAIL:
				echo "Authentication failed with password $s_Password, no more retries permitted\n\n";
				break;
			case OTPClient::CLIENT_DISABLED:
				echo "Authentication failed, client disabled\n\n";
				break;
			default:
				echo "Unrecognized response: '$s_Response'\n";
				break;
		}
	}

	private function _socketError($i_Line)
	{
		die(socket_strerror(socket_last_error())." --- $i_Line\n");
	}
}
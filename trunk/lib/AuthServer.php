<?php
/**
 * AuthServer.php
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

class AuthServer
{
	/**
	 * @constant The maximum number of bytes the auth server is willing to have at one time
	 */
	const MAX_CLIENTS = 20;

	/**
	 * @constant The maximum number of bytes the server is willing to recieve in one stream
	 */
	const MAX_RECV_BYTES = 512;

	/**
	 * @var OTPServer	The OTPServer
	 */
	private $_o_AuthEngine;

	/**
	 * @var resource	The server's listening socket
	 */
	private $_r_Socket;

	/**
	 * @param string	$s_ConfigPath	The path to the OTP server's configuration file
	 */
	public function __construct($s_ConfigPath)
	{
		$this->_o_AuthEngine = new OTPServer($s_ConfigPath);

		$this->_s_Address = 'localhost';
		$this->_s_Port = '8080';

		$this->run();
	}

	public function __destruct()
	{
		socket_close($this->_r_Socket);
	}

	public function run()
	{
		set_time_limit(0);
		ob_implicit_flush();

		$this->_r_Socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);

		if (false === $this->_r_Socket)
		{
			$this->_socketError(__LINE__);
		}

		if (false === socket_bind($this->_r_Socket, $this->_s_Address, $this->_s_Port))
		{
			$this->_socketError(__LINE__);
		}

		if (false === socket_listen($this->_r_Socket, self::MAX_CLIENTS))
		{
			$this->_socketError(__LINE__);
		}

		if (false === socket_set_block($this->_r_Socket))
		{
			$this->_socketError(__LINE__);
		}

		while(true)
		{
			$r_Connection = socket_accept($this->_r_Socket);

			if (false === $r_Connection)
			{
				$this->_socketError(__LINE__);
			}

			for ($i = 0; $i < self::MAX_RECV_BYTES; $i++)
			{
				$c_Data = socket_read($r_Connection, 1);

				if (false === $c_Data)
				{
					$this->_socketError(__LINE__);
				}

				if ("\n" == $c_Data)
				{
					break;
				}

				$s_Data .= $c_Data;
			}

			list($s_ClientID, $s_EncryptedPassword) = explode('::', trim($s_Data));

			$s_Result = $this->_o_AuthEngine->authenticateClient($s_ClientID, $s_EncryptedPassword);

			if (false === socket_write($r_Connection, $s_Result."\n"))
			{
				$this->_socketError(__LINE__);
			}

			if (false === socket_close($r_Connection))
			{
				$this->_socketError(__LINE__);
			}
		}
	}

	private function _socketError($i_Line)
	{
		die(socket_strerror(socket_last_error())." --- $i_Line\n");
	}
}
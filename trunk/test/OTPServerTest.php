<?php
/**
 * OTPServerTest.php
 * $Id$
 *
 * PHPUnit unit test for OTPServer.php
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
class OTPServerTest extends PHPUnit_Framework_TestCase
{
	public $o_Server;
	public $o_Client;

	/**
	 * @test createClient
	 * @dataProvider createClasses
	 */
	public function testCreateClient($o_Server, $o_Client)
	{
		$s_ClientPath = $o_Server->client_export_path.$o_Client->id.DIRECTORY_SEPARATOR;

		$this->assertFileExists($s_ClientPath."{$o_Client->id}.db");
		$this->assertFileExists($s_ClientPath.'OTPClient.php');
		$this->assertFileExists($s_ClientPath.'ClientEntity.php');
		$this->assertFileExists($s_ClientPath.'config.xml');
	}

	/**
	 * @test authenticateClient
	 * @dataProvider createClasses
	 */
	public function testAuthenticateClient($o_Server, $o_Client)
	{
		$s_Password = $o_Client->password;

		$i_Result = $o_Server->authenticateClient($o_Client->id, $s_Password);
		$this->assertEquals(OTPClient::AUTH_SUCCESS, $i_Result);

		for ($i = 0; $i < $o_Server->max_auths; $i++)
		{
			$i_Result = $o_Server->authenticateClient($o_Client->id, '');
			$this->assertEquals(OTPClient::AUTH_RETRY, $i_Result);
		}

		$i_Result = $o_Server->authenticateClient($o_Client->id, '');
		$this->assertEquals(OTPClient::AUTH_FAIL, $i_Result);

		$i_Result = $o_Server->authenticateClient($o_Client->id, '');
		$this->assertEquals(OTPClient::CLIENT_DISABLED, $i_Result);
	}

	/**
	 * @test authenticateClient
	 * @dataProvider createClasses
	 */
	public function testAuthenticateClientLookahead($o_Server, $o_Client)
	{
		for ($i = 0; $i < $o_Server->look_ahead; $i++)
		{
			$s_Password = $o_Client->password;
		}

		$i_Result = $o_Server->authenticateClient($o_Client->id, $s_Password);
		$this->assertEquals(OTPClient::AUTH_SUCCESS, $i_Result);

		for ($i = 0; $i <= $o_Server->look_ahead; $i++)
		{
			$s_Password = $o_Client->password;
		}

		$i_Result = $o_Server->authenticateClient($o_Client->id, $s_Password);
		$this->assertEquals(OTPClient::AUTH_RETRY, $i_Result);
	}

	/**
	 * @test unlockClient
	 * @dataProvider createClasses
	 */
	public function testUnlockClient($o_Server, $o_Client)
	{
		for ($i = 0; $i <= $o_Server->max_auths; $i++)
		{
			$o_Server->authenticateClient($o_Client->id, '');
		}

		$i_Result = $o_Server->authenticateClient($o_Client->id, '');
		$this->assertEquals(OTPClient::CLIENT_DISABLED, $i_Result);

		$o_Server->unlockClient($o_Client->id);

		$i_Result = $o_Server->authenticateClient($o_Client->id, '');
		$this->assertEquals(OTPClient::AUTH_RETRY, $i_Result);
	}

	/*** Data Providers ***/

	public function createClasses()
	{
		include_once 'OTPServer.php';
		include_once 'client_data/ClientEntity.php';
		include_once 'client_data/OTPClient.php';

		$o_Server = new OTPServer('config.xml');

		$a_Data = array();

		$o_Client = new OTPClient($o_Server->createClient());

		$a_Data[] = array($o_Server, $o_Client);

		return $a_Data;
	}
}
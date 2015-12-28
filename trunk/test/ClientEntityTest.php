<?php
/**
 * ClientEntityTest.php
 * $Id$
 *
 * PHPUnit unit test for ClientEntity.php
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
class ClientEntityTest extends PHPUnit_Framework_TestCase
{
	/**
	 * @test			__construct
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	Database file does not exist
	 */
	public function testConstructInvalidFilepath($o_Config, $o_ClientEntity, $o_DB)
	{
		new ClientEntity('invalid_path', '', '');
	}

	/**
	 * @test			__construct
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	Invalid database specification
	 */
	public function testConstructInvalidPDO($o_Config, $o_ClientEntity, $o_DB)
	{
		new ClientEntity(new DateTime(), '', '');
	}

	/**
	 * @test			__construct
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	Client ID must be provided
	 */
	public function testConstructValidFilepath($o_Config, $o_ClientEntity, $o_DB)
	{
		new ClientEntity((string) $o_Config->db_path, '', '');
	}

	/**
	 * @test			__construct
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	Client ID must be provided
	 */
	public function testConstructValidPDO($o_Config, $o_ClientEntity, $o_DB)
	{
		new ClientEntity($o_DB, '', '');
	}

	/**
	 * @test			__construct
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	Client ID must be provided
	 */
	public function testConstructBlankID($o_Config, $o_ClientEntity, $o_DB)
	{
		new ClientEntity($o_DB, '', (string) $o_Config->db_key);
	}

	/**
	 * @test			__construct
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	Invalid Client ID
	 */
	public function testConstructInvalidID($o_Config, $o_ClientEntity, $o_DB)
	{
		new ClientEntity($o_DB, 'invalid_id', (string) $o_Config->db_key);
	}

	/**
	 * @test			__construct
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	Database encryption key must be provided
	 */
	public function testConstructInvalidDBKey($o_Config, $o_ClientEntity, $o_DB)
	{
		new ClientEntity($o_DB, (string) $o_Config->id, '');
	}

	/**
	* @test				__construct
	* @dataProvider			createClasses
	 */
	public function testConstructValidData($o_Config, $o_ClientEntity, $o_DB)
	{
		new ClientEntity($o_DB, (string) $o_Config->id, (string) $o_Config->db_key);
	}

	/**
	 * @test			__get
	 * @dataProvider		createClasses
	 */
	public function testGet($o_Config, $o_ClientEntity, $o_DB)
	{
		$this->assertEquals($o_ClientEntity->id, (string) $o_Config->id);
	}

	/**
	 * @test			__set
	 * @dataProvider		createClasses
	 */
	public function testSetValidData($o_Config, $o_ClientEntity, $o_DB)
	{
		$s_OldKey = $o_ClientEntity->key;
		$s_NewKey = sha1(openssl_random_pseudo_bytes(4096));

		$this->assertNotEquals($s_OldKey, $s_NewKey);

		$o_ClientEntity->key = $s_NewKey;

		$this->assertEquals($o_ClientEntity->key, $s_NewKey);
	}

	/**
	 * @test			getNewID
	 */
	public function testGetNewID()
	{
		$s_NewID = ClientEntity::getNewID();

		$this->assertTrue(strlen($s_NewID) == 36);

		$a_IDParts = explode('-', $s_NewID);

		$this->assertTrue(count($a_IDParts) == 5);

		$this->assertTrue(strlen($a_IDParts[0]) == 8);

		$this->assertTrue(strlen($a_IDParts[1]) == 4);

		$this->assertTrue(strlen($a_IDParts[2]) == 4);
		$this->assertTrue(substr($a_IDParts[2], 0, 1) == 4);

		$this->assertTrue(strlen($a_IDParts[3]) == 4);

		$this->assertTrue(strlen($a_IDParts[4]) == 12);

	}

	/**
	 * @test			generatePassword
	 * @dataProvider		createClasses
	 */
	public function testGeneratePassword($o_Config, $o_ClientEntity, $o_DB)
	{
		$s_Password1 = $o_ClientEntity->generatePassword();
		$i_Counter = $o_ClientEntity->counter;
		$s_Password2 = $o_ClientEntity->generatePassword($i_Counter);
		$s_Password3 = $o_ClientEntity->generatePassword();

		$this->assertEquals($s_Password1, $s_Password2);
		$this->assertNotEquals($s_Password1, $s_Password3);
		$this->assertNotEquals($s_Password2, $s_Password3);

		$this->assertEquals(strlen($s_Password1), (int) $o_ClientEntity->password_length);
		$this->assertEquals(strlen($s_Password2), (int) $o_ClientEntity->password_length);
		$this->assertEquals(strlen($s_Password3), (int) $o_ClientEntity->password_length);

		$this->assertTrue(is_numeric($s_Password1));
		$this->assertTrue(is_numeric($s_Password2));
		$this->assertTrue(is_numeric($s_Password3));
	}

	/**
	 * @test			save
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	Database connection must be an instance of PDO
	 */
	public function testSaveNoData($o_Config, $o_ClientEntity, $o_DB)
	{
		ClientEntity::save('', '', '');
	}

	/**
	 * @test			save
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	Database connection must be an instance of PDO
	 */
	public function testSaveInvalidPDO($o_Config, $o_ClientEntity, $o_DB)
	{
		ClientEntity::save(array(), '', '');
	}

	/**
	 * @test			save
	 * @dataProvider		createClasses
	 * @expectedException		InvalidArgumentException
	 * @expectedExceptionMessage	All database fields except init_vector must be provided
	 */
	public function testSaveIncompleteData($o_Config, $o_ClientEntity, $o_DB)
	{
		$a_ClientData['id'] = $o_ClientEntity->id;
		$a_ClientData['counter'] = $o_ClientEntity->counter;
		$a_ClientData['key'] = $o_ClientEntity->key;
		$a_ClientData['password_length'] = $o_ClientEntity->password_length;
		$a_ClientData['status'] = ClientEntity::ACTIVE;
		$a_ClientData['failed_auths'] = $o_ClientEntity->failed_auths;

		ClientEntity::save($a_ClientData, $o_DB, $o_Config->db_key);
	}

	/**
	 * @test			save
	 * @dataProvider		createClasses
	 */
	public function testSaveCompleteData($o_Config, $o_ClientEntity, $o_DB)
	{
		$a_ClientData['id'] = $o_ClientEntity->id;
		$a_ClientData['server_public_key'] = $o_ClientEntity->server_public_key;
		$a_ClientData['counter'] = $o_ClientEntity->counter;
		$a_ClientData['key'] = $o_ClientEntity->key;
		$a_ClientData['password_length'] = $o_ClientEntity->password_length;
		$a_ClientData['status'] = ClientEntity::ACTIVE;
		$a_ClientData['failed_auths'] = $o_ClientEntity->failed_auths;

		$a_EncryptedData = ClientEntity::save($a_ClientData, $o_DB, $o_Config->db_key);

		$this->assertEquals(count($a_EncryptedData), count($a_ClientData));
	}

	/*** Data Providers ***/

	public function createClasses()
	{
		include_once 'OTPServer.php';
		include_once 'client_data/ClientEntity.php';
		include_once 'client_data/OTPClient.php';

		$a_Data = array();

		$o_Server = new OTPServer('config.xml');

		$o_Config = simplexml_load_file($o_Server->createClient());

		$o_ClientEntity = new ClientEntity((string) $o_Config->db_path, (string) $o_Config->id, (string) $o_Config->db_key);
		$o_DB = new PDO('sqlite:'.$o_Config->db_path);

		$a_Data[] = array($o_Config, $o_ClientEntity, $o_DB);

		return $a_Data;
	}
}
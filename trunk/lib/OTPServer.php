<?php
/**
 * OTPServer.php
 * $Id$
 *
 * The OTPHP authentication server class
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

class OTPServer
{
	/**
	* @var ClientEntity
	*/
	private $_o_DB;

	/**
	* @var SimpleXML	The configuration object
	*/
	private $_o_Config;

	/**
	* @param string	$s_ConfigPath	The path to the config file
	*/
	public function __construct($s_ConfigPath)
	{
		$this->_o_Config = simplexml_load_file($s_ConfigPath);

		$this->_o_Config->public_key = file_get_contents($this->_o_Config->public_key_path);
		$this->_o_Config->private_key = file_get_contents($this->_o_Config->private_key_path);

		$this->_o_DB = new PDO('sqlite:'.$this->db_path);
		$this->_o_DB->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	}

	/**
	 * @param string	$s_Name	The name of the attribute
	 *
	 * @return mixed	The attribute cast as a string or null on failure
	 */
	public function __get($s_Name)
	{
		return (property_exists($this->_o_Config, $s_Name))? (string) $this->_o_Config->$s_Name : null;
	}

	/*** Authentication Functions ***/

	/**
	 * Authenticates an OTPClient
	 *
	 * @link http://tools.ietf.org/html/rfc4226
	 *
	 * @param string	$s_ClientID		The ID of the client to be authenticated
	 * @param string	$s_EncryptedPassword	The client's password, encrypted with the OTP server's public key
	 *
	 * @return integer	One of OTPClient::AUTH_SUCCESS, OTPClient::AUTH_RETRY (authentication failure, retry permitted), OTPClient::AUTH_FAIL (final authentication failure, client has been disabled), or OTPClient::CLIENT_DISABLED
	 */
	public function authenticateClient($s_ClientID, $s_EncryptedPassword)
	{
		$o_ClientEntity = $this->_getClientByID($s_ClientID);

		if (ClientEntity::DISABLED == $o_ClientEntity->status)
		{
			// To protect against brute-force and DoS attacks
			sleep(2 * $o_ClientEntity->failed_auths);
			return OTPClient::CLIENT_DISABLED;
		}
		elseif ($this->max_auths <= $o_ClientEntity->failed_auths)
		{
			// To protect against brute-force and DoS attacks
			sleep(2 * $o_ClientEntity->failed_auths);
			$o_ClientEntity->status = ClientEntity::DISABLED;
			return OTPClient::AUTH_FAIL;
		}
		else
		{
			$i_Counter = $o_ClientEntity->counter;
			$s_GeneratedPassword = $o_ClientEntity->generatePassword($i_Counter);

			$s_ReceivedPassword = $this->_decryptRSA($s_EncryptedPassword);

			if ($s_ReceivedPassword == $s_GeneratedPassword)
			{
				$o_ClientEntity->counter++;
				return OTPClient::AUTH_SUCCESS;
			}
			else
			{
				// To protect against brute-force and DoS attacks
				sleep(2 * $o_ClientEntity->failed_auths);

				$i_FailedAuthsThisSession = 1;
				// look-ahead allows for a small error correction window in case the client is a few password generations ahead of the server
				while ($this->look_ahead >= $i_FailedAuthsThisSession)
				{
					$i_Counter++;
					$s_GeneratedPassword = $o_ClientEntity->generatePassword($i_Counter);

					if ($s_ReceivedPassword == $s_GeneratedPassword)
					{
						$o_ClientEntity->counter = $i_Counter;
						return OTPClient::AUTH_SUCCESS;
					}
					$i_FailedAuthsThisSession++;
				}
				$o_ClientEntity->failed_auths++;
				return OTPClient::AUTH_RETRY;
			}
		}
	}

	/**
	 * Resets a client's status to ACTIVE
	 *
	 * @param string	$s_ClientID	The ID of the client to unlock
	 */
	public function unlockClient($s_ClientID)
	{
		$o_ClientEntity = $this->_getClientByID($s_ClientID);
		$o_ClientEntity->status = ClientEntity::ACTIVE;
		$o_ClientEntity->failed_auths = 0;
	}

	/*** Client Management Functions ***/

	/**
	 * Creates a new client record and exports the data to the configured client export directory
	 *
	 * @return mixed	The new client's ID or false on failure
	 */
	public function createClient()
	{
		$s_NewID = ClientEntity::getNewID();
		$s_NewPath = $this->client_export_path.$s_NewID.DIRECTORY_SEPARATOR;

		$s_NewDBPath = $s_NewPath.$s_NewID.'.db';
		$s_NewConfigPath = $s_NewPath.'config.xml';

		/* Create client directory */

		if (!file_exists($s_NewPath) && !mkdir($s_NewPath, (int) $this->dir_umask, true))
		{
			return false;
		}
		elseif (!is_writeable($s_NewPath))
		{
			return false;
		}

		/* Initialize client data */

		$s_NewDBKey = sha1(openssl_random_pseudo_bytes(4096));

		$a_NewData['id'] = $s_NewID;
		$a_NewData['server_public_key'] = (string) $this->public_key;
		// Randomizing the initial counter sequence makes brute force attacks harder
		$a_NewData['counter'] = hexdec(bin2hex(openssl_random_pseudo_bytes(1)));
		$a_NewData['key'] = sha1(openssl_random_pseudo_bytes(4096));
		$a_NewData['password_length'] = (int) $this->password_length;
		$a_NewData['status'] = ClientEntity::ACTIVE;
		$a_NewData['failed_auths'] = 0;

		/* Write the files to the client directory */

		$o_ClientConfig = new SimpleXMLElement('<otpclient></otpclient>');
		$o_ClientConfig->addChild('id', $a_NewData['id']);
		$o_ClientConfig->addChild('db_key', $s_NewDBKey);
		$o_ClientConfig->addChild('db_path', $s_NewDBPath);

		file_put_contents($s_NewConfigPath, $o_ClientConfig->asXML());
		chmod($s_NewConfigPath, (int) $this->file_umask);

		copy($this->client_export_path.'OTPClient.php', $s_NewPath.'OTPClient.php');
		chmod($s_NewPath.'OTPClient.php', (int) $this->file_umask);

		copy($this->client_export_path.'ClientEntity.php', $s_NewPath.'ClientEntity.php');
		chmod($s_NewPath.'ClientEntity.php', (int) $this->file_umask);

		// Create client's database file
		$o_ClientDB = new PDO('sqlite:'.$s_NewDBPath);
		$o_ClientDB->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		chmod($s_NewDBPath, (int) $this->file_umask);

		/* Create the new client records */

		ClientEntity::save($a_NewData, $this->_o_DB, $this->db_key);

		$o_Result = $this->_o_DB->query("SELECT sql FROM sqlite_master WHERE tbl_name='clients'");
		$a_Result = $o_Result->fetch(PDO::FETCH_NUM);
		$s_CreateTableQuery = $a_Result[0];

		$o_ClientDB->exec($s_CreateTableQuery);

		ClientEntity::save($a_NewData, $o_ClientDB, $s_NewDBKey);

		/*
		The RFC specifies that the client should increment its counter before sending a password,
		but the server should only increment the counter AFTER a successful authentication attempt.
		This ensures that the server-side record is one count ahead of the client-side record to facilitate this requirement
		*/

		$NewClient = new ClientEntity($this->_o_DB, $a_NewData['id'], $this->db_key);
		$NewClient->counter++;

		return $s_NewConfigPath;
	}

	/**
	 * Decrypts given data with the server's private RSA key
	 *
	 * @param string	$s_EncryptedData	The encrypted data, encoded in base64
	 *
	 * @return mixed	The decrypted data or false on failure
	 */
	private function _decryptRSA($s_EncryptedData)
	{
		$s_Data = false;

		openssl_private_decrypt(base64_decode($s_EncryptedData), $s_Data, $this->private_key);

		return $s_Data;
	}

	/**
	 * Private because it returns the local DB instance
	 *
	 * @param string			$id		The client's ID
	 *
	 * @return ClientEntity		An instace of the client
	 */
	private function _getClientByID($id)
	{
		return new ClientEntity($this->_o_DB, $id, $this->db_key);
	}
}
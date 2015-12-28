<?php
/**
 * ClientEntity.php
 * $Id$
 *
 * A class that provides database abstraction and specialized functions for OTPHP
 *
 * Implements an RFC-4226 compliant HOTP algorithm for password generation
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

class ClientEntity
{
	const DISABLED = 0;
	const ACTIVE = 1;

	/**
	* @var	array	The client's attributes from the database
	*/
	private $_a_Attributes;

	/**
	* @var	string	The client's database encryption key
	*/
	private $_s_DBCryptoKey;

	/**
	* @var	PDO	The client's database instance
	*/
	private $_o_DB;

	/**
	 * @var	array	The client database fields that should not be encrypted
	 */
	private static $_a_DoNotEncrypt = array('id', 'init_vector', 'server_public_key');

	/**
	 * @param	mixed	$v_DB			An instantiated PDO object or the path to the SQLite database.
	 * @param	string	$s_ID 			The client ID
	 * @param	string	$s_DBCryptoKey	The client's database encryption key
	 */
	public function __construct($v_DB, $s_ID, $s_DBCryptoKey)
	{
		if ($v_DB instanceof PDO)
		{
			$this->_o_DB = $v_DB;
		}
		elseif (is_string($v_DB))
		{
			if (file_exists($v_DB))
			{
				$this->_o_DB = new PDO('sqlite:'.$v_DB);
			}
			else
			{
				throw new InvalidArgumentException('Database file does not exist');
			}
		}
		else
		{
			throw new InvalidArgumentException('Invalid database specification');
		}

		if (empty($s_ID))
		{
			throw new InvalidArgumentException('Client ID must be provided');
		}

		if (empty($s_DBCryptoKey))
		{
			throw new InvalidArgumentException('Database encryption key must be provided');
		}

		$this->_s_DBCryptoKey = $s_DBCryptoKey;

		$this->_getAttributes($s_ID);

		$this->_o_DB->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
	}

	/**
	 * A general-purpose getter that decrypts attributes on-the-fly
	 *
	 * @param	string	$s_Name	The name of the attribute
	 *
	 * @return	mixed 	The decrypted attribute or null on failure
	 */
	public function __get($s_Name)
	{
		if (in_array($s_Name, array_keys($this->_a_Attributes)))
		{
			$s_DecryptedValue = $this->_decryptField($s_Name);
			return $s_DecryptedValue;
		}

		return null;
	}

	/**
	 * A general-purpose setter that encrypts attributes on-the-fly
	 * It also saves the new attribute to the database
	 *
	 * @param	string	$s_Name		The attribute name
	 * @param	string	$s_Value	The attribute
	 */
	public function __set($s_Name, $s_Value)
	{
		if (in_array($s_Name, array_keys($this->_a_Attributes)))
		{
			// decrypting all values to send to save()
			foreach ($this->_a_Attributes as $s_AttrName => $s_AttrValue)
			{
				if ($s_AttrName != $s_Name)
				{
					$a_DecryptedAttributes[$s_AttrName] = $this->_decryptField($s_AttrName);
				}
			}

			$a_DecryptedAttributes[$s_Name] = $s_Value;

			$this->_a_Attributes = self::save($a_DecryptedAttributes, $this->_o_DB, $this->_s_DBCryptoKey);
		}
	}

	/**
	 * Generates a new password and returns it encrypted with the OTP server's public key
	 *
	 * @return	string	The OTP client's password encrypted with the OTP server's public RSA key and encoded in base64
	 */
	public function getRSAEncryptedPassword()
	{
		$s_Password = $this->generatePassword();

		openssl_public_encrypt($s_Password, $s_EncryptedPassword, $this->server_public_key);

		return base64_encode($s_EncryptedPassword);
	}

	/**
	 * Generates a HOTP password for the client compliant with RFC 4226
	 *
	 * @link http://tools.ietf.org/html/rfc4226
	 *
	 * @param integer	$i_Counter	(optional) The counter value to use in generating the HOTP password (default: $this->counter plus one)
	 *
	 * @return string	The new password
	 */
	public function generatePassword($i_Counter = null)
	{
		$i_Counter = (is_null($i_Counter))? ++$this->counter : $i_Counter;

		$s_HMAC = hash_hmac('sha1', $i_Counter, $this->key);

		// split hash into an array of 2-char pairs, each one of which is a hexadecimal number
		$a_HMAC = str_split($s_HMAC, 2);

		// Get the dynamic offset from the last hex pair in decimal
		// PHP automatically converts the decimal to hex for the AND operation and also converts hex chars to ASCII codes if not converted to decimal
		$i_Offset = hexdec($a_HMAC[19]) & 0xf;

		// Generate the dynamic binary code
		$s_DBC = '';
		for ($i = $i_Offset; $i <= ($i_Offset + 3); $i++)
		{
			$s_DBC .= $a_HMAC[$i];
		}

		// Mask the highest-order bit to avoid processor compatibility issues
		$s_DBC = hexdec($s_DBC) & 0x7fffffff;

		// Obtain the modulo of the dynamic binary code according to the length of the password required
		// This results in a number <password_length> digits long
		$s_HOTP = $s_DBC % pow(10, $this->password_length);

		// The various numeric base conversions strip leading zeroes
		while (strlen($s_HOTP) < $this->password_length)
		{
			$s_HOTP = '0'.$s_HOTP;
		}

		return $s_HOTP;
	}

	/**
	 * This is a function that saves attributes to the database
	 *
	 * @param	array	$a_Data		An array of the data to be saved
	 * @param	PDO	$o_DB		The database in which save the data
	 * @param	string	$s_DBCryptoKey	The database encryption key
	 *
	 * @return	mixed	The array of encrypted data or false on failure
	 */
	public static function save($a_Data, $o_DB, $s_DBCryptoKey)
	{
		$a_ObligatoryFields = array('id', 'server_public_key', 'counter', 'key', 'password_length', 'status', 'failed_auths');

		if (!($o_DB instanceof PDO))
		{
			throw new InvalidArgumentException('Database connection must be an instance of PDO');
		}

		if (count(array_intersect(array_keys($a_Data), $a_ObligatoryFields)) < count($a_ObligatoryFields))
		{
			throw new InvalidArgumentException('All database fields except init_vector must be provided');
		}

		$i_InitVector = bin2hex(openssl_random_pseudo_bytes(8));

		$a_EncryptedData = array();
		foreach ($a_Data as $s_Name => $s_Value)
		{
			$a_EncryptedData[$s_Name] = self::_encryptField($s_Name, $s_Value, $i_InitVector, $s_DBCryptoKey);
		}

		$o_Statement = $o_DB->prepare('INSERT OR REPLACE INTO clients
						(id, server_public_key, counter, key, password_length, status, failed_auths, init_vector)
						VALUES
						(:id, :server_public_key, :counter, :key, :password_length, :status, :failed_auths, :init_vector)
						');

		$o_Statement->bindParam(':id', $a_EncryptedData['id']);
		$o_Statement->bindParam(':server_public_key', $a_EncryptedData['server_public_key']);
		$o_Statement->bindParam(':counter', $a_EncryptedData['counter']);
		$o_Statement->bindParam(':key', $a_EncryptedData['key']);
		$o_Statement->bindParam(':password_length', $a_EncryptedData['password_length']);
		$o_Statement->bindParam(':status', $a_EncryptedData['status']);
		$o_Statement->bindParam(':failed_auths', $a_EncryptedData['failed_auths']);
		$o_Statement->bindParam(':init_vector', $i_InitVector);

		if ($o_Statement->execute())
		{
			return $a_EncryptedData;
		}
		else
		{
			return false;
		}
	}

	/**
	 * Generates a UUIDv4 for the client's ID compliant with RFC 4122
	 *
	 * @link http://tools.ietf.org/html/rfc4122
	 *
	 * @return	string	The new ID
	 */
	public static function getNewID()
	{
		// Create a pool of pseudorandom data for the UUID generation process
		$s_RandomPool = bin2hex(openssl_random_pseudo_bytes(16));

		/* Concatenate the UUID from its component parts */

		// time-low
		$s_UUID = substr($s_RandomPool, 0, 8).'-';

		// time-mid
		$s_UUID .= substr($s_RandomPool, 8, 4).'-';

		// time-hi-and-version (4 is the version number)
		$s_UUID .= '4'.substr($s_RandomPool, 12, 3).'-';

		$s_ClockHiRes = substr($s_RandomPool, 15, 2);
		$s_BinDigit = decbin(hexdec($s_ClockHiRes));

		// The hex to binary conversion strips leading zeroes
		while (strlen($s_BinDigit) < 4)
		{
			$s_BinDigit = '0'.$s_BinDigit;
		}

		// The standard specifies that the first 2 of 8 bits in the clock-seq-hi-and-reserved secton be 10
		$s_NewBinDigit = '10'.substr($s_BinDigit, 2);
		$s_NewClockHiRes = dechex(bindec($s_NewBinDigit));

		// clock-seq-hi-and-reserved
		$s_UUID .= $s_NewClockHiRes;

		// clock-seq-low
		$s_UUID .= substr($s_RandomPool, 16, 2).'-';

		// node
		$s_UUID .= substr($s_RandomPool, 18, 12);

		return $s_UUID;
	}

	/**
	 * Initializes the attributes array from the database
	 *
	 * @param	string	$s_ID	(optional) The client ID (default: the current instance's ID)
	 */
	private function _getAttributes($s_ID = null)
	{
		$s_ID = (is_null($s_ID))? $this->_a_Attributes['id'] : $s_ID;

		if (is_null($s_ID))
		{
			throw new InvalidArgumentException('Client ID may not be null');
		}

		$o_Statement = $this->_o_DB->prepare('SELECT * FROM clients WHERE id=:id');
		$o_Statement->bindValue(':id', $s_ID);
		$o_Statement->execute();

		$a_Record = $o_Statement->fetch(PDO::FETCH_ASSOC);

		if (!$a_Record)
		{
			throw new InvalidArgumentException('Invalid Client ID');
		}

		$this->_a_Attributes = $a_Record;
	}

	/**
	 * Decrypts a database field by name
	 *
	 * @param	string	$s_Name	The field name
	 *
	 * @return	mixed	The decrypted field or null on failure
	 */
	private function _decryptField($s_Name)
	{
		if (in_array($s_Name, self::$_a_DoNotEncrypt))
		{
			return $this->_a_Attributes[$s_Name];
		}
		elseif (isset($this->_a_Attributes[$s_Name]))
		{
			$this->_refreshInitVector();
			return openssl_decrypt($this->_a_Attributes[$s_Name], 'aes-256-cbc', $this->_s_DBCryptoKey, false, $this->_a_Attributes['init_vector']);
		}
		else
		{
			return null;
		}
	}

	/**
	 * Checks if the init_vector field in the database has changed and updates the attributes array if so
	 *
	 * This must be called at minimum before all DB write operations because it is theoretically possible
	 * for another process to update this instance's record after it has read it
	 */
	private function _refreshInitVector()
	{
		// Check to see if another process updated our row after we last read it...
		$o_Statement = $this->_o_DB->prepare('SELECT init_vector FROM clients WHERE id=:id');
		$o_Statement->bindValue(':id', $this->_a_Attributes['id']);
		$o_Statement->execute();

		$a_Result = $o_Statement->fetch(PDO::FETCH_ASSOC);

		if ($this->_a_Attributes['init_vector'] != $a_Result['init_vector'])
		{
			// Someone did change the row, update our records...
			$this->_getAttributes();
		}
	}

	/**
	 * Encrypts a field with the provided key and initialization vector
	 *
	 * @param	string	$s_Name			The field name
	 * @param	string	$s_Value		The unencrypted data
	 * @param	string	$i_InitVector	The initialization vector
	 * @param	string	$s_Key			The key used for encryption
	 *
	 * @return	mixed	The encrypted data or false on failure
	 */
	private static function _encryptField($s_Name, $s_Value, $i_InitVector, $s_Key)
	{
		if (in_array($s_Name, self::$_a_DoNotEncrypt))
		{
			return $s_Value;
		}

		return openssl_encrypt($s_Value, 'aes-256-cbc', $s_Key, false, $i_InitVector);
	}
}
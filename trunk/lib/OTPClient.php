<?php
/**
 * OTPClient.php
 * $Id$
 *
 * The OTPHP authentication client class
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

class OTPClient
{
    const AUTH_SUCCESS = 0;
    const AUTH_RETRY = 1;
    const AUTH_FAIL = 2;
    const CLIENT_DISABLED = 3;

    /**
    * @var ClientEntity
    */
    private $_o_ClientEntity;

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

	    $this->_o_ClientEntity = new ClientEntity( (string) $this->_o_Config->db_path, (string) $this->_o_Config->id, (string) $this->_o_Config->db_key);
    }

    /**
    * @param string	$s_Name	The name of the attribute
    *
    * @return mixed	The attribute or null if it does not exist
    */
    public function __get($s_Name)
    {
	    switch ($s_Name)
	    {
		    case 'id':
			    return $this->_o_Config->id;
		    case 'status':
			    return $this->_o_ClientEntity->status;
		    case 'password':
			    return $this->_o_ClientEntity->getRSAEncryptedPassword();
		    default:
			    return null;
	    }
    }
}

<?php

/**
 *
 * Secure Client Side Session Handler
 *
 * ------------------------------------------------------------------------
 *
 * Copyright (c) 2014 Dan Cotora
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * ------------------------------------------------------------------------
 *
 * This PHP class can be used to store session information on the client side
 * using an encrypted cookie.
 *
 * The session data is also compressed (using deflate) before it's encrypted to
 * try to reduce its size as there's a browser limit of around 4KB for all the
 * cookies set on a domain.
 *
 * By default, the class is configured to only set the data cookie over a secure
 * HTTPS connection. This can be overridden by changing the `secureCookie` var.
 *
 * The class also allows the customization of other cookie specific settings,
 * as well as the compression level for the session data deflate algorithm.
 *
 */

class SecureClientSideSessionHandlerException extends Exception {};

class SecureClientSideSessionHandler implements SessionHandlerInterface
{
    /**
     * The zlib compression level for the session data compression (0 to 9)
     * @var integer
     */
    public static $compressionLevel = 3;

    /**
     * The name for the cookie that will contain the session data
     * @var string
     */
    public static $cookieName = 'PHPSESSDATA';

    /**
     * The path on the server in which the session cookie will be available on
     * @var string
     */
    public static $cookiePath = '/';

    /**
     * The domain that the cookie is available to
     * @var string
     */
    public static $cookieDomain = null;

    /**
     * Indicates that the cookie should only be transmitted over a secure HTTPS connection from the client
     * @var boolean
     */
    public static $cookieSecure = true;

    /**
     * When TRUE the cookie will be made accessible only through the HTTP protocol. This means that the cookie won't be accessible by scripting languages, such as JavaScript.
     * @var boolean
     */
    public static $cookieHTTPOnly = true;

    /**
     * Initialize the session handler
     * @param  string $encryptionKey     The encryption key used to encrypt the session data
     * @param  string $encryptionKeySalt The encryption key salt (this is appended to the encryption key & random salt)
     * @return boolean                   TRUE on success or FALSE on failure
     */
    public static function initialize($encryptionKey, $encryptionKeySalt) {
        $handler = new SecureClientSideSessionHandler($encryptionKey, $encryptionKeySalt);
        return session_set_save_handler($handler, true);
    }

    /**
     * The encryption key used to encrypt the session data
     * @var string
     */
    private $encryptionKey;

    /**
     * The encryption key salt (this is appended to the encryption key & random salt)
     * @var string
     */
    private $encryptionKeySalt;

    /**
     * The class constructor
     * @param string $encryptionKey     The encryption key used to encrypt the session data
     * @param string $encryptionKeySalt The encryption key salt (this is appended to the encryption key & random salt)
     */
    public function __construct($encryptionKey, $encryptionKeySalt) {
        // Check if an encryption key was specified
        if (empty($encryptionKey)) {
            throw new SecureClientSideSessionHandlerException('You must specify an encryption key');
        }

        // Check if an encryption key salt was specified
        if (empty($encryptionKeySalt)) {
            throw new SecureClientSideSessionHandlerException('You must specify an encryption key salt');
        }

        // Set the encryption key & salt
        $this->encryptionKey     = $encryptionKey;
        $this->encryptionKeySalt = $encryptionKeySalt;
    }

    /**
     * Encrypt the data using AES
     * @param  string $data The data that should be encrypted
     * @return string       The encrypted data
     */
    public function encrypt($data) {
        // Generate a random IV
        $iv = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);

        // Generate a random salt
        $salt = mcrypt_create_iv(16, MCRYPT_DEV_URANDOM);

        // Get the SHA256 hash from the encryption key, the random salt and the static encryption key salt
        $key = hash('SHA256', $this->encryptionKey . $salt . $this->encryptionKeySalt, true);

        // Pad & encrypt the data; return the salt + iv + encrypted data concatenated into a single string
        $padding = 16 - (strlen($data) % 16);
        $data   .= str_repeat(chr($padding), $padding);
        return $salt . $iv . mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
    }

    /**
     * Decrypt the data using AES
     * @param  string $data The data that should be decrypted
     * @return string       The decrypted data
     */
    public function decrypt($data) {
        // Extract the salt and the IV from the original data
        $salt    = substr($data, 0, 16);
        $iv      = substr($data, 16, 16);
        $data    = substr($data, 32);

        // Get the SHA256 hash from the encryption key, the random salt and the static encryption key salt
        $key = hash('SHA256', $this->encryptionKey . $salt . $this->encryptionKeySalt, true);

        // Decrypt the data and remove the padding
        $data    = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
        $padding = ord($data[strlen($data) - 1]);
        return substr($data, 0, -$padding);
    }

    /**
     * Compress the data using the deflate algorithm
     * @param  string $data The data that should be compressed
     * @return string       The compressed data
     */
    public function compress($data) {
        $data = gzdeflate($data, self::$compressionLevel);

        if ($data === false) {
            throw new SecureClientSideSessionHandlerException('Unable to compress the session data');
        }

        return $data;
    }

    /**
     * Decompress the data using the inflate algorithm
     * @param  string $data The data that should be decompressed
     * @return string       The decompressed data
     */
    public function decompress($data) {
        return gzinflate($data);
    }

    /**
     * Initialize the session (not used)
     * @return boolean This method always returns TRUE
     */
    public function open($savePath, $sessionName)
    {
        return true;
    }

    /**
     * Close the session (not used)
     * @return boolean This method always returns TRUE
     */
    public function close()
    {
        return true;
    }

    /**
     * Read the session data from the client side cookie (authenticates the data and it then decrypts it and decompresses it)
     * @param  string $id The session id
     * @return string     The serialized session data
     */
    public function read($id)
    {
        // Get the data from the session data cookie
        $data = isset($_COOKIE[self::$cookieName]) ? $_COOKIE[self::$cookieName] : null;

        // If the data seems invalid, return an empty session
        if (($delimiterPos = strpos($data, '-')) === false) return '';

        // Extract the signature & the data
        $signature = substr($data, 0, $delimiterPos);
        $data      = substr($data, $delimiterPos + 1);

        // Authenticate the data (determine the expected signature)
        $expectedSignature = base64_encode(hash_hmac('sha256', $data, $this->encryptionKey . $id . $this->encryptionKeySalt, true));

        // If the data can't be authenticated, return an empty session
        if (strcmp($signature, $expectedSignature) !== 0) return '';

        // Decode the data from base64
        $data = base64_decode($data);

        // If the data can't be decoded, return an empty session
        if ($data === false) return '';

        // Decrypt the data
        $data = $this->decrypt($data);

        // Decompress the data and return it
        $data = $this->decompress($data);

        return ($data !== false) ? $data : '';
    }

    /**
     * Write the session data to a cookie (compresses, encrypts and signs the data)
     * @param  string  $id   The session id
     * @param  string  $data The serialized session data
     * @return boolean       TRUE on success or FALSE on failure
     */
    public function write($id, $data)
    {
        // If the headers have already been sent, throw an exception
        if (headers_sent($file, $line)) {
            throw new SecureClientSideSessionHandlerException('Can not send session data cookie - headers already sent (output started at ' . $file . ':' . $line . ')');
        }

        // Compress the session data
        $data = $this->compress($data);

        // Encrypt the session data
        $data = $this->encrypt($data);

        // Encode the data in base64
        $data = base64_encode($data);

        // Sign the data (generate a HMAC signature)
        $signature = hash_hmac('sha256', $data, $this->encryptionKey . $id . $this->encryptionKeySalt, true);

        // Attatch the signature
        $data = base64_encode($signature) . '-' . $data;

        // If the data is over 3072 bytes, throw an exception
        if (strlen($data) > 3072) {
            throw new SecureClientSideSessionHandlerException("The session data is too large (over 3KB)", 1);
        }

        // Get the data cookie's lifetime - this will have the same lifetime as the session cookie
        $cookieLifetime = ini_get('session.cookie_lifetime');

        // Set the data cookie
        return setcookie(self::$cookieName, $data, $cookieLifetime, self::$cookiePath, self::$cookieDomain, self::$cookieSecure, self::$cookieHTTPOnly);
    }

    /**
     * Destroy the session (clear the session data cookie)
     * @return boolean Returns TRUE on success or FALSE on failure
     */
    public function destroy($id)
    {
        $expirationTime = time() - 10800;
        return setcookie(self::$cookieName, '', $expirationTime, self::$cookiePath, self::$cookieDomain, self::$cookieSecure, self::$cookieHTTPOnly);
    }

    /**
     * Cleanup old sessions (not used)
     * @return boolean This method always returns TRUE
     */
    public function gc($maxlifetime)
    {
        return true;
    }
}
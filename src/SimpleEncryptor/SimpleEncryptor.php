<?php

namespace Evgmel\SimpleEncryptor;

class SimpleEncryptor implements SimpleEncryptorInterface
{
    private static $delimeter = ".::";

    /**
     * Encrypt given string using giving secret key and encryption algorithm
     *
     * @param string $data
     * @param string $encKey
     * @param string $encAlg
     *
     * @return string
     */
    public static function encrypt(string $data, string $encKey, string $encAlg = self::ALG_AES_256_CBC)
    {
        $ivBytes = static::generateIVBytes($encAlg);
        $encryptedString = openssl_encrypt($data, $encAlg, $encKey, 0, $ivBytes);

        return base64_encode($encryptedString . static::$delimeter . $ivBytes);
    }

    /**
     * Decrypt given string with a secret key and encryption algorithm
     *
     * @param string $data
     * @param string $encKey
     * @param string $encAlg
     *
     * @return string|false
     */
    public static function decrypt(string $data, string $encKey, string $encAlg = self::ALG_AES_256_CBC)
    {
        $data = base64_decode($data);
        list($payloadData, $ivBytes) = explode(static::$delimeter, $data, 2);

        return openssl_decrypt($payloadData, $encAlg, $encKey, 0, $ivBytes);
    }

    /**
     * Generates random bytes according to IV length
     *
     * @param string $encAlg
     * @return string
     */
    private static function generateIVBytes($encAlg = self::ALG_AES_256_CBC): string
    {
        return openssl_random_pseudo_bytes(openssl_cipher_iv_length($encAlg));
    }
}
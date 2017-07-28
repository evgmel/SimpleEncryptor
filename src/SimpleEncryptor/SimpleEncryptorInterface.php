<?php

namespace Evgmel\SimpleEncryptor;


interface SimpleEncryptorInterface
{
    const
        ALG_AES_256_CBC = 'AES-256-CBC',
        ALG_AES_128_CBC = 'AES-128-CBC';

    /**
     * Encrypt given string using giving secret key and encryption algorithm
     *
     * @param string $data
     * @param string $encKey
     * @param string $encAlg
     *
     * @return string
     */
    public static function encrypt(string $data, string $encKey, string $encAlg = self::ALG_AES_256_CBC);

    /**
     * Decrypt given string with a secret key and encryption algorithm
     *
     * @param string $data
     * @param string $encKey
     * @param string $encAlg
     *
     * @return string
     */
    public static function decrypt(string $data, string $encKey, string $encAlg = self::ALG_AES_256_CBC);
}
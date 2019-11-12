<?php

declare(strict_types=1);

namespace DanielNess\Ansible\Vault;

use DanielNess\Ansible\Vault\Decrypter\Envelope;
use DanielNess\Ansible\Vault\Decrypter\Exception\DecryptionException;
use DanielNess\Ansible\Vault\Exception\AnsibleVaultException;

/**
 * Class Decrypter
 * @package DanielNess\Ansible\Vault
 * @see https://github.com/ansible/ansible/blob/devel/lib/ansible/parsing/vault/__init__.py
 */
class Decrypter
{
    const AES_256_CTR = 'aes-256-ctr';

    /**
     * @param string $payload
     * @param string $password
     * @return string
     * @throws AnsibleVaultException
     * @throws Decrypter\Exception\InvalidPayloadException
     * @throws DecryptionException
     * @see https://github.com/ansible/ansible/blob/abf33196668f27503065115d84932d2807bce253/lib/ansible/parsing/vault/__init__.py#L1242
     */
    public static function decryptString(string $payload, string $password): string
    {
        $envelope = new Envelope($payload);

        if (!$envelope->isAES256()) {
            throw new AnsibleVaultException("Only AES256 is supported");
        }

        list($key1, $key2, $iv) = self::generateSha256Keys($password, $envelope->getSalt());
        $hmac = self::generateHMAC($envelope->getCipherText(), $key2);

        if ($hmac !== hex2bin($envelope->getHmac())) {
            throw new DecryptionException("Invalid HMAC");
        }

        $binaryText = openssl_decrypt(
            $envelope->getCipherText(),
            self::AES_256_CTR,
            $key1,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($binaryText === false) {
            throw new DecryptionException();
        }

        // convert from binary data
        $plainText = '';
        foreach (unpack('c*', $binaryText) as $bin) {
            $char = chr($bin);
            if (ord($char) === 3) {
                continue;
            }
            $plainText .= $char;
        }

        return (string) $plainText;
    }

    /**
     * @param string $password
     * @param string $salt
     * @return array
     */
    public static function generateSha256Keys(string $password, string $salt): array
    {
        $keyLength = 32;
        $ivLength = 16;

        $derivedKey = hash_pbkdf2(
            'sha256',
            $password,
            $salt,
            10000,
            2 * $keyLength + $ivLength,
            true
        );

        $key1 = substr($derivedKey, 0, $keyLength);
        $key2 = substr($derivedKey, $keyLength, $keyLength);
        $iv = substr($derivedKey, ($keyLength*2), $ivLength);

        return [
            $key1,
            $key2,
            $iv,
        ];
    }

    public static function generateHMAC(string $cipherText, string $key): string
    {
        return hash_hmac('sha256', $cipherText, $key, true);
    }
}
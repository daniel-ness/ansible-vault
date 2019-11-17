<?php
declare(strict_types=1);

namespace DanielNess\Ansible\Vault\Contracts;

/**
 * Trait EncryptionTrait
 * @package DanielNess\Ansible\Vault\Contracts
 */
trait EncryptionTrait
{
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

    /**
     * @param string $cipherText
     * @param string $key
     * @return string
     * @see https://github.com/ansible/ansible/blob/3a9650df98b7e0219f060aa5ec775f22d4170f10/lib/ansible/parsing/vault/__init__.py#L1178
     */
    public static function generateHMAC(string $cipherText, string $key): string
    {
        return hash_hmac('sha256', $cipherText, $key, true);
    }
}
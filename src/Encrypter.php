<?php
declare(strict_types=1);

namespace DanielNess\Ansible\Vault;

use DanielNess\Ansible\Vault\Contracts\EncryptionTrait;
use DanielNess\Ansible\Vault\Encrypter\Exception\EncryptionException;

/**
 * Class Encrypter
 * @package DanielNess\Ansible\Vault
 */
class Encrypter
{
    use EncryptionTrait;

    const VERSION = '1.1';
    const CIPHER_NAME = 'AES256';
    const AES_256_CTR = 'aes-256-ctr';

    /**
     * @param string $plainText
     * @param string $password
     * @return string
     * @throws \Exception
     */
    public static function encryptString(string $plainText,
                                         string $password,
                                         string $salt = null,
                                         array  $sha256Keys = []): string
    {
        // add PKCS7 padding
        $padding = 16 - (strlen($plainText) % 16);
        $plainText .= str_repeat(chr($padding), $padding);

        $salt = $salt ?? self::generateSalt();

        list($key1, $key2, $iv) = (count($sha256Keys) === 3)
            ? $sha256Keys
            : self::generateSha256Keys($salt, $password);

        $binaryCipher = openssl_encrypt(
            $plainText,
            self::AES_256_CTR,
            $key1,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($binaryCipher === false) {
            throw new EncryptionException();
        }

        $hmac = bin2hex(self::generateHMAC($binaryCipher, $key2));

        $header = implode(';', ['$ANSIBLE_VAULT', self::VERSION, self::CIPHER_NAME]);
        $cipherText = bin2hex(implode("\n", [bin2hex($salt), $hmac, bin2hex($binaryCipher)]));
        $cipherText = chunk_split($cipherText, 80, "\n");
        $vaultText = implode("\n", [$header, $cipherText]);

        return $vaultText;
    }

    /**
     * @return string
     * @throws \Exception
     */
    public static function generateSalt(): string
    {
        return openssl_random_pseudo_bytes(32);
    }
}
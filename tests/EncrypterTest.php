<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use DanielNess\Ansible\Vault\Encrypter;
use DanielNess\Ansible\Vault\Decrypter;
use DanielNess\Ansible\Vault\Decrypter\Envelope;

/**
 * Class DecrypterTest
 */
class EncrypterTest extends TestCase
{
    const PASSWORD = 'daniel-ness/ansible-vault';
    const SALT = '8565b8e807e96b250c1af0c726c1a48115de5b9bcfab41fcbaae3a7960719760';

    /**
     * @test
     */
    public function itCanGenerateASalt()
    {
        $salt = Encrypter::generateSalt();

        $this->assertEquals(
            32,
            strlen($salt)
        );
    }

    /**
     * @test
     */
    public function itCanGenerateSha256Keys()
    {
        list($key1, $key2, $iv) = Encrypter::generateSha256Keys(
            self::PASSWORD,
            hex2bin(self::SALT)
        );

        $this->assertEquals(
            b'ba97e5bb0fb5ef01c5bd3eaf01e594ad318bf6ee4f8d7fd96e8efdbe537fc7a0',
            bin2hex($key1)
        );

        $this->assertEquals(
            b'7c79261bb9043cb7bd63ec718788cf15f9d368847dce3139b5bb98384e45d764',
            bin2hex($key2)
        );

        $this->assertEquals(
            b'c7b4ed0ce6604e78f2a9b93469d52976',
            bin2hex($iv)
        );
    }

    /**
     * @test
     */
    public function itCanGenerateHMAC()
    {
         list($key1, $key2, $iv) = Encrypter::generateSha256Keys(
            self::PASSWORD,
             hex2bin(self::SALT)
        );

        $cipherHex = '3ab5480ac14c02762e17c2bf4deec594d80347e4f103df2abd2fb60023ed0a30';
        $hmac = Encrypter::generateHMAC(hex2bin($cipherHex), $key2);

        $this->assertEquals(
            'bf9e99765b189dcfa6efe87f42a62020128350933c0fc1c39aa3363e4e46f21b',
            bin2hex($hmac)
        );
    }

    /**
     * @test
     */
    public function itCanEncryptAString()
    {
        list($key1, $key2, $iv) = Encrypter::generateSha256Keys(
            self::PASSWORD,
            hex2bin(self::SALT)
        );

        $vaultText = Encrypter::encryptString(
            'itCanDecryptOnePointOneString',
            self::PASSWORD,
            hex2bin(self::SALT),
            [$key1, $key2, $iv]
        );

        $expectedVaultText = file_get_contents(__DIR__ . '/files/OnePointOneStringNoTag.txt');
        $this->assertEquals($expectedVaultText, $vaultText);
    }

    /**
     * @test
     */
    public function itCanEncryptAndDecryptAString()
    {
        $input = 'decrypt';
        $vaultText = Encrypter::encryptString($input, self::PASSWORD);
        $plainText = Decrypter::decryptString($vaultText, self::PASSWORD);
        $this->assertEquals($input, $plainText);
    }
}
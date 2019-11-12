<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use DanielNess\Ansible\Vault\Decrypter;
use DanielNess\Ansible\Vault\Decrypter\Envelope;

/**
 * Class DecrypterTest
 */
class DecrypterTest extends TestCase
{
    const PASSWORD = 'daniel-ness/ansible-vault';

    /**
     * @test
     */
    public function itCanGenerateSha256Keys()
    {
        list($key1, $key2, $iv) = Decrypter::generateSha256Keys(
            self::PASSWORD,
            hex2bin('8565b8e807e96b250c1af0c726c1a48115de5b9bcfab41fcbaae3a7960719760')
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
        /** @var Decrypter\Envelope $env */
        $env = new Envelope(file_get_contents(__DIR__ . '/files/OnePointOneString.txt'));

        list($key1, $key2, $iv) = Decrypter::generateSha256Keys(
            self::PASSWORD,
            $env->getSalt()
        );

        $hmac = Decrypter::generateHMAC($env->getCipherText(), $key2);

        $this->assertEquals(
            'bf9e99765b189dcfa6efe87f42a62020128350933c0fc1c39aa3363e4e46f21b',
            bin2hex($hmac)
        );
    }

    /**
     * @test
     */
    public function itCanDecryptOnePointOneString()
    {
        $encrypted = file_get_contents(__DIR__ . '/files/OnePointOneString.txt');
        $decrypted = Decrypter::decryptString($encrypted, self::PASSWORD);
        $this->assertEquals(b'itCanDecryptOnePointOneString', $decrypted);
    }

    /**
     * @test
     */
    public function itCanDecryptOnePointOneStringWithTag()
    {
        $encrypted = file_get_contents(__DIR__ . '/files/OnePointOneStringNoTag.txt');
        $decrypted = Decrypter::decryptString($encrypted, self::PASSWORD);
        $this->assertEquals(b'itCanDecryptOnePointOneString', $decrypted);
    }
}
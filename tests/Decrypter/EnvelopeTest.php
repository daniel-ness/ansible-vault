<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use DanielNess\Ansible\Vault\Decrypter\Envelope;

/**
 * Class EnvelopeTest
 */
class EnvelopeTest extends TestCase
{
    /**
     * @test
     * @param Envelope $envelope
     * @param array $expect
     * @dataProvider dataProvider
     */
    public function itCanDetectYamlTag(Envelope $envelope, array $expect)
    {
        $this->assertEquals(
            $expect['has_tag'],
            $envelope->hasTagPrefix()
        );
    }

    /**
     * @test
     * @param Envelope $envelope
     * @param array $expect
     * @dataProvider dataProvider
     */
    public function itCanDetectVersion(Envelope $envelope, array $expect)
    {
        $this->assertEquals($expect['version'], $envelope->getVersion());
    }

    /**
     * @test
     * @param Envelope $envelope
     * @param array $expect
     * @dataProvider dataProvider
     */
    public function itCanExtractTheCipherText(Envelope $envelope, array $expect)
    {
        $this->assertEquals($expect['vault']['salt'], bin2hex($envelope->getSalt()));
        $this->assertEquals($expect['vault']['hmac'], $envelope->getHmac());
        $this->assertEquals($expect['vault']['cipher'], bin2hex($envelope->getCipherText()));
    }

    public function dataProvider(): array
    {
        return [
            [
                new Envelope(file_get_contents(__DIR__ . '/../files/OnePointOneString.txt')),
                [
                    'version' => Envelope::VERSION_1_1,
                    'has_tag' => true,
                    'vault' => [
                        'salt' => '8565b8e807e96b250c1af0c726c1a48115de5b9bcfab41fcbaae3a7960719760',
                        'hmac' => 'bf9e99765b189dcfa6efe87f42a62020128350933c0fc1c39aa3363e4e46f21b',
                        'cipher' => '3ab5480ac14c02762e17c2bf4deec594d80347e4f103df2abd2fb60023ed0a30'
                    ],
                ]
            ],
            [
                new Envelope(file_get_contents(__DIR__ . '/../files/OnePointOneStringNoTag.txt')),
                [
                    'version' => Envelope::VERSION_1_1,
                    'has_tag' => false,
                    'vault' => [
                        'salt' => '8565b8e807e96b250c1af0c726c1a48115de5b9bcfab41fcbaae3a7960719760',
                        'hmac' => 'bf9e99765b189dcfa6efe87f42a62020128350933c0fc1c39aa3363e4e46f21b',
                        'cipher' => '3ab5480ac14c02762e17c2bf4deec594d80347e4f103df2abd2fb60023ed0a30'
                    ],
                ],
            ],
        ];
    }
}
<?php
declare(strict_types=1);

namespace DanielNess\Ansible\Vault\Decrypter;

use DanielNess\Ansible\Vault\Decrypter\Exception\InvalidPayloadException;

/**
 * Class Envelope
 * @package DanielNess\Ansible\Vault\Decrypter
 */
class Envelope
{
    const ALG_AES128 = 'AES128';
    const ALG_AES256 = 'AES256';

    const VERSION_1_1 = '1.1';
    const VERSION_1_2 = '1.2';

    const HEADER = '$ANSIBLE_VAULT';

    /** @var string */
    private $payload;
    /** @var array */
    private $lines;
    /** @var string */
    private $version;
    /** @var string */
    private $cipherText;
    /** @var bool */
    private $tagPrefix;
    /** @var string */
    private $headerLine;
    /** @var string */
    private $salt;
    /** @var string */
    private $hmac;
    /** @var string */
    private $alg;

    /**
     * Envelope constructor.
     * @param string $payload
     * @throws InvalidPayloadException
     */
    public function __construct(string $payload)
    {
        // parse payload and separate into required/optional
        // components. At the end, if the cipher is blank and
        // no header has been detected the payload is deemed
        // invalid and an exception is thrown.

        $this->payload = trim($payload);
        $this->lines = explode("\n", $this->payload);
        $vaultLines = [];
        foreach ($this->lines as $i => $line) {
            $line = trim($line);

            if ($i == 0 && strpos($line, '!vault') === 0) {
                $this->tagPrefix = true;
                continue;
            }

            if ($i <= 1 && strpos($line, self::HEADER) === 0) {
                list($header, $version, $alg) = explode(';', $line);
                $this->headerLine = $line;
                $this->alg = $alg;
                $this->version = $version;
                continue;

            }

            if ($this->headerLine) {
                $vaultLines[] = $line;
                continue;
            }

            throw new InvalidPayloadException();
        }

        if (!$this->headerLine || count($vaultLines) < 1) {
            throw new InvalidPayloadException();
        }

        $vaultText = implode("", $vaultLines);
        $vaultText = hex2bin($vaultText);
        $vaultLines = explode("\n", $vaultText, 3);

        $this->salt = hex2bin($vaultLines[0]);
        $this->hmac = $vaultLines[1];
        $this->cipherText = hex2bin($vaultLines[2]);

        if (!$this->salt || !$this->hmac || !$this->cipherText) {
            throw new InvalidPayloadException();
        }
    }

    /**
     * @return bool
     */
    public function hasTagPrefix(): bool
    {
        return (bool) $this->tagPrefix;
    }

    /**
     * @return string
     */
    public function getVersion(): string
    {
        return $this->version;
    }

    /**
     * @return string
     */
    public function getCipherText(): string
    {
        return $this->cipherText;
    }

    /**
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * @return string
     */
    public function getHmac(): string
    {
        return $this->hmac;
    }

    /**
     * @return bool
     */
    public function isAES128(): bool
    {
        return ($this->alg === self::ALG_AES128);
    }

    /**
     * @return bool
     */
    public function isAES256(): bool
    {
        return ($this->alg === self::ALG_AES256);
    }
}
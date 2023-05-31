<?php

namespace TiGR\CompactEncrypter;

use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Encryption\Encrypter;
use RuntimeException;
use TiGR\CompactEncrypter\Encrypter as CompactEncrypterCore;

final class CompactEncrypter implements EncrypterContract
{
    /**
     * The encryption key.
     *
     * @var string
     */
    protected $key;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipher;

    /**
     * @var CompactEncrypterCore
     */
    protected $encrypter;

    /** @var Encrypter */
    private $laravelEncrypter;

    /**
     * Create a new encrypter instance.
     *
     * @param string $key
     * @param string $cipher
     * @return void
     *
     * @throws RuntimeException
     */
    public function __construct(string $key, string $cipher = 'AES-128-CBC')
    {
        $this->encrypter = new CompactEncrypterCore($key, $cipher);
        $this->cipher = $cipher;
        $this->key = $key;
    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param string $key
     * @param string $cipher
     * @return bool
     */
    public static function supported(string $key, string $cipher): bool
    {
        return CompactEncrypterCore::supported($key, $cipher);
    }

    /**
     * Create a new encryption key for the given cipher.
     *
     * @param string $cipher
     * @return string
     * @throws \Exception
     */
    public static function generateKey(string $cipher): string
    {
        return CompactEncrypterCore::generateKey($cipher);
    }

    /**
     * Encrypt the given value.
     *
     * @param mixed $value
     * @param bool $serialize
     * @param bool $useMac
     * @return string
     *
     * @throws \Exception
     */
    public function encrypt($value, $serialize = true, bool $useMac = true): string
    {
        try {
            return $this->encrypter->encrypt($value, $serialize, $useMac);
        } catch (EncryptException $exception) {
            throw new \Illuminate\Contracts\Encryption\EncryptException(
                $exception->getMessage(), $exception->getCode(), $exception
            );
        }
    }

    /**
     * Encrypt a string without serialization.
     *
     * @param string $value
     * @param bool $useMac
     * @return string
     *
     * @throws \Exception
     */
    public function encryptString(string $value, bool $useMac = true): string
    {
        return $this->encrypt($value, false, $useMac);
    }

    /**
     * Decrypt the given value.
     *
     * @param mixed $payload
     * @param bool $unserialize
     * @param bool $useMac
     * @return mixed
     *
     */
    public function decrypt($payload, $unserialize = true, bool $useMac = true)
    {
        if (!$this->isCompactPayload($payload)) {
            return $this->getLaravelEncrypter()->decrypt($payload, $unserialize);
        }

        try {
            return $this->encrypter->decrypt($payload, $unserialize, $useMac);
        } catch (DecryptException $exception) {
            throw new \Illuminate\Contracts\Encryption\DecryptException(
                $exception->getMessage(), $exception->getCode(), $exception
            );
        }
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @param string $payload
     * @param bool $useMac
     * @return string
     */
    public function decryptString($payload, bool $useMac = true): string
    {
        return $this->decrypt($payload, false, $useMac);
    }

    /**
     * Get the encryption key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->encrypter->getKey();
    }

    private function getLaravelEncrypter(): Encrypter
    {
        if (!isset($this->laravelEncrypter)) {
            $this->laravelEncrypter = new Encrypter($this->key, $this->cipher);
        }

        return $this->laravelEncrypter;
    }

    private function isCompactPayload($payload): bool
    {
        if (strlen($payload) % 4 !== 0 or strpos($payload, '-') !== false or strpos($payload, '_') !== false) {
            return true;
        }

        if (strpos($payload, '=') or strpos($payload, '/') !== false or strpos($payload, '+') !== false) {
            return false;
        }

        $payload = base64_decode($payload);

        if (is_string($payload) and substr($payload, 0, 7) === '{"iv":"' and json_decode($payload)) {
            return false;
        }

        return true;
    }
}

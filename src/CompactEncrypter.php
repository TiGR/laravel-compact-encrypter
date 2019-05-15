<?php

namespace TiGR\CompactEncrypter;

use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Contracts\Encryption\Encrypter as EncrypterContract;
use Illuminate\Contracts\Encryption\EncryptException;
use Illuminate\Encryption\Encrypter;

class CompactEncrypter implements EncrypterContract
{
    const SUPPORTED_KEY_SIZES = [
        'AES-128-CBC' => 16,
        'AES-256-CBC' => 32,
    ];

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

    /** @var Encrypter */
    private $laravelEncrypter;

    /**
     * Create a new encrypter instance.
     *
     * @param string $key
     * @param string $cipher
     * @return void
     *
     * @throws \RuntimeException
     */
    public function __construct(string $key, string $cipher = 'AES-128-CBC')
    {
        if (!static::supported($key, $cipher)) {
            if (!static::isCipherSupported($cipher)) {
                throw new \RuntimeException('The only supported ciphers are AES-128-CBC and AES-256-CBC.');
            } else {
                throw new \RuntimeException(sprintf('Invalid key length (%d) for %s cipher.', strlen($key), $cipher));
            }
        }

        $this->key    = $key;
        $this->cipher = $cipher;
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
        return self::isCipherSupported($cipher) ? self::SUPPORTED_KEY_SIZES[$cipher] == strlen($key) : false;
    }

    private static function isCipherSupported(string $cipher): bool
    {
        return isset(self::SUPPORTED_KEY_SIZES[$cipher]);
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
        return random_bytes(self::SUPPORTED_KEY_SIZES[$cipher]);
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
        $iv = random_bytes(openssl_cipher_iv_length($this->cipher));

        // First we will encrypt the value using OpenSSL. After this is encrypted we
        // will proceed to calculating a MAC for the encrypted value so that this
        // value can be verified later as not having been changed by the users.
        $value = openssl_encrypt(
            $serialize ? serialize($value) : $value,
            $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv
        );

        if ($value === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        // Once we get the encrypted value we'll go ahead and base64_encode the input
        // vector and create the MAC for the encrypted value so we can then verify
        // its authenticity. Then, we'll JSON the data into the "payload" array.
        if ($useMac) {
            $mac  = $this->hash($iv, $value);
            $pack = pack('a20a16a*', $mac, $iv, $value);
        } else {
            $pack = pack('a16a*', $iv, $value);
        }

        return $this->base64_encode($pack);
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

        $payload = $this->getPayload($payload, $useMac);

        // Here we will decrypt the value. If we are able to successfully decrypt it
        // we will then unserialize it and return it out to the caller. If we are
        // unable to decrypt this value we will throw out an exception message.
        $decrypted = openssl_decrypt(
            $payload['value'], $this->cipher, $this->key, OPENSSL_RAW_DATA, $payload['iv']
        );

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted) : $decrypted;
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
     * Create a MAC for the given value.
     *
     * @param string $iv
     * @param mixed $value
     * @return string
     */
    protected function hash($iv, $value)
    {
        return hash_hmac('sha1', $iv.$value, $this->key, true);
    }

    /**
     * Get the JSON array from the given payload.
     *
     * @param string $payload
     * @param bool $useMac
     * @return array
     *
     */
    protected function getPayload(string $payload, bool $useMac = true): array
    {
        $payload = unpack(($useMac ? 'a20mac/' : '').'a16iv/a*value', $this->base64_decode($payload));

        // If the payload is not valid JSON or does not have the proper keys set we will
        // assume it is invalid and bail out of the routine since we will not be able
        // to decrypt the given value. We'll also check the MAC for this encryption.
        if (!$this->validPayload($payload, $useMac)) {
            throw new DecryptException('The payload is invalid.');
        }

        if ($useMac and !$this->validMac($payload)) {
            throw new DecryptException('The MAC is invalid.');
        }

        return $payload;
    }

    /**
     * Verify that the encryption payload is valid.
     *
     * @param mixed $payload
     * @param bool $useMac
     * @return bool
     */
    protected function validPayload($payload, bool $useMac = true)
    {
        return is_array($payload) && isset($payload['iv'], $payload['value']) && ($useMac ? isset($payload['mac']) : true) &&
            strlen($payload['iv']) === openssl_cipher_iv_length($this->cipher);
    }

    /**
     * Determine if the MAC for the given payload is valid.
     *
     * @param array $payload
     * @return bool
     */
    protected function validMac(array $payload)
    {
        return hash_equals($payload['mac'], $this->hash($payload['iv'], $payload['value']));
    }

    /**
     * Get the encryption key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * URL-safe base64_encode
     *
     * @param string $data
     * @return string
     */
    private function base64_encode(string $data): string
    {
        return strtr(rtrim(base64_encode($data), '='), '+/', '-_');
    }

    /**
     * URL-safe base64_decode
     *
     * @param string $data
     * @return string
     */
    private function base64_decode(string $data): string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function getLaravelEncrypter(): Encrypter
    {
        if (!isset($this->laravelEncrypter)) {
            $this->laravelEncrypter = new Encrypter($this->getKey(), $this->cipher);
        }

        return $this->laravelEncrypter;
    }

    private function isCompactPayload($payload): bool
    {
        if (strpos($payload, '=') or strpos($payload, '/') !== false or strpos($payload, '+') !== false) {
            return false;
        }

        if (strpos($payload, '-') !== false or strpos($payload, '_') !== false) {
            return true;
        }

        $payload = base64_decode($payload);

        if (is_string($payload) and substr($payload, 0, 7) === '{"iv":"' and json_decode($payload)) {
            return false;
        }

        return true;
    }
}

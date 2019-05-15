<?php /** @noinspection PhpUnhandledExceptionInspection */

namespace TiGR\CompactEncrypter\Tests;

use Illuminate\Contracts\Encryption\DecryptException;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use TiGR\CompactEncrypter\CompactEncrypter;

/**
 * Class CompactEncrypterTest
 * @package TiGR\CompactEncrypter\Tests
 * @covers \TiGR\CompactEncrypter\CompactEncrypter
 */
final class CompactEncrypterTest extends TestCase
{
    public function testEncryption()
    {
        $e = new CompactEncrypter(str_repeat('a', 16));
        $encrypted = $e->encrypt('foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testRawStringEncryption()
    {
        $e = new CompactEncrypter(str_repeat('a', 16));
        $encrypted = $e->encryptString('foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decryptString($encrypted));
    }

    public function testEncryptionUsingBase64EncodedKey()
    {
        $e = new CompactEncrypter(random_bytes(16));
        $encrypted = $e->encrypt('foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testWithCustomCipher()
    {
        $e = new CompactEncrypter(str_repeat('b', 32), 'AES-256-CBC');
        $encrypted = $e->encrypt('bar');
        $this->assertNotEquals('bar', $encrypted);
        $this->assertEquals('bar', $e->decrypt($encrypted));
        $e = new CompactEncrypter(random_bytes(32), 'AES-256-CBC');
        $encrypted = $e->encrypt('foo');
        $this->assertNotEquals('foo', $encrypted);
        $this->assertEquals('foo', $e->decrypt($encrypted));
    }

    public function testDoNoAllowLongerKey()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid key length (32) for AES-128-CBC cipher.');
        new CompactEncrypter(str_repeat('z', 32));
    }

    public function testWithBadKeyLength()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Invalid key length (5) for AES-128-CBC cipher.');
        new CompactEncrypter(str_repeat('a', 5));
    }

    public function testWithBadKeyLengthAlternativeCipher()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The only supported ciphers are AES-128-CBC and AES-256-CBC.');
        new CompactEncrypter(str_repeat('a', 16), 'AES-256-CFB8');
    }

    public function testWithUnsupportedCipher()
    {
        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The only supported ciphers are AES-128-CBC and AES-256-CBC.');
        new CompactEncrypter(str_repeat('c', 16), 'AES-256-CFB8');
    }

    public function testExceptionThrownWhenPayloadIsInvalid()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('The payload is invalid.');
        $e = new CompactEncrypter(str_repeat('a', 16));
        $payload = $e->encrypt('foo');
        $payload = substr($payload, 0, -3);
        $e->decrypt($payload);
    }

    public function testExceptionThrownWithDifferentKey()
    {
        $this->expectException(DecryptException::class);
        $this->expectExceptionMessage('The MAC is invalid.');
        $a = new CompactEncrypter(str_repeat('a', 16));
        $b = new CompactEncrypter(str_repeat('b', 16));
        $b->decrypt($a->encrypt('baz'));
    }

    public function testNoMac()
    {
        $encrypter = $this->encryptRandomBytes($encrypted, $data, 8, false);
        $this->assertEquals($data, $encrypter->decryptString($encrypted, false));
    }

    public function testEncryptedLength()
    {
        $this->encryptRandomBytes($encrypted, $data);

        $this->assertNotEquals($encrypted, $data);
        $this->assertEquals(70, strlen($encrypted));

        $this->encryptRandomBytes($encrypted, $data, 8, false);

        $this->assertEquals(43, strlen($encrypted));
    }

    public function testFallbackDecryption()
    {
        $encrypter = $this->getEncrypter('AES-256-CBC', base64_decode("aRsWVY+rZrst5fFO94WssJqSx6+yxeMT90to/TG+XKI="));
        $this->assertEquals(
            'Encrypt!',
            $encrypter->decryptString(
                "eyJpdiI6Ikh1ZGM5UTltT0ZqZENqXC9nNjN3NklRPT0iLCJ2YWx1ZSI6ImlEdXhUVW1rWnZmeE5RbXRGQVBwK2c9PSIsIm1hYyI6ImY4MTRmMjk3MmM3NGI1ZGI1OTg2NzY2ODc5OGU5MmRkMTQ2MWJhNTU3ODQzMjRkNzVhMDIzMjIxNzZiZmE2ZjMifQ=="
            )
        );
        $this->assertEquals(
            'Encrypt!',
            $encrypter->decryptString(
                "eyJpdiI6IlBOeUsrc1VObkFXNmdTRzFaUmVKc3c9PSIsInZhbHVlIjoiV0FZNDVlOVgxQ1VaZ3pzbDJuNUMrQT09IiwibWFjIjoiNGU1YjAzODI2OTI0MjIzMzMzZjQxOWYzYTRmZjk4NzMyY2Q2YThkY2UzNjQ1ODNkNGM5YmYyN2NmZTgzNjEzYiJ9"
            )
        );

        // test for payload that looks like 100% valid base64
        $encrypter = new CompactEncrypter(base64_decode("Smn/UbkmjlRyI5cKb2XBYp9r+Ltb9sSHMn/9OrcuJSg="), 'AES-256-CBC');
        $this->assertEquals(
            'Lorem ipsum dolor sit amet, consectetur',
            $encrypter->decryptString(
                "QwuufcJe7kqB85tkoqqqKcrP7BiVVS8rF11lwi0nrXHeSyuOyVlZwxp18zfpW2uC9uPco9gfMXWCDmKgOEoC5gOjhHYmGj7uihFhmYlbXDZTXeO3"
            )
        );
    }

    public function testBadMac()
    {
        $encrypter = $this->encryptRandomBytes($encrypted, $data);
        $this->expectExceptionMessage('The MAC is invalid.');
        $encrypter->decryptString(str_shuffle($encrypted));
    }

    public function testUnencryptable()
    {
        $encrypter = $this->encryptRandomBytes($encrypted, $data, 8, false);
        $this->expectExceptionMessage('Could not decrypt the data.');
        $encrypter->decryptString(substr($encrypted, 0, -16).str_shuffle(substr($encrypted, -16)), false);
    }

    private function getEncrypter(string $cipher = 'AES-256-CBC', string $key = null): CompactEncrypter
    {
        return new CompactEncrypter($key ?: CompactEncrypter::generateKey($cipher), $cipher);
    }

    private function encryptRandomBytes(
        string &$encrypted = null,
        string &$data = null,
        int $bytes = 8,
        bool $useMac = true
    ): CompactEncrypter {
        $data = random_bytes($bytes);

        if (!isset($encrypter)) {
            $encrypter = $this->getEncrypter();
        }

        $encrypted = $encrypter->encryptString($data, $useMac);

        return $encrypter;
    }
}

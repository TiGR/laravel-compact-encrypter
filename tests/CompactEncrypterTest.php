<?php /** @noinspection PhpUnhandledExceptionInspection */

namespace TiGR\CompactEncrypter\Tests;

use Illuminate\Encryption\Encrypter;
use PHPUnit\Framework\TestCase;
use TiGR\CompactEncrypter\CompactEncrypter;

class CompactEncrypterTest extends TestCase
{
    public function testNoMac()
    {
        $encrypter = new CompactEncrypter(CompactEncrypter::generateKey('AES-256-CBC'), 'AES-256-CBC');

        $encrypted = $encrypter->encryptString($data = random_bytes(8), false);
        $this->assertEquals($data, $encrypter->decryptString($encrypted, false));
    }

    public function testEncrypt()
    {
        $encrypter = new CompactEncrypter(CompactEncrypter::generateKey('AES-256-CBC'), 'AES-256-CBC');

        $encrypted = $encrypter->encryptString($data = random_bytes(8), false);
        $this->assertNotEquals($encrypted, $data);
        $this->assertEquals(43, strlen($encrypted));

        $encrypted = $encrypter->encryptString($data = random_bytes(8));
        $this->assertNotEquals($encrypted, $data);
        $this->assertEquals(70, strlen($encrypted));
    }

    public function testDecrypt()
    {
        $encrypter = new CompactEncrypter(CompactEncrypter::generateKey('AES-128-CBC'), 'AES-128-CBC');

        $encrypted = $encrypter->encryptString($data = random_bytes(8));
        $this->assertEquals($data, $encrypter->decryptString($encrypted));

        $encrypted = $encrypter->encryptString($data = random_bytes(1233));
        $this->assertEquals($data, $encrypter->decryptString($encrypted));

        $encrypter = new CompactEncrypter(CompactEncrypter::generateKey('AES-256-CBC'), 'AES-256-CBC');

        $encrypted = $encrypter->encryptString($data = random_bytes(8));
        $this->assertEquals($data, $encrypter->decryptString($encrypted));

        $encrypted = $encrypter->encryptString($data = random_bytes(1233));
        $this->assertEquals($data, $encrypter->decryptString($encrypted));
    }

    public function testFallbackDecrypt()
    {
        $cipher           = 'AES-256-CBC';
        $key              = Encrypter::generateKey($cipher);
        $originalEncypter = new Encrypter($key, $cipher);
        $encrypted        = $originalEncypter->encryptString('Encrypt!');
        $encrypter        = new CompactEncrypter($key, $cipher);
        $this->assertEquals('Encrypt!', $encrypter->decryptString($encrypted));
    }

    public function testSupportedBadKeySize()
    {
        $this->expectExceptionMessage('Invalid key length (16) for AES-256-CBC cipher.');
        new CompactEncrypter(CompactEncrypter::generateKey('AES-128-CBC'), 'AES-256-CBC');
    }

    public function testSupportedBadCipher()
    {
        $this->expectExceptionMessage('The only supported ciphers are AES-128-CBC and AES-256-CBC.');
        new CompactEncrypter('', 'DES-CBC');
    }
}

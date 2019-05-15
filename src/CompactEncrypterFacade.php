<?php

namespace TiGR\CompactEncrypter;

use Illuminate\Support\Facades\Facade;

/**
 * @method static string encrypt($value, bool $serialize = true, bool $useMac = true)
 * @method static string encryptString(string $value, bool $useMac = true)
 * @method static string decrypt($payload, bool $unserialize = true, bool $useMac = true)
 * @method static string decryptString(string $payload, bool $useMac = true)
 *
 * @see \Illuminate\Encryption\Encrypter
 */
class CompactEncrypterFacade extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'encrypter';
    }
}

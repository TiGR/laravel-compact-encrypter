<?php

namespace TiGR\CompactEncrypter;

use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class CompactEncrypterServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->app->singleton('encrypter', function (Application $app) {
            $config = $app->make('config');

            if (null === $key = $config->get('app.key')) {
                throw new \RuntimeException(
                    'No application encryption key has been specified.'
                );
            }

            // If the key starts with "base64:", we will need to decode the key before handing
            // it off to the encrypter. Keys may be base-64 encoded for presentation and we
            // want to make sure to convert them back to the raw bytes before encrypting.
            if (strpos($key, 'base64:') === 0) {
                $key = base64_decode(substr($key, 7));
            }

            return new CompactEncrypter($key, $config->get('app.cipher'));
        });
        $this->app->alias('encrypter', Encrypter::class);
        $this->app->alias('encrypter', CompactEncrypter::class);
    }
}

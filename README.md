# URL-safe Compact Encrypter for Laravel

![Travis (.org)](https://img.shields.io/travis/TiGR/laravel-compact-encrypter.svg)
![PHP from Packagist](https://img.shields.io/badge/php-7.0%2B-blue.svg)
![Laravel Version](https://img.shields.io/badge/laravel-5.5%2B-blue.svg)
![Packagist Version](https://img.shields.io/packagist/v/TiGR/laravel-compact-encrypter.svg)
![GitHub](https://img.shields.io/github/license/TiGR/laravel-compact-encrypter.svg)

Drop-in replacement for Laravel encrypter that produces much more concise and 
URL-safe output with fallback for encrypted data in old format. For Laravel 5.5+.

## Installation

```
composer require tigr/laravel-compact-encrypter
```

Then Laravel should do the magic and register our service provider.

## Why?

Laravel's encrypter is very inefficient when it comes to space usage. It takes 
64 bytes of raw encrypted data and converts it into 192 characters. How?

Laravel stores encrypted data in base64-encoded JSON containing base64 and HEX strings inside. 
So, `base64_encode(json_encode(base64_encode(data) + sha256 hex hash))`. Just compare encryption 
of simple string "hello":

```
# Laravel Encrypter: 192 characters long
$ artisan tinker
>>> Crypt::encryptString('hello')
=> "eyJpdiI6IlZRZFY5TVZiZVdNSlg3RVdDYTNDbHc9PSIsInZhbHVlIjoiNk9rXC9oV3hZaWEzNE95SU5xMUVHUWc9PSIsIm1hYyI6ImIyZDQ1MTdiODlhMzU1ZjQ1NmU3N2ZlN2I4OGU0Yzc2MjIyZDBkMzAwMGViNjM2OTFlMTZkOGY4MDFjYTg1NDIifQ=="

# add Compact Encrypter
$ composer require tigr/laravel-compact-encrypter

# Compact Encrypter: 70 characters long
$ artisan tinker
>>> Crypt::encryptString('hello')
=> "ABvcrldH1QNn8AgEL_LY-E_Cj04MRWPn3M-kSuvf3DAjzsNfFqC_lUml6iqGkRTjlox2kA"

# Compact Encrypter dropping verification hash: 53 characters long
>>> Crypt::encryptString('hello', false)
=> "z4zztewR8vQ7QId_P6diDRW2DvVPhwf4xh8gNss4G1o"
```

## Who cares?

First, if you have some encrypted cookies, you might easily run into 400 errors 
with "header too long" from your server, or from load-balancing/DDoS-protection 
proxies in the middle. On average, Compact Encrypter produces 25-275% more 
compact output or up to 360% more compact with hash dropped.

Second, you might want to use self-contained tokens in URLs (no need for token DB), 
but guess what, 192 characters some of which are URL-escaped are way too ugly.

## How does it work?

1. No intermediate base64 or hex encoding, all data is raw binary.
2. No JSON, use pack()/unpack().
3. Use URL-safe version of base64 (drop trailing '=', replace '/+' with '-_').
4. For hashing, use SHA1 instead of SHA256. I know, I know, but for real-world 
   purposes SHA1 is still good enough.
5. Allow dropping Mac (validation hash) whatsoever in case you want it really short.
6. And provide fallback decryption if we ever encounter data encrypted with 
   Laravel Encryptor

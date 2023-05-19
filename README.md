Google Authenticator PHP class
==============================

* Copyright (c) 2012-2016, [https://www.phpgangsta.de](https://www.phpgangsta.de)
* Author: Michael Kliewe, [@PHPGangsta](https://twitter.com/PHPGangsta) and [contributors](https://github.com/PHPGangsta/GoogleAuthenticator/graphs/contributors)
* Licensed under the BSD License.

[![PHPUnit](https://github.com/Coderberg/GoogleAuthenticator/actions/workflows/tests.yml/badge.svg)](https://github.com/Coderberg/GoogleAuthenticator/actions/workflows/tests.yml) [![Code Quality](https://github.com/Coderberg/GoogleAuthenticator/actions/workflows/lint.yml/badge.svg)](https://github.com/Coderberg/GoogleAuthenticator/actions/workflows/lint.yml) 

This PHP class can be used to interact with the Google Authenticator mobile app for 2-factor-authentication. This class
can generate secrets, generate codes, validate codes and present a QR-Code for scanning the secret. It implements TOTP 
according to [RFC6238](https://tools.ietf.org/html/rfc6238)

For a secure installation you have to make sure that used codes cannot be reused (replay-attack). You also need to
limit the number of verifications, to fight against brute-force attacks. For example, you could limit the amount of
verifications to 10 tries within 10 minutes for one IP address (or IPv6 block). It depends on your environment.

### Supported PHP Versions
- PHP 8.0
- PHP 8.1
- PHP 8.2

### Installation
```shell
composer req coderberg/google-authenticator
```

### Usage

```php
<?php

use Coderberg\GoogleAuthenticator;

$ga = new GoogleAuthenticator();
$secret = $ga->createSecret();
echo "Secret is: ".$secret."\n\n";

$qrCodeUrl = $ga->getQRCodeGoogleUrl('Blog', $secret);
echo "Google Charts URL for the QR-Code: ".$qrCodeUrl."\n\n";

$oneCode = $ga->getCode($secret);
echo "Checking Code '$oneCode' and Secret '$secret':\n";

$checkResult = $ga->verifyCode($secret, $oneCode, 2);    // 2 = 2*30sec clock tolerance
if ($checkResult) {
    echo 'OK';
} else {
    echo 'FAILED';
}
```
Running the script provides the following output:
```
Secret is: OQB6ZZGYHCPSX4AK

Google Charts URL for the QR-Code: https://www.google.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/infoATphpgangsta.de%3Fsecret%3DOQB6ZZGYHCPSX4AK

Checking Code '848634' and Secret 'OQB6ZZGYHCPSX4AK':
OK
```

<?php

namespace PHPGangsta\Tests;

use PHPGangsta\GoogleAuthenticator;
use PHPUnit\Framework\TestCase;

final class GoogleAuthenticatorTest extends TestCase
{
    protected GoogleAuthenticator $googleAuthenticator;

    protected function setUp(): void
    {
        $this->googleAuthenticator = new GoogleAuthenticator();
    }

    public function codeProvider(): array
    {
        // Secret, time, code
        return [
            ['SECRET', '0', '200470'],
            ['SECRET', '1385909245', '780018'],
            ['SECRET', '1378934578', '705013'],
        ];
    }

    public function testItCanBeInstantiated()
    {
        $ga = new GoogleAuthenticator();

        $this->assertInstanceOf(GoogleAuthenticator::class, $ga);
    }

    /**
     * @throws \Exception
     */
    public function testCreateSecretDefaultsToSixteenCharacters()
    {
        $ga = $this->googleAuthenticator;
        $secret = $ga->createSecret();

        $this->assertSame(16, strlen($secret));
    }

    /**
     * @throws \Exception
     */
    public function testCreateSecretLengthCanBeSpecified()
    {
        $ga = $this->googleAuthenticator;

        for ($secretLength = 16; $secretLength < 100; ++$secretLength) {
            $secret = $ga->createSecret($secretLength);

            $this->assertSame(strlen($secret), $secretLength);
        }
    }

    /**
     * @dataProvider codeProvider
     */
    public function testGetCodeReturnsCorrectValues($secret, $timeSlice, $code)
    {
        $generatedCode = $this->googleAuthenticator->getCode($secret, $timeSlice);

        $this->assertSame($code, $generatedCode);
    }

    public function testGetQRCodeGoogleUrlReturnsCorrectUrl()
    {
        $secret = 'SECRET';
        $name = 'Test';
        $url = $this->googleAuthenticator->getQRCodeGoogleUrl($name, $secret);
        $urlParts = parse_url($url);

        parse_str($urlParts['query'], $queryStringArray);

        $this->assertSame('https', $urlParts['scheme']);
        $this->assertSame('api.qrserver.com', $urlParts['host']);
        $this->assertSame('/v1/create-qr-code/', $urlParts['path']);

        $expectedChl = 'otpauth://totp/'.$name.'?secret='.$secret;

        $this->assertSame($queryStringArray['data'], $expectedChl);
    }

    public function testVerifyCode()
    {
        $secret = 'SECRET';
        $code = $this->googleAuthenticator->getCode($secret);
        $result = $this->googleAuthenticator->verifyCode($secret, $code);

        $this->assertSame(true, $result);

        $code = 'INVALIDCODE';
        $result = $this->googleAuthenticator->verifyCode($secret, $code);

        $this->assertSame(false, $result);
    }

    public function testVerifyCodeWithLeadingZero()
    {
        $secret = 'SECRET';
        $code = $this->googleAuthenticator->getCode($secret);
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertSame(true, $result);

        $code = '0'.$code;
        $result = $this->googleAuthenticator->verifyCode($secret, $code);
        $this->assertSame(false, $result);
    }

    public function testSetCodeLength()
    {
        $result = $this->googleAuthenticator->setCodeLength(6);

        $this->assertInstanceOf(GoogleAuthenticator::class, $result);
    }
}

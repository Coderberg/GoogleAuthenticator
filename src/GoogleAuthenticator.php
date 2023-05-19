<?php

declare(strict_types=1);

namespace Coderberg;

/**
 * PHP Class for handling Google Authenticator 2-factor authentication.
 *
 * @author Michael Kliewe
 * @copyright 2012 Michael Kliewe
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 *
 * @see http://www.phpgangsta.de/
 */
final class GoogleAuthenticator
{
    private int $_codeLength = 6;

    /**
     * Create new secret.
     * 16 characters, randomly chosen from the allowed base32 characters.
     *
     * @throws \Exception
     */
    public function createSecret(int $secretLength = 16): string
    {
        $validChars = $this->_getBase32LookupTable();

        // Valid secret lengths are 80 to 640 bits
        if ($secretLength < 16 || $secretLength > 128) {
            throw new \Exception('Bad secret length');
        }
        $secret = '';
        $rnd = false;
        if (\function_exists('random_bytes')) {
            $rnd = random_bytes($secretLength);
        } elseif (\function_exists('openssl_random_pseudo_bytes')) {
            $rnd = openssl_random_pseudo_bytes($secretLength, $cryptoStrong);
            if (!$cryptoStrong) {
                $rnd = false;
            }
        }
        if (false !== $rnd) {
            for ($i = 0; $i < $secretLength; ++$i) {
                $secret .= $validChars[\ord($rnd[$i]) & 31];
            }
        } else {
            throw new \Exception('No source of secure random');
        }

        return $secret;
    }

    /**
     * Calculate the code, with given secret and point in time.
     */
    public function getCode(string $secret, int $timeSlice = null): string
    {
        if (null === $timeSlice) {
            $timeSlice = floor(time() / 30);
        }

        $secretkey = $this->_base32Decode($secret);

        // Pack time into binary string
        $time = \chr(0).\chr(0).\chr(0).\chr(0).pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac('SHA1', $time, $secretkey, true);
        // Use last nipple of result as index/offset
        $offset = \ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value &= 0x7FFFFFFF;

        $modulo = 10 ** $this->_codeLength;

        return str_pad((string) ($value % $modulo), $this->_codeLength, '0', \STR_PAD_LEFT);
    }

    /**
     * Get QR-Code URL for image, from Google charts.
     */
    public function getQRCodeGoogleUrl(string $name, string $secret, string $title = null, array $params = []): string
    {
        $width = !empty($params['width']) && (int) $params['width'] > 0 ? (int) $params['width'] : 200;
        $height = !empty($params['height']) && (int) $params['height'] > 0 ? (int) $params['height'] : 200;
        $level = !empty($params['level']) && \in_array($params['level'], ['L', 'M', 'Q', 'H']) ? $params['level'] : 'M';

        $urlencoded = urlencode('otpauth://totp/'.$name.'?secret='.$secret);
        if (isset($title)) {
            $urlencoded .= urlencode('&issuer='.urlencode($title));
        }

        return "https://api.qrserver.com/v1/create-qr-code/?data=$urlencoded&size={$width}x{$height}&ecc=$level";
    }

    /**
     * Check if the code is correct.
     * This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now.
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1, int $currentTimeSlice = null): bool
    {
        if (null === $currentTimeSlice) {
            $currentTimeSlice = floor(time() / 30);
        }

        if ($this->_codeLength !== \strlen($code)) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $calculatedCode = $this->getCode($secret, (int) $currentTimeSlice + $i);
            if ($this->timingSafeEquals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Set the code length, should be >=6.
     */
    public function setCodeLength(int $length): self
    {
        $this->_codeLength = $length;

        return $this;
    }

    /**
     * Helper class to decode base32.
     */
    private function _base32Decode($secret): bool|string
    {
        if (empty($secret)) {
            return '';
        }

        $base32chars = $this->_getBase32LookupTable();
        $base32charsFlipped = array_flip($base32chars);

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = [6, 4, 3, 1, 0];
        if (!\in_array($paddingCharCount, $allowedValues)) {
            return false;
        }
        for ($i = 0; $i < 4; ++$i) {
            if ($paddingCharCount == $allowedValues[$i] &&
                substr($secret, -$allowedValues[$i]) !== str_repeat($base32chars[32], $allowedValues[$i])) {
                return false;
            }
        }
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binaryString = '';
        $secretCount = \count($secret);
        for ($i = 0; $i < $secretCount; $i += 8) {
            $x = '';
            if (!\in_array($secret[$i], $base32chars)) {
                return false;
            }
            for ($j = 0; $j < 8; ++$j) {
                $x .= str_pad(base_convert((string) @$base32charsFlipped[@$secret[$i + $j]], 10, 2), 5, '0', \STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            foreach ($eightBits as $z => $eightBit) {
                $binaryString .= (($y = \chr((int) base_convert($eightBit, 2, 10))) || 48 == \ord($y)) ? $y : '';
            }
        }

        return $binaryString;
    }

    /**
     * Get array with all 32 characters for decoding from/encoding to base32.
     */
    private function _getBase32LookupTable(): array
    {
        return [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '=',  // padding char
        ];
    }

    /**
     * A timing safe equals comparison
     * more info here: http://blog.ircmaxell.com/2014/11/its-all-about-time.html.
     */
    private function timingSafeEquals(string $safeString, string $userString): bool
    {
        if (\function_exists('hash_equals')) {
            return hash_equals($safeString, $userString);
        }
        $safeLen = \strlen($safeString);
        $userLen = \strlen($userString);

        if ($userLen !== $safeLen) {
            return false;
        }

        $result = 0;

        for ($i = 0; $i < $userLen; ++$i) {
            $result |= (\ord($safeString[$i]) ^ \ord($userString[$i]));
        }

        // They are only identical strings if $result is exactly 0...
        return 0 === $result;
    }
}

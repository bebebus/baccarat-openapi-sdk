<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class Signing
{
    public static function signBody(string $rawBodyBytes, string $hmacSecret): string
    {
        if ($hmacSecret === '') {
            throw new BaccaratSdkException('hmacSecret must be non-empty', 'INVALID_CONFIG');
        }
        // CRITICAL: Pass raw UTF-8 string bytes of $hmacSecret directly — NEVER base64_decode!
        return hash_hmac('sha256', $rawBodyBytes, $hmacSecret);
    }

    public static function verifySignature(string $rawBodyBytes, ?string $signatureHeader, string $hmacSecret): bool
    {
        if ($hmacSecret === '' || $signatureHeader === null) {
            return false;
        }
        $trimmed = trim($signatureHeader);
        if (!preg_match('/^[0-9a-fA-F]{64}$/', $trimmed)) {
            return false;
        }
        $expectedRaw = hex2bin(self::signBody($rawBodyBytes, $hmacSecret));
        $actualRaw = hex2bin(strtolower($trimmed));
        if ($expectedRaw === false || $actualRaw === false) {
            return false;
        }
        return hash_equals($expectedRaw, $actualRaw);
    }

    public static function verifyWebhookHeaders(
        ?string $apiKeyHeader,
        ?string $signatureHeader,
        string $rawBodyBytes,
        string $expectedApiKey,
        string $hmacSecret
    ): string {
        $expected = trim($expectedApiKey);
        $actual = $apiKeyHeader !== null ? trim($apiKeyHeader) : '';
        if ($expected === '' || $actual === '' || !hash_equals($expected, $actual)) {
            return StatusCode::SC_AUTHENTICATION_FAILED;
        }
        if (!self::verifySignature($rawBodyBytes, $signatureHeader, $hmacSecret)) {
            return StatusCode::SC_INVALID_SIGNATURE;
        }
        return StatusCode::SC_OK;
    }
}

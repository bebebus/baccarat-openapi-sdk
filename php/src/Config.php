<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class Config
{
    public const ENV_SANDBOX = 'SANDBOX';
    public const ENV_PRODUCTION = 'PRODUCTION';
    public const SANDBOX_BASE_URL = 'https://api.lt.cniia.cloud';

    public readonly string $apiKey;
    public readonly string $hmacSecret;
    public readonly string $environment;
    public readonly string $baseUrl;
    public readonly int $timeoutMs;
    public readonly bool $sendTimestamp;

    public function __construct(
        string $apiKey,
        string $hmacSecret,
        string $environment = self::ENV_PRODUCTION,
        ?string $baseUrl = null,
        int $timeoutMs = 8000,
        bool $sendTimestamp = false
    ) {
        $trimmedKey = trim($apiKey);
        if ($trimmedKey === '') {
            throw new BaccaratSdkException('apiKey is required', 'INVALID_CONFIG');
        }
        if ($hmacSecret === '') {
            throw new BaccaratSdkException('hmacSecret is required', 'INVALID_CONFIG');
        }
        $resolved = $baseUrl !== null ? trim($baseUrl) : '';
        if ($resolved === '') {
            if ($environment === self::ENV_SANDBOX) {
                $resolved = self::SANDBOX_BASE_URL;
            } else {
                throw new BaccaratSdkException(
                    'baseUrl is required when environment is PRODUCTION',
                    'INVALID_CONFIG'
                );
            }
        }
        if (!preg_match('#^https?://#i', $resolved)) {
            throw new BaccaratSdkException("baseUrl must start with http:// or https://: {$resolved}", 'INVALID_CONFIG');
        }
        if ($timeoutMs <= 0) {
            throw new BaccaratSdkException('timeoutMs must be positive', 'INVALID_CONFIG');
        }
        $this->apiKey = $trimmedKey;
        $this->hmacSecret = $hmacSecret;
        $this->environment = $environment;
        $this->baseUrl = rtrim($resolved, '/');
        $this->timeoutMs = $timeoutMs;
        $this->sendTimestamp = $sendTimestamp;
    }
}

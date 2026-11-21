<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class WebhookDispatcher
{
    private Config $config;
    private InMemoryWallet $wallet;

    public function __construct(Config $config, InMemoryWallet $wallet)
    {
        $this->config = $config;
        $this->wallet = $wallet;
    }

    /** @return array{statusCode: int, body: array<string, mixed>} */
    public function handle(
        string $routePath,
        ?string $apiKeyHeader,
        ?string $signatureHeader,
        string $rawBody
    ): array {
        $traceId = '';
        $decoded = json_decode($rawBody, true);
        if (is_array($decoded) && !array_is_list($decoded)) {
            if (isset($decoded['traceId']) && is_string($decoded['traceId'])) {
                $traceId = substr(trim($decoded['traceId']), 0, 128);
            }
        } else {
            $decoded = null;
        }

        $auth = Signing::verifyWebhookHeaders(
            $apiKeyHeader,
            $signatureHeader,
            $rawBody,
            $this->config->apiKey,
            $this->config->hmacSecret
        );
        if ($auth !== StatusCode::SC_OK) {
            return [
                'statusCode' => 200,
                'body' => ['traceId' => $traceId, 'status' => $auth, 'message' => 'Auth/signature failed'],
            ];
        }
        if ($decoded === null) {
            return [
                'statusCode' => 200,
                'body' => ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Invalid JSON body'],
            ];
        }

        $clean = rtrim((string) strtok($routePath, '?'), '/');
        if (str_ends_with($clean, '/wallet/balance')) {
            return ['statusCode' => 200, 'body' => $this->wallet->onBalance($decoded)];
        }
        if (str_ends_with($clean, '/wallet/bet')) {
            return ['statusCode' => 200, 'body' => $this->wallet->onBet($decoded)];
        }
        if (str_ends_with($clean, '/wallet/bet_result')) {
            return ['statusCode' => 200, 'body' => $this->wallet->onBetResult($decoded)];
        }
        if (str_ends_with($clean, '/wallet/rollback')) {
            return ['statusCode' => 200, 'body' => $this->wallet->onRollback($decoded)];
        }

        return [
            'statusCode' => 200,
            'body' => ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => "Unknown route {$clean}"],
        ];
    }
}

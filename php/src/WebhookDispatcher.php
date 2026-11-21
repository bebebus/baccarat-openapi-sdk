<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class WebhookDispatcher
{
    public const MAX_WEBHOOK_BODY_BYTES = 1048576;

    private Config $config;
    private WalletHandlerInterface $wallet;

    public function __construct(Config $config, WalletHandlerInterface $wallet)
    {
        $this->config = $config;
        $this->wallet = $wallet;
    }

    private static function extractTraceHint(string $rawBody): string
    {
        $head = substr($rawBody, 0, 1024);
        if (preg_match('/"traceId"\s*:\s*"([A-Za-z0-9_.:-]{1,128})"/', $head, $m)) {
            return $m[1];
        }
        return '';
    }

    /** @return array{statusCode: int, body: array<string, mixed>} */
    public function handle(
        string $routePath,
        ?string $apiKeyHeader,
        ?string $signatureHeader,
        string $rawBody
    ): array {
        if (strlen($rawBody) > self::MAX_WEBHOOK_BODY_BYTES) {
            return [
                'statusCode' => 200,
                'body' => ['traceId' => '', 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Request body exceeds 1 MiB limit'],
            ];
        }

        // Verify X-API-Key & X-Signature over raw bytes BEFORE decoding JSON!
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
                'body' => ['traceId' => self::extractTraceHint($rawBody), 'status' => $auth, 'message' => 'Auth/signature failed'],
            ];
        }

        $probeObj = json_decode($rawBody, false, 64);
        if (!($probeObj instanceof \stdClass)) {
            return [
                'statusCode' => 200,
                'body' => ['traceId' => '', 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Invalid JSON body'],
            ];
        }

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($rawBody, true, 64);
        $traceId = isset($decoded['traceId']) && is_string($decoded['traceId'])
            ? substr(trim($decoded['traceId']), 0, 128)
            : '';

        $clean = rtrim((string) strtok($routePath, '?'), '/');
        try {
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
        } catch (BaccaratSdkException $e) {
            $st = str_starts_with($e->errorCode, 'SC_') ? $e->errorCode : StatusCode::SC_INVALID_REQUEST;
            return [
                'statusCode' => 200,
                'body' => ['traceId' => $traceId, 'status' => $st, 'message' => $e->getMessage()],
            ];
        } catch (\Throwable $e) {
            return [
                'statusCode' => 200,
                'body' => ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Wallet handler error'],
            ];
        }
    }
}

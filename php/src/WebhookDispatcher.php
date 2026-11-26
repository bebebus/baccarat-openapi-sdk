<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class WebhookDispatcher
{
    public const MAX_WEBHOOK_BODY_BYTES = 1048576;

    /** @var list<string> */
    private const INCOMING_DECIMAL_ERROR_CODES = [
        'INVALID_DECIMAL_AMOUNT',
        'DECIMAL_PRECISION_EXCEEDED',
        'NEGATIVE_DECIMAL_FORBIDDEN',
    ];

    private string $apiKey;
    private string $hmacSecret;
    private WalletHandlerInterface $wallet;

    public function __construct(Config $config, WalletHandlerInterface $wallet)
    {
        $this->apiKey = $config->apiKey;
        $this->hmacSecret = $config->hmacSecret;
        $this->wallet = $wallet;
    }

    public static function fromCredentials(string $apiKey, string $hmacSecret, WalletHandlerInterface $wallet): self
    {
        $cfg = new Config($apiKey, $hmacSecret, Config::ENV_SANDBOX);
        return new self($cfg, $wallet);
    }

    private static function extractTraceHint(string $rawBody): string
    {
        $head = substr($rawBody, 0, 1024);
        if (preg_match('/"traceId"\s*:\s*"([A-Za-z0-9_.:-]{1,128})"/', $head, $m)) {
            return $m[1];
        }
        return '';
    }

    private static function truncateUtf8(string $s, int $maxChars): string
    {
        if (function_exists('mb_substr')) {
            return mb_substr($s, 0, $maxChars, 'UTF-8');
        }
        $out = preg_replace('/^(.{0,' . $maxChars . '}).*/us', '$1', $s);
        return is_string($out) ? $out : substr($s, 0, $maxChars);
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
            $this->apiKey,
            $this->hmacSecret
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
            ? self::truncateUtf8(trim($decoded['traceId']), 128)
            : '';

        $clean = rtrim(explode('?', $routePath, 2)[0], '/');
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
            if (str_ends_with($clean, '/wallet/adjustment')) {
                if ($this->wallet instanceof WalletAdjustmentHandlerInterface) {
                    return ['statusCode' => 200, 'body' => $this->wallet->onAdjustment($decoded)];
                }
                if (!method_exists($this->wallet, 'onAdjustment')) {
                    return ['statusCode' => 200, 'body' => ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'onAdjustment not implemented']];
                }
                /** @var array<string, mixed> $adjRes */
                $adjRes = $this->wallet->onAdjustment($decoded);
                return ['statusCode' => 200, 'body' => $adjRes];
            }
            return [
                'statusCode' => 200,
                'body' => ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => "Unknown route {$clean}"],
            ];
        } catch (BaccaratSdkException $e) {
            if (!($e instanceof BaccaratApiException)) {
                if (StatusCode::isValidErrorCode($e->errorCode)) {
                    return [
                        'statusCode' => 200,
                        'body' => ['traceId' => $traceId, 'status' => $e->errorCode, 'message' => $e->getMessage()],
                    ];
                }
                if (in_array($e->errorCode, self::INCOMING_DECIMAL_ERROR_CODES, true)) {
                    return [
                        'statusCode' => 200,
                        'body' => ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => $e->getMessage()],
                    ];
                }
            }
            return [
                'statusCode' => 200,
                'body' => ['traceId' => $traceId, 'status' => StatusCode::SC_OPERATOR_TIMEOUT, 'message' => 'Temporary wallet handler error'],
            ];
        } catch (\Throwable $e) {
            return [
                'statusCode' => 200,
                'body' => ['traceId' => $traceId, 'status' => StatusCode::SC_OPERATOR_TIMEOUT, 'message' => 'Temporary wallet handler error'],
            ];
        }
    }
}

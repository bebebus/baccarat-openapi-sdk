<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

use Closure;

final class Client
{
    public const MAX_DETAIL_WINDOW_MS = 604800000;
    public const MAX_PAGE_SIZE = 20000;
    private const MAX_HTTP_RESPONSE_BYTES = 16777216; // 16 MiB

    private Config $config;
    /** @var Closure(string, array<string, string>, string, int): array{0: int, 1: string} */
    private Closure $transport;

    /** @param (callable(string, array<string, string>, string, int): array{0: int, 1: string})|null $transport */
    public function __construct(Config $config, ?callable $transport = null)
    {
        $this->config = $config;
        $this->transport = $transport !== null ? Closure::fromCallable($transport) : self::curlTransport(...);
    }

    /** @param array<string, string> $headers @return array{0: int, 1: string} */
    private static function curlTransport(string $url, array $headers, string $rawBody, int $timeoutMs): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new BaccaratSdkException('Failed to initialize cURL', StatusCode::SC_OPERATOR_TIMEOUT);
        }
        $headerLines = [];
        foreach ($headers as $k => $v) {
            $headerLines[] = "{$k}: {$v}";
        }
        $respBuf = '';
        $overflow = false;
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $rawBody,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => min($timeoutMs, 5000),
            CURLOPT_WRITEFUNCTION => static function ($curl, string $chunk) use (&$respBuf, &$overflow): int {
                $len = strlen($chunk);
                if (strlen($respBuf) + $len > self::MAX_HTTP_RESPONSE_BYTES) {
                    $overflow = true;
                    return 0;
                }
                $respBuf .= $chunk;
                return $len;
            },
        ]);
        $ok = curl_exec($ch);
        $errNo = curl_errno($ch);
        $errMsg = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($overflow) {
            throw new BaccaratSdkException('Gateway response exceeded 16 MiB limit', StatusCode::SC_INVALID_REQUEST);
        }
        if ($ok === false || $errNo !== 0) {
            throw new BaccaratSdkException("cURL error ({$errNo}): {$errMsg}", StatusCode::SC_OPERATOR_TIMEOUT);
        }
        return [$httpCode, $respBuf];
    }

    private static function uuidV4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }

    private static function fallbackStatusForHttp(int $httpStatus): string
    {
        if ($httpStatus === 429) {
            return StatusCode::SC_RATE_LIMITED;
        }
        if ($httpStatus >= 500 || $httpStatus === 408) {
            return StatusCode::SC_OPERATOR_TIMEOUT;
        }
        return StatusCode::SC_INVALID_REQUEST;
    }

    /**
     * @param array<string, mixed> $payload
     * @return array<string, mixed>
     */
    private function postSigned(string $routePath, array $payload): array
    {
        $traceId = isset($payload['traceId']) ? trim((string) $payload['traceId']) : '';
        if ($traceId === '') {
            $traceId = self::uuidV4();
        }
        $payload = array_merge(['traceId' => $traceId], $payload);
        $payload['traceId'] = $traceId;

        $rawJson = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $sig = Signing::signBody($rawJson, $this->config->hmacSecret);
        $headers = [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
            'X-API-Key' => $this->config->apiKey,
            'X-Signature' => $sig,
        ];
        if ($this->config->sendTimestamp) {
            $headers['X-Timestamp'] = (string) (int) floor(microtime(true) * 1000);
        }

        [$httpStatus, $rawResp] = ($this->transport)(
            $this->config->baseUrl . $routePath,
            $headers,
            $rawJson,
            $this->config->timeoutMs
        );

        $probeObj = json_decode($rawResp, false, 64);
        if (!($probeObj instanceof \stdClass)) {
            $st = self::fallbackStatusForHttp($httpStatus);
            throw new BaccaratApiException($st, "Non-JSON-object HTTP {$httpStatus}", $traceId, null, $httpStatus);
        }
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($rawResp, true, 64);

        $rawStatus = is_string($decoded['status'] ?? null) ? trim($decoded['status']) : '';
        $respStatus = $rawStatus !== '' ? $rawStatus : self::fallbackStatusForHttp($httpStatus);
        if ($httpStatus !== 200 || $respStatus !== StatusCode::SC_OK) {
            /** @var array<string, string>|null $val */
            $val = isset($decoded['validation']) && is_array($decoded['validation']) ? $decoded['validation'] : null;
            throw new BaccaratApiException(
                $respStatus,
                (string) ($decoded['message'] ?? "HTTP {$httpStatus}"),
                (string) ($decoded['traceId'] ?? $traceId),
                $val,
                $httpStatus
            );
        }

        return [
            'traceId' => (string) ($decoded['traceId'] ?? $traceId),
            'status' => StatusCode::SC_OK,
            'data' => $decoded['data'] ?? null,
        ];
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function ping(array $params = []): array
    {
        return $this->postSigned('/operator/v1/ping', $params);
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function createGameUrl(array $params): array
    {
        return $this->postSigned('/operator/v1/game/url', $params);
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function listTables(array $params = []): array
    {
        return $this->postSigned('/operator/v1/game/tables', $params);
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function terminateSessions(array $params = []): array
    {
        return $this->postSigned('/operator/v1/game/terminate', $params);
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function updatePlayerStatus(array $params): array
    {
        return $this->postSigned('/operator/v1/player/status', $params);
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function updatePlayerLimits(array $params): array
    {
        return $this->postSigned('/operator/v1/player/limits', $params);
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function listTransactions(array $params): array
    {
        if (!isset($params['fromTime'], $params['toTime']) || !is_int($params['fromTime']) || !is_int($params['toTime'])) {
            throw new BaccaratSdkException('fromTime and toTime must be integers', 'INVALID_ARGUMENT');
        }
        if ($params['fromTime'] < 0 || $params['toTime'] < $params['fromTime']) {
            throw new BaccaratSdkException('Invalid [fromTime, toTime] window', 'INVALID_ARGUMENT');
        }
        return $this->postSigned('/operator/v1/transaction/list', $params);
    }

    /**
     * @param array<string, mixed> $filters
     * @return list<array<string, mixed>>
     */
    public function listAllTransactions(
        int $fromTime,
        int $toTime,
        int $pageSize = 2000,
        array $filters = [],
        int $rateLimitMaxRetries = 3,
        int $rateLimitBackoffMs = 1000
    ): array {
        if ($pageSize < 1 || $pageSize > self::MAX_PAGE_SIZE) {
            throw new BaccaratSdkException('pageSize must be in 1..' . self::MAX_PAGE_SIZE, 'INVALID_ARGUMENT');
        }
        $maxRetries = max(0, $rateLimitMaxRetries);
        $backoffMs = max(0, $rateLimitBackoffMs);
        unset($filters['traceId']);
        $all = [];
        $pageNo = 1;
        while (true) {
            $attempt = 0;
            while (true) {
                try {
                    $res = $this->listTransactions(array_merge($filters, [
                        'fromTime' => $fromTime,
                        'toTime' => $toTime,
                        'pageNo' => $pageNo,
                        'pageSize' => $pageSize,
                    ]));
                    break;
                } catch (BaccaratApiException $e) {
                    if ($e->status === StatusCode::SC_RATE_LIMITED && $attempt < $maxRetries) {
                        $attempt++;
                        $waitMs = $backoffMs * $attempt;
                        if ($waitMs > 0) {
                            usleep($waitMs * 1000);
                        }
                        continue;
                    }
                    throw $e;
                }
            }
            $data = is_array($res['data'] ?? null) ? $res['data'] : [];
            $batch = is_array($data['transactions'] ?? null) ? $data['transactions'] : [];
            foreach ($batch as $row) {
                $all[] = $row;
            }
            $total = (int) ($data['total'] ?? count($all));
            if (count($all) >= $total || count($batch) === 0) {
                break;
            }
            $pageNo++;
        }
        return $all;
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function getTransactionDetail(array $params): array
    {
        $betId = trim((string) ($params['betId'] ?? ''));
        if ($betId === '') {
            throw new BaccaratSdkException('betId is required', 'INVALID_ARGUMENT');
        }
        if (array_key_exists('fromTime', $params) || array_key_exists('toTime', $params)) {
            $from = $params['fromTime'] ?? null;
            $to = $params['toTime'] ?? null;
            if (!is_int($from) || !is_int($to)) {
                throw new BaccaratSdkException('fromTime and toTime must both be non-negative integers when specified (null is rejected)', 'INVALID_ARGUMENT');
            }
            $span = $to - $from;
            if ($from < 0 || $span < 0 || $span > self::MAX_DETAIL_WINDOW_MS) {
                throw new BaccaratSdkException('Detail window must satisfy 0 <= toTime - fromTime <= 604800000', 'INVALID_ARGUMENT');
            }
        }
        return $this->postSigned('/operator/v1/transaction/detail', $params);
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function listUnsettledTransactions(array $params = []): array
    {
        if (array_key_exists('fromTime', $params) || array_key_exists('toTime', $params)) {
            $from = $params['fromTime'] ?? null;
            $to = $params['toTime'] ?? null;
            if (!is_int($from) || !is_int($to)) {
                throw new BaccaratSdkException('fromTime and toTime must both be non-negative integers when specified (null is rejected)', 'INVALID_ARGUMENT');
            }
            $span = $to - $from;
            if ($from < 0 || $span < 0 || $span > self::MAX_DETAIL_WINDOW_MS) {
                throw new BaccaratSdkException('Unsettled window must satisfy 0 <= toTime - fromTime <= 604800000', 'INVALID_ARGUMENT');
            }
        }
        return $this->postSigned('/operator/v1/transaction/unsettled', $params);
    }

    /** @param array<string, mixed> $params @return array<string, mixed> */
    public function getWalletTransactionStatus(array $params): array
    {
        $txId = trim((string) ($params['transactionId'] ?? ''));
        $betId = trim((string) ($params['betId'] ?? ''));
        $username = trim((string) ($params['username'] ?? ''));
        if ($txId === '' && $betId === '' && $username === '') {
            throw new BaccaratSdkException('At least one of transactionId, betId, or username is required', 'INVALID_ARGUMENT');
        }
        $userOnly = ($username !== '' && $txId === '' && $betId === '');
        $hasWindow = array_key_exists('fromTime', $params) || array_key_exists('toTime', $params);
        if ($userOnly || $hasWindow) {
            $from = $params['fromTime'] ?? null;
            $to = $params['toTime'] ?? null;
            if (!is_int($from) || !is_int($to)) {
                throw new BaccaratSdkException('fromTime and toTime must both be non-negative integers (null is rejected)', 'INVALID_ARGUMENT');
            }
            $span = $to - $from;
            if ($from < 0 || $span < 0 || ($userOnly && $span > 86400000)) {
                throw new BaccaratSdkException(
                    $userOnly
                        ? 'Username query window must satisfy 0 <= toTime - fromTime <= 86400000 (24 hours)'
                        : 'Invalid [fromTime, toTime] window',
                    'INVALID_ARGUMENT',
                );
            }
        }
        return $this->postSigned('/operator/v1/wallet/transaction-status', $params);
    }
}

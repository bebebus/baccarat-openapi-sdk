<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

use Closure;

final class Client
{
    public const MAX_DETAIL_WINDOW_MS = 604800000;
    public const MAX_PAGE_SIZE = 20000;

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
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $rawBody,
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_TIMEOUT_MS => $timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => min($timeoutMs, 5000),
        ]);
        $resp = curl_exec($ch);
        $errNo = curl_errno($ch);
        $errMsg = curl_error($ch);
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if ($resp === false || $errNo !== 0) {
            throw new BaccaratSdkException("cURL error ({$errNo}): {$errMsg}", StatusCode::SC_OPERATOR_TIMEOUT);
        }
        return [$httpCode, (string) $resp];
    }

    private static function uuidV4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
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

        [$httpStatus, $rawResp] = ($this->transport)(
            $this->config->baseUrl . $routePath,
            $headers,
            $rawJson,
            $this->config->timeoutMs
        );

        $probeObj = json_decode($rawResp, false, 64);
        if (!($probeObj instanceof \stdClass)) {
            $st = ($httpStatus >= 500 || $httpStatus === 408 || $httpStatus === 429)
                ? StatusCode::SC_OPERATOR_TIMEOUT
                : StatusCode::SC_INVALID_REQUEST;
            throw new BaccaratApiException($st, "Non-JSON-object HTTP {$httpStatus}", $traceId, null, $httpStatus);
        }
        /** @var array<string, mixed> $decoded */
        $decoded = json_decode($rawResp, true, 64);

        $respStatus = (string) ($decoded['status'] ?? StatusCode::SC_INVALID_REQUEST);
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
    public function terminateSessions(array $params): array
    {
        return $this->postSigned('/operator/v1/game/terminate', $params);
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

    /** @return list<array<string, mixed>> */
    public function listAllTransactions(int $fromTime, int $toTime, int $pageSize = 2000): array
    {
        if ($pageSize < 1 || $pageSize > self::MAX_PAGE_SIZE) {
            throw new BaccaratSdkException('pageSize must be in 1..' . self::MAX_PAGE_SIZE, 'INVALID_ARGUMENT');
        }
        $all = [];
        $pageNo = 1;
        while (true) {
            $res = $this->listTransactions([
                'fromTime' => $fromTime,
                'toTime' => $toTime,
                'pageNo' => $pageNo,
                'pageSize' => $pageSize,
            ]);
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
        $from = $params['fromTime'] ?? null;
        $to = $params['toTime'] ?? null;
        if ($betId === '' || !is_int($from) || !is_int($to)) {
            throw new BaccaratSdkException('betId, fromTime, and toTime are required', 'INVALID_ARGUMENT');
        }
        $span = $to - $from;
        if ($from < 0 || $span < 0 || $span > self::MAX_DETAIL_WINDOW_MS) {
            throw new BaccaratSdkException('Detail window must satisfy 0 <= toTime - fromTime <= 604800000', 'INVALID_ARGUMENT');
        }
        return $this->postSigned('/operator/v1/transaction/detail', $params);
    }
}

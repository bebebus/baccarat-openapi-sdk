<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class WalletResponse
{
    /** @return array<string, mixed> */
    public static function ok(
        string $traceId,
        string $username,
        string $currency,
        string $balance,
        ?int $timestamp = null
    ): array {
        if (preg_match('/\A[0-9]+(?:\.[0-9]+)?\z/', $balance) !== 1) {
            throw new BaccaratSdkException(
                'WalletResponse::ok balance must be a non-empty non-negative decimal string matching ^\\d+(?:\\.\\d+)?$',
                'INVALID_ARGUMENT'
            );
        }
        return [
            'traceId' => $traceId,
            'status' => StatusCode::SC_OK,
            'data' => [
                'username' => $username,
                'currency' => $currency,
                'balance' => $balance,
                'timestamp' => $timestamp ?? (int) floor(microtime(true) * 1000),
            ],
        ];
    }

    /** @return array<string, mixed> */
    public static function error(string $traceId, string $status, string $message = ''): array
    {
        $st = trim($status);
        if ($st === '' || strcasecmp($st, StatusCode::SC_OK) === 0) {
            throw new BaccaratSdkException(
                'WalletResponse::error status must be a non-empty error status code (cannot be SC_OK)',
                'INVALID_ARGUMENT'
            );
        }
        $res = [
            'traceId' => $traceId,
            'status' => $st,
        ];
        if ($message !== '') {
            $res['message'] = $message;
        }
        return $res;
    }
}

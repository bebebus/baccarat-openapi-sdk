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
        $res = [
            'traceId' => $traceId,
            'status' => $status,
        ];
        if ($message !== '') {
            $res['message'] = $message;
        }
        return $res;
    }
}

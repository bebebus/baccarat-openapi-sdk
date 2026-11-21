<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class Idempotency
{
    /** @param list<string|int> $fields */
    public static function encodeTupleFingerprint(string $domain, array $fields): string
    {
        $parts = ["v1|{$domain}"];
        foreach ($fields as $val) {
            $str = (string) $val;
            $parts[] = strlen($str) . ':' . $str;
        }
        return hash('sha256', implode('|', $parts));
    }

    /** @param array<string, mixed> $p */
    public static function betFingerprint(array $p): string
    {
        return self::encodeTupleFingerprint('wallet/bet', [
            (string) ($p['transactionId'] ?? ''),
            (string) ($p['username'] ?? ''),
            (string) ($p['betId'] ?? ''),
            (string) ($p['externalTransactionId'] ?? ''),
            (string) ($p['roundId'] ?? ''),
            (string) ($p['currency'] ?? ''),
            (string) ($p['gameCode'] ?? ''),
            (string) ($p['amount'] ?? ''),
        ]);
    }

    /** @param array<string, mixed> $p */
    public static function betResultFingerprint(array $p): string
    {
        return self::encodeTupleFingerprint('wallet/bet_result', [
            (string) ($p['transactionId'] ?? ''),
            (string) ($p['username'] ?? ''),
            (string) ($p['betId'] ?? ''),
            (string) ($p['externalTransactionId'] ?? ''),
            (string) ($p['roundId'] ?? ''),
            (string) ($p['currency'] ?? ''),
            (string) ($p['gameCode'] ?? ''),
            (string) ($p['betAmount'] ?? ''),
            (string) ($p['winAmount'] ?? ''),
            (string) ($p['effectiveTurnover'] ?? ''),
            (string) ($p['winLoss'] ?? ''),
            (string) ($p['jackpotAmount'] ?? ''),
            (string) ($p['resultType'] ?? ''),
            (string) ($p['isFreespin'] ?? 0),
            (string) ($p['isEndRound'] ?? 1),
            (string) ($p['betTime'] ?? 0),
        ]);
    }

    /** @param array<string, mixed> $p */
    public static function rollbackFingerprint(array $p): string
    {
        return self::encodeTupleFingerprint('wallet/rollback', [
            (string) ($p['transactionId'] ?? ''),
            (string) ($p['username'] ?? ''),
            (string) ($p['betId'] ?? ''),
            (string) ($p['externalTransactionId'] ?? ''),
            (string) ($p['roundId'] ?? ''),
            (string) ($p['currency'] ?? ''),
            (string) ($p['gameCode'] ?? ''),
            (string) ($p['amount'] ?? ''),
        ]);
    }
}

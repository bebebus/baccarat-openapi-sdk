<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class Idempotency
{
    private static function scalarStr(mixed $v): string
    {
        return is_string($v)
            ? $v
            : (is_int($v) ? (string) $v : (is_bool($v) ? ($v ? 'true' : 'false') : ''));
    }

    /** @param list<mixed> $fields */
    public static function encodeTupleFingerprint(string $domain, array $fields): string
    {
        $parts = ["v1|{$domain}"];
        foreach ($fields as $val) {
            $str = self::scalarStr($val);
            $parts[] = strlen($str) . ':' . $str;
        }
        return hash('sha256', implode('|', $parts));
    }

    /** @param array<string, mixed> $p */
    public static function betFingerprint(array $p): string
    {
        return self::encodeTupleFingerprint('wallet/bet', [
            self::scalarStr($p['transactionId'] ?? null),
            self::scalarStr($p['username'] ?? null),
            self::scalarStr($p['betId'] ?? null),
            self::scalarStr($p['externalTransactionId'] ?? null),
            self::scalarStr($p['roundId'] ?? null),
            self::scalarStr($p['currency'] ?? null),
            self::scalarStr($p['gameCode'] ?? null),
            self::scalarStr($p['amount'] ?? null),
        ]);
    }

    /** @param array<string, mixed> $p */
    public static function betResultFingerprint(array $p): string
    {
        return self::encodeTupleFingerprint('wallet/bet_result', [
            self::scalarStr($p['transactionId'] ?? null),
            self::scalarStr($p['username'] ?? null),
            self::scalarStr($p['betId'] ?? null),
            self::scalarStr($p['externalTransactionId'] ?? null),
            self::scalarStr($p['roundId'] ?? null),
            self::scalarStr($p['currency'] ?? null),
            self::scalarStr($p['gameCode'] ?? null),
            self::scalarStr($p['betAmount'] ?? null),
            self::scalarStr($p['winAmount'] ?? null),
            self::scalarStr($p['effectiveTurnover'] ?? null),
            self::scalarStr($p['winLoss'] ?? null),
            self::scalarStr($p['jackpotAmount'] ?? null),
            self::scalarStr($p['resultType'] ?? null),
            self::scalarStr($p['isFreespin'] ?? null),
            self::scalarStr($p['isEndRound'] ?? null),
            self::scalarStr($p['betTime'] ?? null),
        ]);
    }

    /** @param array<string, mixed> $p */
    public static function rollbackFingerprint(array $p): string
    {
        return self::encodeTupleFingerprint('wallet/rollback', [
            self::scalarStr($p['transactionId'] ?? null),
            self::scalarStr($p['username'] ?? null),
            self::scalarStr($p['betId'] ?? null),
            self::scalarStr($p['externalTransactionId'] ?? null),
            self::scalarStr($p['roundId'] ?? null),
            self::scalarStr($p['currency'] ?? null),
            self::scalarStr($p['gameCode'] ?? null),
            self::scalarStr($p['amount'] ?? null),
        ]);
    }

    /** @param array<string, mixed> $p */
    public static function adjustmentFingerprint(array $p): string
    {
        return self::encodeTupleFingerprint('wallet/adjustment', [
            self::scalarStr($p['transactionId'] ?? null),
            self::scalarStr($p['username'] ?? null),
            self::scalarStr($p['betId'] ?? null),
            self::scalarStr($p['externalTransactionId'] ?? null),
            self::scalarStr($p['roundId'] ?? null),
            self::scalarStr($p['currency'] ?? null),
            self::scalarStr($p['gameCode'] ?? null),
            self::scalarStr($p['direction'] ?? null),
            self::scalarStr($p['amount'] ?? null),
            self::scalarStr($p['reasonCode'] ?? null),
        ]);
    }
}

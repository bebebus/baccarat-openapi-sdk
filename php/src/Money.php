<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

/**
 * Arbitrary-precision base-10 Decimal <-> Ledger Units (1/1000 minor unit) without ext-bcmath or floats.
 */
final class Money
{
    public static function decimalToLedgerUnits(string $raw, int $displayExponent, bool $allowNegative = false): string
    {
        if ($displayExponent < 0 || $displayExponent > 18) {
            throw new BaccaratSdkException("displayExponent out of range: {$displayExponent}", 'INVALID_DISPLAY_EXPONENT');
        }
        $text = trim($raw);
        if (!preg_match('/^(-?)(\d+)(?:\.(\d+))?$/', $text, $m)) {
            throw new BaccaratSdkException("malformed decimal amount: {$raw}", 'INVALID_DECIMAL_AMOUNT');
        }
        $negative = $m[1] === '-';
        $wholePart = ltrim($m[2], '0');
        $rawFrac = $m[3] ?? '';
        $scaleDigits = $displayExponent + 3;
        $trimmedFrac = rtrim($rawFrac, '0');
        if (strlen($trimmedFrac) > $scaleDigits) {
            throw new BaccaratSdkException('decimal amount exceeds max precision', 'DECIMAL_PRECISION_EXCEEDED');
        }
        $fracPadded = str_pad($trimmedFrac, $scaleDigits, '0', STR_PAD_RIGHT);
        $combined = ltrim($wholePart . $fracPadded, '0');
        if ($combined === '') {
            return '0';
        }
        if ($negative) {
            if (!$allowNegative) {
                throw new BaccaratSdkException("negative decimal amount forbidden: {$text}", 'NEGATIVE_DECIMAL_FORBIDDEN');
            }
            return '-' . $combined;
        }
        return $combined;
    }

    public static function ledgerUnitsToDecimal(string|int $units, int $displayExponent): string
    {
        if ($displayExponent < 0 || $displayExponent > 18) {
            throw new BaccaratSdkException("displayExponent out of range: {$displayExponent}", 'INVALID_DISPLAY_EXPONENT');
        }
        $u = trim((string) $units);
        if (!preg_match('/^(-?)(\d+)$/', $u, $m)) {
            throw new BaccaratSdkException("invalid integer ledger units: {$u}", 'INVALID_DECIMAL_AMOUNT');
        }
        $absDigits = ltrim($m[2], '0');
        $negative = ($m[1] === '-') && ($absDigits !== '');
        if ($absDigits === '') {
            $absDigits = '0';
        }
        $scaleDigits = $displayExponent + 3;
        $padded = str_pad($absDigits, $scaleDigits + 1, '0', STR_PAD_LEFT);
        $whole = ltrim(substr($padded, 0, -$scaleDigits), '0');
        if ($whole === '') {
            $whole = '0';
        }
        $fracAll = substr($padded, -$scaleDigits);
        $sign = $negative ? '-' : '';
        if ($displayExponent === 0) {
            $sub = rtrim($fracAll, '0');
            return $sub === '' ? "{$sign}{$whole}" : "{$sign}{$whole}.{$sub}";
        }
        $shown = substr($fracAll, 0, $displayExponent);
        $sub = rtrim(substr($fracAll, $displayExponent), '0');
        return "{$sign}{$whole}.{$shown}{$sub}";
    }

    /** Pure base-10 non-negative integer string comparison: -1, 0, 1 */
    public static function compareUnsignedUnits(string $a, string $b): int
    {
        $na = ltrim($a, '0') ?: '0';
        $nb = ltrim($b, '0') ?: '0';
        if (strlen($na) !== strlen($nb)) {
            return strlen($na) <=> strlen($nb);
        }
        return $na <=> $nb;
    }

    public static function addUnsignedUnits(string $a, string $b): string
    {
        $i = strlen($a) - 1;
        $j = strlen($b) - 1;
        $carry = 0;
        $out = '';
        while ($i >= 0 || $j >= 0 || $carry > 0) {
            $da = $i >= 0 ? (ord($a[$i--]) - 48) : 0;
            $db = $j >= 0 ? (ord($b[$j--]) - 48) : 0;
            $sum = $da + $db + $carry;
            $out = chr(($sum % 10) + 48) . $out;
            $carry = intdiv($sum, 10);
        }
        return ltrim($out, '0') ?: '0';
    }

    public static function subUnsignedUnits(string $a, string $b): string
    {
        if (self::compareUnsignedUnits($a, $b) < 0) {
            throw new BaccaratSdkException('underflow in subUnsignedUnits', StatusCode::SC_INSUFFICIENT_FUNDS);
        }
        $i = strlen($a) - 1;
        $j = strlen($b) - 1;
        $borrow = 0;
        $out = '';
        while ($i >= 0) {
            $da = (ord($a[$i--]) - 48) - $borrow;
            $db = $j >= 0 ? (ord($b[$j--]) - 48) : 0;
            if ($da < $db) {
                $da += 10;
                $borrow = 1;
            } else {
                $borrow = 0;
            }
            $out = chr(($da - $db) + 48) . $out;
        }
        return ltrim($out, '0') ?: '0';
    }
}

<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class StatusCode
{
    public const SC_OK = 'SC_OK';
    public const SC_INVALID_REQUEST = 'SC_INVALID_REQUEST';
    public const SC_AUTHENTICATION_FAILED = 'SC_AUTHENTICATION_FAILED';
    public const SC_INVALID_SIGNATURE = 'SC_INVALID_SIGNATURE';
    public const SC_INVALID_TOKEN = 'SC_INVALID_TOKEN';
    public const SC_INVALID_GAME = 'SC_INVALID_GAME';
    public const SC_USER_NOT_EXISTS = 'SC_USER_NOT_EXISTS';
    public const SC_USER_DISABLED = 'SC_USER_DISABLED';
    public const SC_WRONG_CURRENCY = 'SC_WRONG_CURRENCY';
    public const SC_CURRENCY_NOT_SUPPORTED = 'SC_CURRENCY_NOT_SUPPORTED';
    public const SC_INSUFFICIENT_FUNDS = 'SC_INSUFFICIENT_FUNDS';
    public const SC_TRANSACTION_DUPLICATED = 'SC_TRANSACTION_DUPLICATED';
    public const SC_TRANSACTION_NOT_EXISTS = 'SC_TRANSACTION_NOT_EXISTS';
    public const SC_TRANSACTION_STILL_PROCESSING = 'SC_TRANSACTION_STILL_PROCESSING';
    public const SC_OPERATOR_TIMEOUT = 'SC_OPERATOR_TIMEOUT';
    public const SC_UNDER_MAINTENANCE = 'SC_UNDER_MAINTENANCE';
    public const SC_GAME_DISABLED = 'SC_GAME_DISABLED';
    public const SC_RATE_LIMITED = 'SC_RATE_LIMITED';

    public static function isRetryable(string $status): bool
    {
        $trimmed = trim($status);
        return $trimmed === self::SC_TRANSACTION_STILL_PROCESSING
            || $trimmed === self::SC_OPERATOR_TIMEOUT
            || $trimmed === self::SC_RATE_LIMITED;
    }
}

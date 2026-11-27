<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class InMemoryWallet implements WalletHandlerInterface, WalletAdjustmentHandlerInterface
{
    /** @var array<string, array{currency: string, exponent: int, balanceUnits: string, tokens: array<string, bool>, disabled: bool}> */
    private array $accounts = [];
    /** @var array<string, array{type: string, fp: string, empty: bool}> */
    private array $transactions = [];
    /** @var array<string, array{txId: string, username: string, currency: string, stake: string, state: string}> */
    private array $deductedBets = [];

    /** @param array<string, array{currency: string, balance?: string, exponent?: int, tokens?: list<string>, disabled?: bool}> $initial */
    public function __construct(array $initial = [])
    {
        foreach ($initial as $username => $info) {
            $exp = (int) ($info['exponent'] ?? 2);
            $tokens = [];
            foreach (($info['tokens'] ?? []) as $t) {
                $tokens[(string) $t] = true;
            }
            $this->accounts[$username] = [
                'currency' => strtoupper(trim((string) $info['currency'])),
                'exponent' => $exp,
                'balanceUnits' => Money::decimalToLedgerUnits((string) ($info['balance'] ?? '0.00'), $exp),
                'tokens' => $tokens,
                'disabled' => (bool) ($info['disabled'] ?? false),
            ];
        }
    }

    public function setDisabled(string $username, bool $disabled): void
    {
        if (isset($this->accounts[$username])) {
            $this->accounts[$username]['disabled'] = $disabled;
        }
    }

    /** @return array<string, mixed> */
    private function okEnvelope(string $traceId, string $username): array
    {
        $acct = $this->accounts[$username];
        return WalletResponse::ok(
            $traceId,
            $username,
            $acct['currency'],
            Money::ledgerUnitsToDecimal($acct['balanceUnits'], $acct['exponent'])
        );
    }

    private function checkAccount(string $username, string $currency): ?string
    {
        if (!isset($this->accounts[$username])) {
            return StatusCode::SC_USER_NOT_EXISTS;
        }
        if ($this->accounts[$username]['currency'] !== strtoupper(trim($currency))) {
            return StatusCode::SC_WRONG_CURRENCY;
        }
        return null;
    }

    /** @param array<string, mixed> $req */
    private static function reqStr(array $req, string $key): ?string
    {
        return is_string($req[$key] ?? null) ? trim($req[$key]) : null;
    }

    /** @param array<string, mixed> $req */
    private static function optStr(array $req, string $key): string
    {
        return is_string($req[$key] ?? null) ? trim($req[$key]) : '';
    }

    /** @param array<string, mixed> $req */
    private static function reqAmount(array $req, string $key): ?string
    {
        $v = $req[$key] ?? null;
        if (is_string($v)) {
            return $v;
        }
        if (is_int($v)) {
            return (string) $v;
        }
        return null;
    }

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onBalance(array $req): array
    {
        $traceId = self::optStr($req, 'traceId');
        $username = self::reqStr($req, 'username');
        $currency = self::reqStr($req, 'currency');
        if ($username === null || $username === '' || $currency === null || $currency === '') {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'username and currency are required'];
        }
        $err = $this->checkAccount($username, $currency);
        if ($err !== null) {
            return ['traceId' => $traceId, 'status' => $err, 'message' => 'Account check failed'];
        }
        $acct = $this->accounts[$username];
        if ($acct['disabled']) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_USER_DISABLED, 'message' => 'User disabled'];
        }
        $tok = $req['token'] ?? null;
        if ($acct['tokens'] !== [] && (!is_string($tok) || !isset($acct['tokens'][$tok]))) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_TOKEN, 'message' => 'Invalid token'];
        }
        return $this->okEnvelope($traceId, $username);
    }

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onBet(array $req): array
    {
        $traceId = self::optStr($req, 'traceId');
        $txId = self::reqStr($req, 'transactionId');
        $betId = self::reqStr($req, 'betId');
        $username = self::reqStr($req, 'username');
        $currency = self::reqStr($req, 'currency');
        $amount = self::reqAmount($req, 'amount');
        if ($txId === null || $txId === '' || $betId === null || $betId === '' || $username === null || $username === '' || $currency === null || $currency === '' || $amount === null || trim($amount) === '') {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Missing required bet fields'];
        }
        $err = $this->checkAccount($username, $currency);
        if ($err !== null) {
            return ['traceId' => $traceId, 'status' => $err, 'message' => 'Account check failed'];
        }
        $fp = Idempotency::betFingerprint($req);
        if (isset($this->transactions[$txId])) {
            if ($this->transactions[$txId]['type'] !== 'BET' || $this->transactions[$txId]['fp'] !== $fp) {
                return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_DUPLICATED, 'message' => 'Conflict'];
            }
            return $this->okEnvelope($traceId, $username);
        }
        if (isset($this->deductedBets[$betId])) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_DUPLICATED, 'message' => 'Duplicate betId'];
        }
        $acct = $this->accounts[$username];
        if ($acct['disabled']) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_USER_DISABLED, 'message' => 'User disabled'];
        }
        $tok = $req['token'] ?? null;
        if ($acct['tokens'] !== [] && (!is_string($tok) || !isset($acct['tokens'][$tok]))) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_TOKEN, 'message' => 'Invalid token'];
        }
        $stake = Money::decimalToLedgerUnits($amount, $acct['exponent']);
        if (Money::compareUnsignedUnits($stake, '0') <= 0) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Bet amount must be positive'];
        }
        if (Money::compareUnsignedUnits($acct['balanceUnits'], $stake) < 0) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INSUFFICIENT_FUNDS, 'message' => 'Insufficient funds'];
        }
        $this->accounts[$username]['balanceUnits'] = Money::subUnsignedUnits($acct['balanceUnits'], $stake);
        $this->transactions[$txId] = ['type' => 'BET', 'fp' => $fp, 'empty' => false];
        $this->deductedBets[$betId] = [
            'txId' => $txId,
            'username' => $username,
            'currency' => $acct['currency'],
            'stake' => $stake,
            'state' => 'DEDUCTED',
        ];
        return $this->okEnvelope($traceId, $username);
    }

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onBetResult(array $req): array
    {
        $traceId = self::optStr($req, 'traceId');
        $txId = self::reqStr($req, 'transactionId');
        $betId = self::reqStr($req, 'betId');
        $username = self::reqStr($req, 'username');
        $currency = self::reqStr($req, 'currency');
        $betAmount = self::reqAmount($req, 'betAmount');
        $winAmount = self::reqAmount($req, 'winAmount');
        if ($txId === null || $txId === '' || $betId === null || $betId === '' || $username === null || $username === '' || $currency === null || $currency === '' || $betAmount === null || trim($betAmount) === '' || $winAmount === null || trim($winAmount) === '') {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Missing required bet_result fields'];
        }
        $err = $this->checkAccount($username, $currency);
        if ($err !== null) {
            return ['traceId' => $traceId, 'status' => $err, 'message' => 'Account check failed'];
        }
        $fp = Idempotency::betResultFingerprint($req);
        if (isset($this->transactions[$txId])) {
            if ($this->transactions[$txId]['type'] !== 'SETTLE' || $this->transactions[$txId]['fp'] !== $fp) {
                return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_DUPLICATED, 'message' => 'Conflict'];
            }
            return $this->okEnvelope($traceId, $username);
        }
        if (!isset($this->deductedBets[$betId])) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_NOT_EXISTS, 'message' => 'Original betId missing'];
        }
        $acct = $this->accounts[$username];
        $orig = $this->deductedBets[$betId];
        $betUnits = Money::decimalToLedgerUnits($betAmount, $acct['exponent']);
        $winUnits = Money::decimalToLedgerUnits($winAmount, $acct['exponent']);
        if ($orig['username'] !== $username || $orig['currency'] !== $acct['currency'] || $orig['stake'] !== $betUnits) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'bet_result mismatch'];
        }
        if ($orig['state'] !== 'DEDUCTED') {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_DUPLICATED, 'message' => 'betId already finalized'];
        }
        $this->accounts[$username]['balanceUnits'] = Money::addUnsignedUnits($acct['balanceUnits'], $winUnits);
        $this->deductedBets[$betId]['state'] = 'SETTLED';
        $this->transactions[$txId] = ['type' => 'SETTLE', 'fp' => $fp, 'empty' => false];
        return $this->okEnvelope($traceId, $username);
    }

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onRollback(array $req): array
    {
        $traceId = self::optStr($req, 'traceId');
        $txId = self::reqStr($req, 'transactionId');
        $betId = self::reqStr($req, 'betId');
        $username = self::reqStr($req, 'username');
        $currency = self::reqStr($req, 'currency');
        $amount = self::reqAmount($req, 'amount');
        if ($txId === null || $txId === '' || $betId === null || $betId === '' || $username === null || $username === '' || $currency === null || $currency === '' || $amount === null || trim($amount) === '') {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Missing required rollback fields'];
        }
        $err = $this->checkAccount($username, $currency);
        if ($err !== null) {
            return ['traceId' => $traceId, 'status' => $err, 'message' => 'Account check failed'];
        }
        $fp = Idempotency::rollbackFingerprint($req);
        if (isset($this->transactions[$txId])) {
            if ($this->transactions[$txId]['type'] !== 'ROLLBACK' || $this->transactions[$txId]['fp'] !== $fp) {
                return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_DUPLICATED, 'message' => 'Conflict'];
            }
            if ($this->transactions[$txId]['empty']) {
                return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_NOT_EXISTS, 'message' => 'Never deducted'];
            }
            return $this->okEnvelope($traceId, $username);
        }
        $acct = $this->accounts[$username];
        $refund = Money::decimalToLedgerUnits($amount, $acct['exponent']);
        if (Money::compareUnsignedUnits($refund, '0') <= 0) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Rollback amount must be positive'];
        }
        if (!isset($this->deductedBets[$betId])) {
            $this->transactions[$txId] = ['type' => 'ROLLBACK', 'fp' => $fp, 'empty' => true];
            return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_NOT_EXISTS, 'message' => 'Never deducted'];
        }
        $orig = $this->deductedBets[$betId];
        if ($orig['username'] !== $username || $orig['currency'] !== $acct['currency'] || $orig['stake'] !== $refund) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Rollback mismatch'];
        }
        if ($orig['state'] !== 'DEDUCTED') {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_DUPLICATED, 'message' => 'betId already finalized'];
        }
        $this->accounts[$username]['balanceUnits'] = Money::addUnsignedUnits($acct['balanceUnits'], $refund);
        $this->deductedBets[$betId]['state'] = 'ROLLED_BACK';
        $this->transactions[$txId] = ['type' => 'ROLLBACK', 'fp' => $fp, 'empty' => false];
        return $this->okEnvelope($traceId, $username);
    }

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onAdjustment(array $req): array
    {
        $traceId = self::optStr($req, 'traceId');
        $txId = self::reqStr($req, 'transactionId');
        $betId = self::reqStr($req, 'betId');
        $username = self::reqStr($req, 'username');
        $currency = self::reqStr($req, 'currency');
        $dirRaw = self::reqStr($req, 'direction');
        $direction = $dirRaw !== null ? strtoupper($dirRaw) : '';
        $reasonCode = self::reqStr($req, 'reasonCode');
        $amount = self::reqAmount($req, 'amount');
        if ($txId === null || $txId === '' || $betId === null || $betId === '' || $username === null || $username === '' || $currency === null || $currency === '' || $reasonCode === null || $reasonCode === '' || $amount === null || trim($amount) === '' || ($direction !== 'CREDIT' && $direction !== 'DEBIT')) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Missing or invalid adjustment fields'];
        }
        $err = $this->checkAccount($username, $currency);
        if ($err !== null) {
            return ['traceId' => $traceId, 'status' => $err, 'message' => 'Account check failed'];
        }
        $fp = Idempotency::adjustmentFingerprint($req);
        if (isset($this->transactions[$txId])) {
            if ($this->transactions[$txId]['type'] !== 'ADJUSTMENT' || $this->transactions[$txId]['fp'] !== $fp) {
                return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_DUPLICATED, 'message' => 'Conflict'];
            }
            return $this->okEnvelope($traceId, $username);
        }
        if (!isset($this->deductedBets[$betId])) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_TRANSACTION_NOT_EXISTS, 'message' => 'Original betId missing'];
        }
        $acct = $this->accounts[$username];
        $orig = $this->deductedBets[$betId];
        if ($orig['username'] !== $username || $orig['currency'] !== $acct['currency']) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Adjustment mismatch'];
        }
        $adjUnits = Money::decimalToLedgerUnits($amount, $acct['exponent']);
        if (Money::compareUnsignedUnits($adjUnits, '0') <= 0) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_REQUEST, 'message' => 'Adjustment amount must be positive'];
        }
        if ($direction === 'DEBIT') {
            if (Money::compareUnsignedUnits($acct['balanceUnits'], $adjUnits) < 0) {
                return ['traceId' => $traceId, 'status' => StatusCode::SC_INSUFFICIENT_FUNDS, 'message' => 'Insufficient funds'];
            }
            $this->accounts[$username]['balanceUnits'] = Money::subUnsignedUnits($acct['balanceUnits'], $adjUnits);
        } else {
            $this->accounts[$username]['balanceUnits'] = Money::addUnsignedUnits($acct['balanceUnits'], $adjUnits);
        }
        $this->transactions[$txId] = ['type' => 'ADJUSTMENT', 'fp' => $fp, 'empty' => false];
        return $this->okEnvelope($traceId, $username);
    }
}

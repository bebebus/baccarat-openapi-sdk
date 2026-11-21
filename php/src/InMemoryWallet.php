<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

namespace Bebebus\BaccaratSdk;

final class InMemoryWallet implements WalletHandlerInterface
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
        return [
            'traceId' => $traceId,
            'status' => StatusCode::SC_OK,
            'data' => [
                'username' => $username,
                'currency' => $acct['currency'],
                'balance' => Money::ledgerUnitsToDecimal($acct['balanceUnits'], $acct['exponent']),
                'timestamp' => (int) floor(microtime(true) * 1000),
            ],
        ];
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

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onBalance(array $req): array
    {
        $traceId = is_string($req['traceId'] ?? null) ? $req['traceId'] : '';
        $username = trim((string) ($req['username'] ?? ''));
        $currency = trim((string) ($req['currency'] ?? ''));
        if ($username === '' || $currency === '') {
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
        $tok = (string) ($req['token'] ?? '');
        if ($acct['tokens'] !== [] && !isset($acct['tokens'][$tok])) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_TOKEN, 'message' => 'Invalid token'];
        }
        return $this->okEnvelope($traceId, $username);
    }

    /** @param array<string, mixed> $req @return array<string, mixed> */
    public function onBet(array $req): array
    {
        $traceId = is_string($req['traceId'] ?? null) ? $req['traceId'] : '';
        $txId = trim((string) ($req['transactionId'] ?? ''));
        $betId = trim((string) ($req['betId'] ?? ''));
        $username = trim((string) ($req['username'] ?? ''));
        $currency = trim((string) ($req['currency'] ?? ''));
        if ($txId === '' || $betId === '' || $username === '' || $currency === '' || !isset($req['amount'])) {
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
        $tok = (string) ($req['token'] ?? '');
        if ($acct['tokens'] !== [] && !isset($acct['tokens'][$tok])) {
            return ['traceId' => $traceId, 'status' => StatusCode::SC_INVALID_TOKEN, 'message' => 'Invalid token'];
        }
        $stake = Money::decimalToLedgerUnits((string) $req['amount'], $acct['exponent']);
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
        $traceId = is_string($req['traceId'] ?? null) ? $req['traceId'] : '';
        $txId = trim((string) ($req['transactionId'] ?? ''));
        $betId = trim((string) ($req['betId'] ?? ''));
        $username = trim((string) ($req['username'] ?? ''));
        $currency = trim((string) ($req['currency'] ?? ''));
        if ($txId === '' || $betId === '' || $username === '' || $currency === '' || !isset($req['winAmount'], $req['betAmount'])) {
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
        $betUnits = Money::decimalToLedgerUnits((string) $req['betAmount'], $acct['exponent']);
        $winUnits = Money::decimalToLedgerUnits((string) $req['winAmount'], $acct['exponent']);
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
        $traceId = is_string($req['traceId'] ?? null) ? $req['traceId'] : '';
        $txId = trim((string) ($req['transactionId'] ?? ''));
        $betId = trim((string) ($req['betId'] ?? ''));
        $username = trim((string) ($req['username'] ?? ''));
        $currency = trim((string) ($req['currency'] ?? ''));
        if ($txId === '' || $betId === '' || $username === '' || $currency === '' || !isset($req['amount'])) {
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
        $refund = Money::decimalToLedgerUnits((string) $req['amount'], $acct['exponent']);
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
}

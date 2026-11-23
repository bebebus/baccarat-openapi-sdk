<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

require_once __DIR__ . '/../autoload.php';

use Bebebus\BaccaratSdk\BaccaratApiException;
use Bebebus\BaccaratSdk\BaccaratSdkException;
use Bebebus\BaccaratSdk\Client;
use Bebebus\BaccaratSdk\Config;
use Bebebus\BaccaratSdk\Idempotency;
use Bebebus\BaccaratSdk\InMemoryWallet;
use Bebebus\BaccaratSdk\Money;
use Bebebus\BaccaratSdk\Signing;
use Bebebus\BaccaratSdk\StatusCode;
use Bebebus\BaccaratSdk\WebhookDispatcher;

function assertEq(mixed $actual, mixed $expected, string $label): void
{
    if ($actual !== $expected) {
        fwrite(STDERR, "FAIL [{$label}]: expected " . var_export($expected, true) . ', got ' . var_export($actual, true) . "\n");
        exit(1);
    }
}

$vectors = json_decode((string) file_get_contents(__DIR__ . '/../../test-vectors.json'), true, 512, JSON_THROW_ON_ERROR);

// 1. HMAC & header vectors
foreach ($vectors['hmacVectors'] as $v) {
    assertEq(strlen($v['rawBody']), $v['utf8ByteLength'], $v['name'] . ':len');
    assertEq(Signing::signBody($v['rawBody'], $v['secret']), $v['signature'], $v['name'] . ':sign');
    assertEq(Signing::verifySignature($v['rawBody'], $v['signature'], $v['secret']), true, $v['name'] . ':verify');
    if (isset($v['wrongBase64DecodedSignature'])) {
        assertEq(Signing::verifySignature($v['rawBody'], $v['wrongBase64DecodedSignature'], $v['secret']), false, $v['name'] . ':wrongB64');
    }
}
foreach ($vectors['headerVerificationVectors'] as $h) {
    $st = Signing::verifyWebhookHeaders($h['apiKeyHeader'], $h['signatureHeader'], $h['rawBody'], $h['expectedApiKey'], $h['hmacSecret']);
    assertEq($st, $h['expectedStatus'], $h['name']);
}

// 2. Idempotency fingerprints
$idem = $vectors['idempotencyVectors'];
assertEq(Idempotency::betFingerprint($idem['bet']['initial']), $idem['bet']['expectedFingerprint'], 'bet:init');
assertEq(Idempotency::betFingerprint($idem['bet']['retrySameBusiness']), $idem['bet']['expectedFingerprint'], 'bet:retry');
assertEq(Idempotency::betFingerprint($idem['bet']['conflictDifferentAmount']), $idem['bet']['conflictFingerprint'], 'bet:conflict');

assertEq(Idempotency::betResultFingerprint($idem['betResult']['initial']), $idem['betResult']['expectedFingerprint'], 'stl:init');
assertEq(Idempotency::betResultFingerprint($idem['betResult']['retrySameBusiness']), $idem['betResult']['expectedFingerprint'], 'stl:retry');
assertEq(Idempotency::betResultFingerprint($idem['betResult']['conflictDifferentWinAmount']), $idem['betResult']['conflictFingerprint'], 'stl:conflict');

assertEq(Idempotency::rollbackFingerprint($idem['rollback']['initial']), $idem['rollback']['expectedFingerprint'], 'rb:init');
assertEq(Idempotency::rollbackFingerprint($idem['rollback']['retrySameBusiness']), $idem['rollback']['expectedFingerprint'], 'rb:retry');
assertEq(Idempotency::rollbackFingerprint($idem['rollback']['conflictDifferentAmount']), $idem['rollback']['conflictFingerprint'], 'rb:conflict');

assertEq(Idempotency::adjustmentFingerprint($idem['adjustment']['initial']), $idem['adjustment']['expectedFingerprint'], 'adj:init');
assertEq(Idempotency::adjustmentFingerprint($idem['adjustment']['retrySameBusiness']), $idem['adjustment']['expectedFingerprint'], 'adj:retry');
assertEq(Idempotency::adjustmentFingerprint($idem['adjustment']['conflictDifferentDirection']), $idem['adjustment']['conflictFingerprint'], 'adj:conflict');

// 3. Money & status vectors
foreach ($vectors['moneyVectors']['valid'] as $m) {
    $units = Money::decimalToLedgerUnits($m['raw'], $m['displayExponent'], $m['allowNegative']);
    assertEq($units, $m['expectedUnits'], $m['name'] . ':units');
    assertEq(Money::ledgerUnitsToDecimal($units, $m['displayExponent']), $m['expectedFormatted'], $m['name'] . ':fmt');
}
foreach ($vectors['moneyVectors']['invalid'] as $inv) {
    $threw = false;
    try {
        Money::decimalToLedgerUnits($inv['raw'], $inv['displayExponent'], $inv['allowNegative']);
    } catch (BaccaratSdkException) {
        $threw = true;
    }
    assertEq($threw, true, 'money:invalid:' . $inv['name']);
}
foreach ($vectors['statusCodes'] as $sc) {
    assertEq(StatusCode::isRetryable($sc['code']), $sc['retryable'], 'retryable:' . $sc['code']);
}

// 4. S2S Client round-trip via verified mock transport
$apiKey = 'ak_0123456789abcdef0123456789abcdef';
$secret = 'dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s';
$cfg = new Config($apiKey, $secret, Config::ENV_SANDBOX);

$mockTransport = static function (string $url, array $headers, string $rawBody, int $timeoutMs) use ($apiKey, $secret): array {
    $st = Signing::verifyWebhookHeaders($headers['X-API-Key'] ?? null, $headers['X-Signature'] ?? null, $rawBody, $apiKey, $secret);
    $body = json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR);
    if ($st !== StatusCode::SC_OK) {
        return [200, json_encode(['traceId' => $body['traceId'], 'status' => $st, 'message' => 'bad auth'])];
    }
    if (str_ends_with($url, '/operator/v1/game/tables')) {
        return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_OK', 'data' => ['tables' => [['tableId' => 'T-A2', 'currency' => 'USD']], 'pageNo' => 1, 'pageSize' => 50, 'total' => 1]])];
    }
    if (str_ends_with($url, '/operator/v1/game/url')) {
        if ($body['currency'] !== 'USD') {
            return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_WRONG_CURRENCY', 'message' => 'USD required'])];
        }
        $tok = 'b2bt_' . str_repeat('c', 48);
        return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_OK', 'data' => ['gameUrl' => "https://play.lt.cniia.cloud/?token={$tok}", 'token' => $tok]])];
    }
    if (str_ends_with($url, '/operator/v1/game/terminate')) {
        return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_OK', 'data' => ['username' => $body['username'], 'terminatedSessions' => 1, 'revokedLaunchTokens' => 0]])];
    }
    if (str_ends_with($url, '/operator/v1/transaction/list')) {
        $rows = ($body['pageNo'] ?? 1) === 1 ? [['betId' => 'b2btkt1'], ['betId' => 'b2btkt2']] : [['betId' => 'b2btkt3']];
        return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_OK', 'data' => ['transactions' => $rows, 'pageNo' => $body['pageNo'] ?? 1, 'pageSize' => 2, 'total' => 3]])];
    }
    return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_OK', 'data' => ['betId' => $body['betId'], 'status' => 1, 'roundResult' => ['outcome' => 'TIE', 'playerPoints' => 6, 'bankerPoints' => 6, 'playerPair' => false, 'bankerPair' => false, 'natural' => false]]])];
};

$client = new Client($cfg, $mockTransport);
assertEq($client->listTables(['currency' => 'USD'])['data']['tables'][0]['tableId'], 'T-A2', 's2s:tables');
$launch = $client->createGameUrl([
    'username' => 'player_9527',
    'tableId' => 'T-A2',
    'platform' => 'H5',
    'currency' => 'USD',
    'lobbyUrl' => 'https://merchant.example.com/lobby',
    'ipAddress' => '203.0.113.42',
]);
assertEq(str_starts_with($launch['data']['token'], 'b2bt_'), true, 's2s:url');

$caughtApiErr = false;
try {
    $client->createGameUrl([
        'username' => 'player_9527',
        'tableId' => 'T-A2',
        'platform' => 'H5',
        'currency' => 'JPY',
        'lobbyUrl' => 'https://merchant.example.com/lobby',
        'ipAddress' => '203.0.113.42',
    ]);
} catch (BaccaratApiException $e) {
    $caughtApiErr = ($e->status === 'SC_WRONG_CURRENCY' && !$e->isRetryable());
}
assertEq($caughtApiErr, true, 's2s:wrongCurrency');

assertEq($client->terminateSessions(['username' => 'player_9527'])['data']['terminatedSessions'], 1, 's2s:terminate');
assertEq(count($client->listAllTransactions(1000, 2000, 2)), 3, 's2s:txAll');
assertEq($client->getTransactionDetail(['betId' => 'b2btkt1', 'fromTime' => 1000, 'toTime' => 2000])['data']['roundResult']['outcome'], 'TIE', 's2s:detail');

// 5. WebhookDispatcher & InMemoryWallet lifecycle
$tok = 'b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819';
$wallet = new InMemoryWallet(['player_9527' => ['currency' => 'USD', 'balance' => '1000.00', 'exponent' => 2, 'tokens' => [$tok]]]);
$disp = new WebhookDispatcher($cfg, $wallet);
$send = static function (string $route, array $obj) use ($disp, $apiKey, $secret): array {
    $raw = json_encode($obj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    return $disp->handle($route, $apiKey, Signing::signBody($raw, $secret), $raw)['body'];
};

assertEq($send('/wallet/balance', ['traceId' => 't1', 'username' => 'player_9527', 'currency' => 'USD', 'token' => $tok])['data']['balance'], '1000.00', 'wb:balance');
assertEq($send('/wallet/bet', $idem['bet']['initial'])['data']['balance'], '900.00', 'wb:bet');
assertEq($send('/wallet/bet', $idem['bet']['retrySameBusiness'])['data']['balance'], '900.00', 'wb:betReplay');
assertEq($send('/wallet/bet', $idem['bet']['conflictDifferentAmount'])['status'], 'SC_TRANSACTION_DUPLICATED', 'wb:betConflict');

$wallet->setDisabled('player_9527', true);
assertEq($send('/wallet/bet_result', $idem['betResult']['initial'])['data']['balance'], '1100.00', 'wb:settle');
assertEq($send('/wallet/adjustment', $idem['adjustment']['initial'])['data']['balance'], '1120.00', 'wb:adjCredit');
assertEq($send('/wallet/adjustment', $idem['adjustment']['retrySameBusiness'])['data']['balance'], '1120.00', 'wb:adjReplay');
assertEq($send('/wallet/adjustment', $idem['adjustment']['conflictDifferentDirection'])['status'], 'SC_TRANSACTION_DUPLICATED', 'wb:adjConflict');
assertEq($send('/wallet/adjustment', array_merge($idem['adjustment']['initial'], ['transactionId' => 'adj_debit_php', 'direction' => 'DEBIT', 'amount' => '20.00']))['data']['balance'], '1100.00', 'wb:adjDebit');
$unknownRb = array_merge($idem['rollback']['initial'], [
    'transactionId' => 'rb_b2btkt000000000000000000000000',
    'betId' => 'b2btkt000000000000000000000000',
    'externalTransactionId' => 'b2btkt000000000000000000000000',
]);
assertEq($send('/wallet/rollback', $unknownRb)['status'], 'SC_TRANSACTION_NOT_EXISTS', 'wb:emptyRollback');

// 6. CR-01..CR-10 regressions: empty object {} accepted as JSON object (returns missing-field SC_INVALID_REQUEST, not Invalid JSON body),
// rollback after settle rejected, malformed decimal caught as SC_INVALID_REQUEST, custom WalletHandlerInterface supported!
$emptyObjRaw = '{}';
$emptyObjRes = $disp->handle('/wallet/balance', $apiKey, Signing::signBody($emptyObjRaw, $secret), $emptyObjRaw)['body'];
assertEq($emptyObjRes['status'], 'SC_INVALID_REQUEST', 'wb:emptyJsonObj');
assertEq($emptyObjRes['message'], 'username and currency are required', 'wb:emptyJsonObjMsg');
assertEq($send('/wallet/rollback', $idem['rollback']['initial'])['status'], 'SC_TRANSACTION_DUPLICATED', 'wb:rbAfterSettle');

$wallet->setDisabled('player_9527', false);
$badAmtBet = array_merge($idem['bet']['initial'], ['transactionId' => 'bet_bad_php', 'betId' => 'b2btkt_bad_php', 'amount' => 'bad']);
assertEq($send('/wallet/bet', $badAmtBet)['status'], 'SC_INVALID_REQUEST', 'wb:badAmtCaught');
$zeroBet = array_merge($idem['bet']['initial'], ['transactionId' => 'bet_zero_php', 'betId' => 'b2btkt_zero_php', 'amount' => '0.00']);
assertEq($send('/wallet/bet', $zeroBet)['status'], 'SC_INVALID_REQUEST', 'wb:zeroBet');
assertEq($disp->handle('/wallet/bet', 'bad', 'bad', str_repeat('[', 50000))['body']['status'], 'SC_AUTHENTICATION_FAILED', 'wb:preAuthDeep');

$customWallet = new class implements \Bebebus\BaccaratSdk\WalletHandlerInterface {
    public function onBalance(array $req): array { return ['traceId' => $req['traceId'] ?? '', 'status' => 'SC_OK', 'data' => ['balance' => '42.00', 'timestamp' => 1]]; }
    public function onBet(array $req): array { return $this->onBalance($req); }
    public function onBetResult(array $req): array { return $this->onBalance($req); }
    public function onRollback(array $req): array { return $this->onBalance($req); }
};
$customDisp = new WebhookDispatcher($cfg, $customWallet);
assertEq($customDisp->handle('/wallet/balance', $apiKey, Signing::signBody($emptyObjRaw, $secret), $emptyObjRaw)['body']['data']['balance'], '42.00', 'wb:customInterface');

echo "PHP SDK: ALL TESTS PASSED\n";

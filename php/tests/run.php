<?php
// SPDX-License-Identifier: MIT
declare(strict_types=1);

require_once __DIR__ . '/../autoload.php';

use Bebebus\BaccaratSdk\BaccaratApiException;
use Bebebus\BaccaratSdk\BaccaratSdkException;
use Bebebus\BaccaratSdk\BaccaratTransportException;
use Bebebus\BaccaratSdk\Client;
use Bebebus\BaccaratSdk\Config;
use Bebebus\BaccaratSdk\Idempotency;
use Bebebus\BaccaratSdk\InMemoryWallet;
use Bebebus\BaccaratSdk\Money;
use Bebebus\BaccaratSdk\Signing;
use Bebebus\BaccaratSdk\StatusCode;
use Bebebus\BaccaratSdk\WalletResponse;
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
    if (str_ends_with($url, '/operator/v1/player/status')) {
        if (($body['username'] ?? '') === 'locked_user') {
            return [403, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_USER_DISABLED', 'message' => 'PLATFORM_RISK_LOCKED'])];
        }
        if (($body['username'] ?? '') === 'capped_user' && ($body['bettingEnabled'] ?? false) === true && ($body['resetPnlWindow'] ?? false) !== true) {
            return [409, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_INVALID_REQUEST', 'message' => 'PNL_CAP_BREACHED_RESET_REQUIRED'])];
        }
        return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_OK', 'data' => ['username' => $body['username'], 'status' => $body['status'] ?? 'ACTIVE', 'bettingEnabled' => $body['bettingEnabled'] ?? true, 'rgRestricted' => false, 'statusReason' => null, 'revokedSessions' => 0, 'revokedLaunchTokens' => 0]])];
    }
    if (str_ends_with($url, '/operator/v1/wallet/transaction-status')) {
        return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_OK', 'data' => ['transactions' => [['transactionId' => $body['transactionId'] ?? 'bet_u1', 'username' => $body['username'] ?? 'player_9527', 'status' => 'COMPLETED']]]])];
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
assertEq($client->updatePlayerStatus(['username' => 'capped_user', 'action' => 'SET', 'bettingEnabled' => true, 'resetPnlWindow' => true])['data']['bettingEnabled'], true, 's2s:playerStatusReset');
$caught403 = false;
try {
    $client->updatePlayerStatus(['username' => 'locked_user', 'action' => 'SET', 'status' => 'ACTIVE']);
} catch (BaccaratApiException $e) {
    $caught403 = ($e->httpStatus === 403 && $e->status === 'SC_USER_DISABLED' && $e->getMessage() === 'PLATFORM_RISK_LOCKED' && !$e->isRetryable());
}
assertEq($caught403, true, 's2s:playerStatus403');
$caught409 = false;
try {
    $client->updatePlayerStatus(['username' => 'capped_user', 'action' => 'SET', 'bettingEnabled' => true]);
} catch (BaccaratApiException $e) {
    $caught409 = ($e->httpStatus === 409 && $e->status === 'SC_INVALID_REQUEST' && $e->getMessage() === 'PNL_CAP_BREACHED_RESET_REQUIRED' && !$e->isRetryable());
}
assertEq($caught409, true, 's2s:playerStatus409');
assertEq($client->getWalletTransactionStatus(['username' => 'player_9527', 'fromTime' => 0, 'toTime' => 86400000])['data']['transactions'][0]['username'], 'player_9527', 's2s:walletStatusByUser');

$expectInvalidArg = static function (callable $fn, string $label): void {
    $threw = false;
    try {
        $fn();
    } catch (BaccaratSdkException $e) {
        $threw = ($e->errorCode === 'INVALID_ARGUMENT');
    }
    assertEq($threw, true, $label);
};
$expectInvalidArg(static fn() => $client->getWalletTransactionStatus([]), 's2s:wtsEmpty');
$expectInvalidArg(static fn() => $client->getWalletTransactionStatus(['username' => 'player_9527']), 's2s:wtsUserNoWindow');
$expectInvalidArg(static fn() => $client->getWalletTransactionStatus(['username' => 'player_9527', 'fromTime' => 0, 'toTime' => 86400001]), 's2s:wtsUserOver24h');
$expectInvalidArg(static fn() => $client->getWalletTransactionStatus(['transactionId' => 'bet_1', 'fromTime' => 1000]), 's2s:wtsPartialWindow');
$expectInvalidArg(static fn() => $client->getWalletTransactionStatus(['betId' => 'b2btkt1', 'fromTime' => 2000, 'toTime' => 1000]), 's2s:wtsInvertedWindow');
$expectInvalidArg(static fn() => $client->getWalletTransactionStatus(['transactionId' => 'bet_1', 'fromTime' => null]), 's2s:wtsNullFrom');
$expectInvalidArg(static fn() => $client->getTransactionDetail(['betId' => 'b2btkt1', 'fromTime' => null]), 's2s:detailNullFrom');
$expectInvalidArg(static fn() => $client->listUnsettledTransactions(['fromTime' => null]), 's2s:unsettledNullFrom');

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

// 7. Regressions: sendTimestamp X-Timestamp, non-JSON/JSON missing-or-empty-status 429 & 503 (M1),
//    listAllTransactions backoff + filters + traceId stripping (m1), WebhookDispatcher::fromCredentials,
//    leading-'?' query route rejection (M5), WalletAdjustmentHandlerInterface (m3), UTF-8 traceId truncation (m10)
$capturedHeaders = [];
$capturedListTraces = [];
$page1Attempts = 0;
$tsTransport = static function (string $url, array $headers, string $rawBody, int $timeoutMs) use (&$capturedHeaders, &$capturedListTraces, &$page1Attempts): array {
    $capturedHeaders[] = $headers;
    $body = json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR);
    if (str_ends_with($url, '/operator/v1/ping')) {
        if (($body['traceId'] ?? '') === 'm1_json_429') {
            return [429, json_encode(['statusCode' => 429, 'message' => 'Too Many Requests'])];
        }
        if (($body['traceId'] ?? '') === 'm1_empty_429') {
            return [429, json_encode(['status' => '', 'message' => 'Empty status'])];
        }
        if (($body['traceId'] ?? '') === 'm1_json_503') {
            return [503, json_encode(['error' => 'unavailable'])];
        }
        return [429, 'Too Many Requests'];
    }
    $capturedListTraces[] = $body['traceId'] ?? '';
    if (($body['pageNo'] ?? 1) === 1 && $page1Attempts === 0) {
        $page1Attempts++;
        return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_RATE_LIMITED', 'message' => 'slow down'])];
    }
    $rows = ($body['pageNo'] ?? 1) === 1 ? [['betId' => 'b1'], ['betId' => 'b2']] : [['betId' => 'b3']];
    return [200, json_encode(['traceId' => $body['traceId'], 'status' => 'SC_OK', 'data' => ['transactions' => $rows, 'pageNo' => $body['pageNo'], 'pageSize' => 2, 'total' => 3]])];
};
$tsCfg = new Config($apiKey, $secret, Config::ENV_SANDBOX, null, 8000, true);
$tsClient = new Client($tsCfg, $tsTransport);
$caught429 = false;
try {
    $tsClient->ping();
} catch (BaccaratApiException $e) {
    $caught429 = ($e->httpStatus === 429 && $e->status === StatusCode::SC_RATE_LIMITED && $e->isRetryable());
}
assertEq($caught429, true, 's2s:nonJson429RateLimited');
assertEq((bool) preg_match('/^\d{13}$/', $capturedHeaders[0]['X-Timestamp'] ?? ''), true, 's2s:xTimestampHeader');

foreach ([
    ['m1_json_429', 429, StatusCode::SC_RATE_LIMITED],
    ['m1_empty_429', 429, StatusCode::SC_RATE_LIMITED],
    ['m1_json_503', 503, StatusCode::SC_OPERATOR_TIMEOUT],
] as [$tid, $expHttp, $expStatus]) {
    $ok = false;
    try {
        $tsClient->ping(['traceId' => $tid]);
    } catch (BaccaratApiException $e) {
        $ok = ($e->httpStatus === $expHttp && $e->status === $expStatus && $e->isRetryable());
    }
    assertEq($ok, true, 's2s:m1:' . $tid);
}

$retriedAll = $tsClient->listAllTransactions(1000, 2000, 2, ['username' => 'player_9527', 'traceId' => 'caller-fixed-trace'], 3, 0);
assertEq(count($retriedAll), 3, 's2s:listAllRateLimitRetry');
assertEq($page1Attempts, 1, 's2s:listAllRetryCount');
assertEq(count($capturedListTraces), 3, 's2s:listAllTraceCount');
assertEq(count(array_unique($capturedListTraces)), 3, 's2s:listAllUniqueTraces');
assertEq(in_array('caller-fixed-trace', $capturedListTraces, true), false, 's2s:listAllStrippedTraceId');

$credDisp = WebhookDispatcher::fromCredentials($apiKey, $secret, $customWallet);
assertEq($credDisp->handle('/wallet/balance', $apiKey, Signing::signBody($emptyObjRaw, $secret), $emptyObjRaw)['body']['data']['balance'], '42.00', 'wb:fromCredentials');

// M5: leading '?' query string must NOT bypass route matching via strtok
$qRouteRes = $credDisp->handle('?/wallet/balance', $apiKey, Signing::signBody($emptyObjRaw, $secret), $emptyObjRaw)['body'];
assertEq($qRouteRes['status'], StatusCode::SC_INVALID_REQUEST, 'wb:m5LeadingQuestionMark');
assertEq(str_starts_with((string) ($qRouteRes['message'] ?? ''), 'Unknown route'), true, 'wb:m5LeadingQuestionMarkMsg');

// m3: WalletAdjustmentHandlerInterface check
assertEq($wallet instanceof \Bebebus\BaccaratSdk\WalletAdjustmentHandlerInterface, true, 'wb:m3InMemoryImplementsAdjInterface');
$typedAdjWallet = new class implements \Bebebus\BaccaratSdk\WalletHandlerInterface, \Bebebus\BaccaratSdk\WalletAdjustmentHandlerInterface {
    public function onBalance(array $req): array { return ['traceId' => $req['traceId'] ?? '', 'status' => 'SC_OK', 'data' => ['balance' => '1.00', 'timestamp' => 1]]; }
    public function onBet(array $req): array { return $this->onBalance($req); }
    public function onBetResult(array $req): array { return $this->onBalance($req); }
    public function onRollback(array $req): array { return $this->onBalance($req); }
    public function onAdjustment(array $req): array { return ['traceId' => $req['traceId'] ?? '', 'status' => 'SC_OK', 'data' => ['balance' => '77.00', 'timestamp' => 1]]; }
};
$typedAdjDisp = WebhookDispatcher::fromCredentials($apiKey, $secret, $typedAdjWallet);
assertEq($typedAdjDisp->handle('/wallet/adjustment', $apiKey, Signing::signBody($emptyObjRaw, $secret), $emptyObjRaw)['body']['data']['balance'], '77.00', 'wb:m3TypedAdjDispatch');

// m10: UTF-8 multi-byte traceId > 128 bytes/chars must not be corrupted on truncation
$utf8Trace = str_repeat('中', 140);
$utf8Raw = json_encode(['traceId' => $utf8Trace], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
$utf8Res = $credDisp->handle('/wallet/unknown', $apiKey, Signing::signBody($utf8Raw, $secret), $utf8Raw)['body'];
assertEq($utf8Res['status'], StatusCode::SC_INVALID_REQUEST, 'wb:m10Utf8TraceStatus');
assertEq((bool) preg_match('//u', (string) $utf8Res['traceId']), true, 'wb:m10Utf8Valid');
assertEq($utf8Res['traceId'], str_repeat('中', 128), 'wb:m10Utf8CharCount');

// 8. v1.5.11 regressions: deadlock, S2S ApiException/TransportException/overflow & allowlist SdkException safety, WalletResponse builders, strict type guards
// Verify postSigned attaches traceId on 16 MiB overflow BaccaratApiException with empty traceId
$ovClient = new Client(
    $cfg,
    static function (string $url, array $headers, string $rawBody, int $timeoutMs): array {
        throw new BaccaratApiException(StatusCode::SC_INVALID_REQUEST, 'Gateway response exceeded 16 MiB limit', '', null, 200);
    }
);
$caughtPhpOv = false;
try {
    $ovClient->ping(['traceId' => 't_php_ov']);
} catch (BaccaratApiException $e) {
    $caughtPhpOv = ($e->status === StatusCode::SC_INVALID_REQUEST && $e->httpStatus === 200 && $e->traceId === 't_php_ov' && !$e->isRetryable());
}
assertEq($caughtPhpOv, true, 's2s:phpOverflowApiException');

// Verify real cURL transport failure raises BaccaratTransportException (subclass of BaccaratSdkException)
$deadPortCfg = new Config($apiKey, $secret, Config::ENV_PRODUCTION, 'http://127.0.0.1:1', 500);
$deadPortClient = new Client($deadPortCfg);
$caughtPhpTransport = false;
try {
    $deadPortClient->ping(['traceId' => 't_php_connrefused']);
} catch (BaccaratTransportException $e) {
    $caughtPhpTransport = ($e instanceof BaccaratSdkException && $e->errorCode === StatusCode::SC_OPERATOR_TIMEOUT);
}
assertEq($caughtPhpTransport, true, 's2s:phpCurlTransportException');

$deadlockWallet = new class implements \Bebebus\BaccaratSdk\WalletHandlerInterface {
    public function onBalance(array $req): array { throw new BaccaratSdkException('explicit sdk err', StatusCode::SC_INSUFFICIENT_FUNDS); }
    public function onBet(array $req): array {
        Money::decimalToLedgerUnits((string) ($req['amount'] ?? 'bad_amt'), 2, false);
        return WalletResponse::ok((string) ($req['traceId'] ?? ''), 'p1', 'USD', '100.00');
    }
    public function onBetResult(array $req): array {
        $mode = (string) ($req['mode'] ?? '');
        if ($mode === 'bad_balance') {
            return WalletResponse::ok((string) ($req['traceId'] ?? ''), 'p1', 'USD', '-1.00');
        }
        if ($mode === 'nan_balance') {
            return WalletResponse::ok((string) ($req['traceId'] ?? ''), 'p1', 'USD', 'NaN');
        }
        if ($mode === 's2s_api_err') {
            throw new BaccaratApiException(StatusCode::SC_INVALID_REQUEST, 'upstream S2S failure secret detail', 't_upstream_s2s', null, 400);
        }
        if ($mode === 's2s_overflow_err') {
            throw new BaccaratApiException(StatusCode::SC_INVALID_REQUEST, 'Gateway response exceeded 16 MiB limit', 't_upstream_overflow', null, 200);
        }
        if ($mode === 's2s_transport_err') {
            throw new BaccaratTransportException('curl failed: 10.0.1.5:8443 proxy refused');
        }
        if ($mode === 'sdk_sc_ok') {
            throw new BaccaratSdkException('bogus SC_OK error', StatusCode::SC_OK);
        }
        if ($mode === 'sdk_sc_custom') {
            throw new BaccaratSdkException('bogus custom error', 'SC_CUSTOM');
        }
        if ($mode === 'sdk_sc_prefix') {
            throw new BaccaratSdkException('bogus prefix error', 'SC_');
        }
        throw new \RuntimeException('ERROR: deadlock detected (40P01) on table wallets');
    }
    public function onRollback(array $req): array { return WalletResponse::ok((string) ($req['traceId'] ?? ''), 'p1', 'USD', '100.00', 1700000000000); }
};
$dlDisp = WebhookDispatcher::fromCredentials($apiKey, $secret, $deadlockWallet);
$dlRaw = json_encode(['traceId' => 't_php_dl', 'transactionId' => 'stl_1'], JSON_THROW_ON_ERROR);
$dlOut = $dlDisp->handle('/wallet/bet_result', $apiKey, Signing::signBody($dlRaw, $secret), $dlRaw);
assertEq($dlOut['statusCode'], 200, 'wb:deadlockHttp200');
assertEq($dlOut['body']['traceId'], 't_php_dl', 'wb:deadlockTraceId');
assertEq($dlOut['body']['status'], StatusCode::SC_OPERATOR_TIMEOUT, 'wb:deadlockTimeoutStatus');
assertEq($dlOut['body']['message'], 'Temporary wallet handler error', 'wb:deadlockSanitizedMsg');
assertEq(str_contains((string) $dlOut['body']['message'], '40P01'), false, 'wb:deadlockNoLeakSql');

foreach (['bad_balance', 'nan_balance', 's2s_api_err', 's2s_overflow_err', 's2s_transport_err', 'sdk_sc_ok', 'sdk_sc_custom', 'sdk_sc_prefix'] as $mode) {
    $bbRaw = json_encode(['traceId' => "t_php_$mode", 'mode' => $mode], JSON_THROW_ON_ERROR);
    $bbOut = $dlDisp->handle('/wallet/bet_result', $apiKey, Signing::signBody($bbRaw, $secret), $bbRaw);
    assertEq($bbOut['statusCode'], 200, "wb:internalSdkErrHttp200:$mode");
    assertEq($bbOut['body']['traceId'], "t_php_$mode", "wb:internalSdkErrTrace:$mode");
    assertEq($bbOut['body']['status'], StatusCode::SC_OPERATOR_TIMEOUT, "wb:internalSdkErrStatus:$mode");
    assertEq($bbOut['body']['message'], 'Temporary wallet handler error', "wb:internalSdkErrMsg:$mode");
    assertEq(str_contains((string) $bbOut['body']['message'], 'WalletResponse::ok'), false, "wb:internalSdkErrNoLeak:$mode");
    assertEq(str_contains((string) $bbOut['body']['message'], 'upstream'), false, "wb:internalSdkErrNoS2sLeak:$mode");
    assertEq(str_contains((string) $bbOut['body']['message'], '10.0.1.5'), false, "wb:internalSdkErrNoTransportLeak:$mode");
    assertEq(str_contains((string) $bbOut['body']['message'], '16 MiB'), false, "wb:internalSdkErrNoOverflowLeak:$mode");
    assertEq(str_contains((string) $bbOut['body']['message'], 'bogus'), false, "wb:internalSdkErrNoBogusLeak:$mode");
}

foreach (['not_a_number', '1.123456', '-5.00'] as $badAmt) {
    $bdRaw = json_encode(['traceId' => 't_php_bad_dec', 'amount' => $badAmt], JSON_THROW_ON_ERROR);
    $bdOut = $dlDisp->handle('/wallet/bet', $apiKey, Signing::signBody($bdRaw, $secret), $bdRaw);
    assertEq($bdOut['statusCode'], 200, "wb:incomingDecHttp200:$badAmt");
    assertEq($bdOut['body']['status'], StatusCode::SC_INVALID_REQUEST, "wb:incomingDecInvalidReq:$badAmt");
}

$sdkErrOut = $dlDisp->handle('/wallet/balance', $apiKey, Signing::signBody($dlRaw, $secret), $dlRaw);
assertEq($sdkErrOut['body']['status'], StatusCode::SC_INSUFFICIENT_FUNDS, 'wb:sdkErrPreserved');

$okResp = WalletResponse::ok('t_ok', 'player_1', 'JPY', '0');
assertEq($okResp['status'], StatusCode::SC_OK, 'walletResp:okStatus');
assertEq($okResp['data']['balance'], '0', 'walletResp:okBalance');
assertEq(is_int($okResp['data']['timestamp']), true, 'walletResp:okTs');
$errResp = WalletResponse::error('t_err', StatusCode::SC_INSUFFICIENT_FUNDS, 'low');
assertEq($errResp, ['traceId' => 't_err', 'status' => StatusCode::SC_INSUFFICIENT_FUNDS, 'message' => 'low'], 'walletResp:err');

foreach (['', '   ', '-1.00', 'abc', '10.', '.5', "10.00\n"] as $badBal) {
    $threw = false;
    try {
        WalletResponse::ok('t_bad', 'player_1', 'USD', $badBal);
    } catch (BaccaratSdkException $e) {
        $threw = ($e->errorCode === 'INVALID_ARGUMENT');
    }
    assertEq($threw, true, "walletResp:badBalance:$badBal");
}
foreach (['', '   ', StatusCode::SC_OK, ' SC_OK ', 'sc_ok', 'Sc_Ok', ' sc_ok ', 'SC_', 'SC_TIMEOUT', 'SC_CUSTOM', 'INSUFFICIENT_FUNDS'] as $badStatus) {
    $threw = false;
    try {
        WalletResponse::error('t_bad', $badStatus, 'oops');
    } catch (BaccaratSdkException $e) {
        $threw = ($e->errorCode === 'INVALID_ARGUMENT');
    }
    assertEq($threw, true, "walletResp:badStatus:$badStatus");
}

// v1.5.11 P1-1: PHP InMemoryWallet, Idempotency, Client strict type guards (zero E_WARNINGs)
set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    throw new \ErrorException($message, 0, $severity, $file, $line);
});
try {
    $strictWallet = new InMemoryWallet(['alice' => ['currency' => 'USD', 'balance' => '1000.00', 'exponent' => 2, 'tokens' => ['tok_ok']]]);
    $strictDisp = WebhookDispatcher::fromCredentials($apiKey, $secret, $strictWallet);
    $sendStrict = static function (string $route, array $obj) use ($strictDisp, $apiKey, $secret): array {
        $raw = json_encode($obj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        return $strictDisp->handle($route, $apiKey, Signing::signBody($raw, $secret), $raw)['body'];
    };

    $rTxArr = $sendStrict('/wallet/bet', [
        'traceId' => 't_p11_tx',
        'transactionId' => ['a'],
        'betId' => 'b_p11_1',
        'username' => 'alice',
        'currency' => 'USD',
        'amount' => '10.00',
        'token' => 'tok_ok',
    ]);
    assertEq($rTxArr['status'], StatusCode::SC_INVALID_REQUEST, 'p11:txIdArray');

    $rAmtBool = $sendStrict('/wallet/bet', [
        'traceId' => 't_p11_amt_bool',
        'transactionId' => 'tx_p11_2',
        'betId' => 'b_p11_2',
        'username' => 'alice',
        'currency' => 'USD',
        'amount' => true,
        'token' => 'tok_ok',
    ]);
    assertEq($rAmtBool['status'], StatusCode::SC_INVALID_REQUEST, 'p11:amountBool');

    $rAmtFloat = $sendStrict('/wallet/bet', [
        'traceId' => 't_p11_amt_float',
        'transactionId' => 'tx_p11_2f',
        'betId' => 'b_p11_2f',
        'username' => 'alice',
        'currency' => 'USD',
        'amount' => 10.5,
        'token' => 'tok_ok',
    ]);
    assertEq($rAmtFloat['status'], StatusCode::SC_INVALID_REQUEST, 'p11:amountFloat');

    $rAmtArr = $sendStrict('/wallet/bet', [
        'traceId' => 't_p11_amt_arr',
        'transactionId' => 'tx_p11_2a',
        'betId' => 'b_p11_2a',
        'username' => 'alice',
        'currency' => 'USD',
        'amount' => ['10.00'],
        'token' => 'tok_ok',
    ]);
    assertEq($rAmtArr['status'], StatusCode::SC_INVALID_REQUEST, 'p11:amountArray');

    $rTokBal = $sendStrict('/wallet/balance', [
        'traceId' => 't_p11_tok_bal',
        'username' => 'alice',
        'currency' => 'USD',
        'token' => ['a'],
    ]);
    assertEq($rTokBal['status'], StatusCode::SC_INVALID_TOKEN, 'p11:tokenArrayBalance');

    $rTokBet = $sendStrict('/wallet/bet', [
        'traceId' => 't_p11_tok_bet',
        'transactionId' => 'tx_p11_3',
        'betId' => 'b_p11_3',
        'username' => 'alice',
        'currency' => 'USD',
        'amount' => '10.00',
        'token' => ['a'],
    ]);
    assertEq($rTokBet['status'], StatusCode::SC_INVALID_TOKEN, 'p11:tokenArrayBet');

    $rRoundArr = $sendStrict('/wallet/bet', [
        'traceId' => 't_p11_round',
        'transactionId' => 'tx_p11_4',
        'betId' => 'b_p11_4',
        'username' => 'alice',
        'currency' => 'USD',
        'amount' => '0.00',
        'roundId' => ['a'],
        'token' => 'tok_ok',
    ]);
    assertEq($rRoundArr['status'], StatusCode::SC_INVALID_REQUEST, 'p11:roundIdArrayNoWarning');
    assertEq(
        Idempotency::betFingerprint(['transactionId' => 'tx1', 'roundId' => ['a']]),
        Idempotency::betFingerprint(['transactionId' => 'tx1']),
        'p11:idempotencyScalarStrArray'
    );

    $rBalAfter = $sendStrict('/wallet/balance', [
        'traceId' => 't_p11_bal_chk',
        'username' => 'alice',
        'currency' => 'USD',
        'token' => 'tok_ok',
    ]);
    assertEq($rBalAfter['status'], StatusCode::SC_OK, 'p11:balanceUnchangedStatus');
    assertEq($rBalAfter['data']['balance'], '1000.00', 'p11:balanceUnchanged');

    // Client::postSigned with non-string message/traceId in JSON response must not warn
    $arrErrClient = new Client(
        $cfg,
        static fn(string $url, array $headers, string $rawBody, int $timeoutMs): array => [
            400,
            json_encode(['status' => StatusCode::SC_INVALID_REQUEST, 'message' => ['arr'], 'traceId' => ['t']], JSON_THROW_ON_ERROR),
        ]
    );
    $caughtArrErr = false;
    try {
        $arrErrClient->ping(['traceId' => 't_php_arr_err']);
    } catch (BaccaratApiException $e) {
        $caughtArrErr = ($e->status === StatusCode::SC_INVALID_REQUEST && $e->getMessage() === 'HTTP 400' && $e->traceId === 't_php_arr_err');
    }
    assertEq($caughtArrErr, true, 'p11:clientNonStringMsgTraceErr');

    $arrOkClient = new Client(
        $cfg,
        static fn(string $url, array $headers, string $rawBody, int $timeoutMs): array => [
            200,
            json_encode(['status' => StatusCode::SC_OK, 'traceId' => ['t'], 'data' => ['ok' => true]], JSON_THROW_ON_ERROR),
        ]
    );
    $arrOkRes = $arrOkClient->ping(['traceId' => 't_php_arr_ok']);
    assertEq($arrOkRes['traceId'], 't_php_arr_ok', 'p11:clientNonStringTraceOk');

    // 9. v1.6.0: notifyPlayerBalance, getGameCcu, paginated getWalletTransactionStatus, deterministic isEndRound & outbound X-Timestamp
    $v16Captured = [];
    $v16Transport = static function (string $url, array $headers, string $rawBody, int $timeoutMs) use ($apiKey, $secret, &$v16Captured): array {
        $st = Signing::verifyWebhookHeaders($headers['X-API-Key'] ?? null, $headers['X-Signature'] ?? null, $rawBody, $apiKey, $secret);
        $body = json_decode($rawBody, true, 512, JSON_THROW_ON_ERROR);
        $v16Captured[] = ['url' => $url, 'body' => $body];
        if ($st !== StatusCode::SC_OK) {
            return [200, json_encode(['traceId' => $body['traceId'], 'status' => $st, 'message' => 'bad auth'], JSON_THROW_ON_ERROR)];
        }
        if (str_ends_with($url, '/operator/v1/player/balance-notify')) {
            $isOnline = ($body['username'] ?? '') === 'player_online';
            return [200, json_encode([
                'traceId' => $body['traceId'],
                'status' => 'SC_OK',
                'data' => [
                    'username' => $body['username'],
                    'currency' => array_key_exists('currency', $body) && $body['currency'] !== null ? $body['currency'] : ($isOnline ? 'USD' : null),
                    'notified' => $isOnline,
                    'activeSessions' => $isOnline ? 2 : 0,
                    'serverTime' => 1763612000123,
                ],
            ], JSON_THROW_ON_ERROR)];
        }
        if (str_ends_with($url, '/operator/v1/game/ccu')) {
            if (($body['tableId'] ?? null) === 'T-A2') {
                return [200, json_encode([
                    'traceId' => $body['traceId'],
                    'status' => 'SC_OK',
                    'data' => [
                        'operatorId' => 'OP_DEMO',
                        'onlinePlayers' => 7,
                        'seatedPlayers' => 7,
                        'lobbyPlayers' => 0,
                        'tables' => [['tableId' => 'T-A2', 'gameCode' => 'BACCARAT:T-A2', 'playerCount' => 7]],
                        'serverTime' => 1763612000456,
                    ],
                ], JSON_THROW_ON_ERROR)];
            }
            return [200, json_encode([
                'traceId' => $body['traceId'],
                'status' => 'SC_OK',
                'data' => [
                    'operatorId' => 'OP_DEMO',
                    'onlinePlayers' => 15,
                    'seatedPlayers' => 11,
                    'lobbyPlayers' => 4,
                    'tables' => [
                        ['tableId' => 'T-A2', 'gameCode' => 'BACCARAT:T-A2', 'playerCount' => 7],
                        ['tableId' => 'T-A3', 'gameCode' => 'BACCARAT:T-A3', 'playerCount' => 4],
                    ],
                    'serverTime' => 1763612000456,
                ],
            ], JSON_THROW_ON_ERROR)];
        }
        if (str_ends_with($url, '/operator/v1/wallet/transaction-status')) {
            $allRows = [
                ['transactionId' => 'bet_p1', 'username' => 'player_online', 'status' => 'COMPLETED'],
                ['transactionId' => 'bet_p2', 'username' => 'player_online', 'status' => 'COMPLETED'],
                ['transactionId' => 'stl_p3', 'username' => 'player_online', 'status' => 'COMPLETED'],
            ];
            $pageNo = $body['pageNo'] ?? 1;
            $pageSize = $body['pageSize'] ?? 200;
            $slice = array_slice($allRows, ($pageNo - 1) * $pageSize, $pageSize);
            $hasMore = count($slice) > 0 && ($pageNo * $pageSize < count($allRows));
            return [200, json_encode([
                'traceId' => $body['traceId'],
                'status' => 'SC_OK',
                'data' => [
                    'transactions' => $slice,
                    'pageNo' => $pageNo,
                    'pageSize' => $pageSize,
                    'total' => count($allRows),
                    'hasMore' => $hasMore,
                ],
            ], JSON_THROW_ON_ERROR)];
        }
        return [404, json_encode(['traceId' => $body['traceId'] ?? '', 'status' => 'SC_INVALID_REQUEST', 'message' => 'not found'], JSON_THROW_ON_ERROR)];
    };

    $v16Client = new Client($cfg, $v16Transport);

    // 9a. notifyPlayerBalance: online (with currency/reason) & offline (null/omitted)
    $bnOnline = $v16Client->notifyPlayerBalance([
        'username' => 'player_online',
        'currency' => 'USD',
        'reason' => 'DEPOSIT',
    ]);
    assertEq((bool) preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', (string) $bnOnline['traceId']), true, 'v16:bnAutoTrace');
    assertEq($bnOnline['data'], [
        'username' => 'player_online',
        'currency' => 'USD',
        'notified' => true,
        'activeSessions' => 2,
        'serverTime' => 1763612000123,
    ], 'v16:bnOnline');
    assertEq($v16Captured[count($v16Captured) - 1]['body']['reason'], 'DEPOSIT', 'v16:bnReasonSent');

    $bnOffline = $v16Client->notifyPlayerBalance([
        'traceId' => 't_php_bn_offline',
        'username' => 'player_offline',
        'currency' => null,
        'reason' => null,
    ]);
    assertEq($bnOffline['traceId'], 't_php_bn_offline', 'v16:bnOfflineTrace');
    assertEq($bnOffline['data'], [
        'username' => 'player_offline',
        'currency' => null,
        'notified' => false,
        'activeSessions' => 0,
        'serverTime' => 1763612000123,
    ], 'v16:bnOffline');

    $expectInvalidArg(static fn() => $v16Client->notifyPlayerBalance([]), 'v16:bnEmpty');
    $expectInvalidArg(static fn() => $v16Client->notifyPlayerBalance(['username' => '   ']), 'v16:bnBlank');
    $expectInvalidArg(static fn() => $v16Client->notifyPlayerBalance(['username' => ['bad']]), 'v16:bnArrayUser');

    // 9b. getGameCcu: aggregate & tableId filter
    $ccuAgg = $v16Client->getGameCcu();
    assertEq((bool) preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', (string) $ccuAgg['traceId']), true, 'v16:ccuAutoTrace');
    assertEq($ccuAgg['data']['operatorId'], 'OP_DEMO', 'v16:ccuOpId');
    assertEq($ccuAgg['data']['onlinePlayers'], 15, 'v16:ccuOnline');
    assertEq($ccuAgg['data']['seatedPlayers'], 11, 'v16:ccuSeated');
    assertEq($ccuAgg['data']['lobbyPlayers'], 4, 'v16:ccuLobby');
    assertEq(count($ccuAgg['data']['tables']), 2, 'v16:ccuTablesLen');
    assertEq($ccuAgg['data']['serverTime'], 1763612000456, 'v16:ccuServerTime');

    $ccuTbl = $v16Client->getGameCcu(['traceId' => 't_php_ccu_t2', 'tableId' => 'T-A2']);
    assertEq($ccuTbl['traceId'], 't_php_ccu_t2', 'v16:ccuTblTrace');
    assertEq($ccuTbl['data']['onlinePlayers'], 7, 'v16:ccuTblOnline');
    assertEq($ccuTbl['data']['seatedPlayers'], 7, 'v16:ccuTblSeated');
    assertEq($ccuTbl['data']['lobbyPlayers'], 0, 'v16:ccuTblLobby');
    assertEq($ccuTbl['data']['tables'], [['tableId' => 'T-A2', 'gameCode' => 'BACCARAT:T-A2', 'playerCount' => 7]], 'v16:ccuTblRows');

    // 9c. getWalletTransactionStatus pagination (pageNo/pageSize + total/hasMore) & backward compatibility
    $wtsDef = $v16Client->getWalletTransactionStatus(['username' => 'player_online', 'fromTime' => 0, 'toTime' => 86400000]);
    assertEq(count($wtsDef['data']['transactions']), 3, 'v16:wtsDefCount');
    assertEq($wtsDef['data']['pageNo'], 1, 'v16:wtsDefPageNo');
    assertEq($wtsDef['data']['pageSize'], 200, 'v16:wtsDefPageSize');
    assertEq($wtsDef['data']['total'], 3, 'v16:wtsDefTotal');
    assertEq($wtsDef['data']['hasMore'], false, 'v16:wtsDefHasMore');
    assertEq(array_key_exists('pageNo', $v16Captured[count($v16Captured) - 1]['body']), false, 'v16:wtsDefNoPageNoSent');
    assertEq(array_key_exists('pageSize', $v16Captured[count($v16Captured) - 1]['body']), false, 'v16:wtsDefNoPageSizeSent');

    $wtsP1 = $v16Client->getWalletTransactionStatus([
        'username' => 'player_online',
        'fromTime' => 0,
        'toTime' => 86400000,
        'pageNo' => 1,
        'pageSize' => 2,
    ]);
    assertEq(count($wtsP1['data']['transactions']), 2, 'v16:wtsP1Count');
    assertEq($wtsP1['data']['pageNo'], 1, 'v16:wtsP1PageNo');
    assertEq($wtsP1['data']['pageSize'], 2, 'v16:wtsP1PageSize');
    assertEq($wtsP1['data']['total'], 3, 'v16:wtsP1Total');
    assertEq($wtsP1['data']['hasMore'], true, 'v16:wtsP1HasMore');

    $wtsP2 = $v16Client->getWalletTransactionStatus([
        'username' => 'player_online',
        'fromTime' => 0,
        'toTime' => 86400000,
        'pageNo' => 2,
        'pageSize' => 2,
    ]);
    assertEq(count($wtsP2['data']['transactions']), 1, 'v16:wtsP2Count');
    assertEq($wtsP2['data']['pageNo'], 2, 'v16:wtsP2PageNo');
    assertEq($wtsP2['data']['pageSize'], 2, 'v16:wtsP2PageSize');
    assertEq($wtsP2['data']['total'], 3, 'v16:wtsP2Total');
    assertEq($wtsP2['data']['hasMore'], false, 'v16:wtsP2HasMore');

    $expectInvalidArg(static fn() => $v16Client->getWalletTransactionStatus(['transactionId' => 'bet_1', 'pageNo' => 0]), 'v16:wtsPageNo0');
    $expectInvalidArg(static fn() => $v16Client->getWalletTransactionStatus(['transactionId' => 'bet_1', 'pageNo' => -1]), 'v16:wtsPageNoNeg');
    $expectInvalidArg(static fn() => $v16Client->getWalletTransactionStatus(['transactionId' => 'bet_1', 'pageNo' => '1']), 'v16:wtsPageNoStr');
    $expectInvalidArg(static fn() => $v16Client->getWalletTransactionStatus(['transactionId' => 'bet_1', 'pageSize' => 0]), 'v16:wtsPageSize0');
    $expectInvalidArg(static fn() => $v16Client->getWalletTransactionStatus(['transactionId' => 'bet_1', 'pageSize' => 201]), 'v16:wtsPageSize201');
    $expectInvalidArg(static fn() => $v16Client->getWalletTransactionStatus(['transactionId' => 'bet_1', 'pageSize' => '10']), 'v16:wtsPageSizeStr');

    // 9d. /wallet/bet_result with deterministic isEndRound (0 on non-last, 1 on last) + outbound X-Timestamp header
    $v16Tok = 'b2bt_v16_multi_ticket_token_0123456789abcdef01234567';
    $v16Wallet = new InMemoryWallet(['player_v16' => ['currency' => 'USD', 'balance' => '1000.00', 'exponent' => 2, 'tokens' => [$v16Tok]]]);
    $v16Disp = WebhookDispatcher::fromCredentials($apiKey, $secret, $v16Wallet);
    $v16SeenTs = [];
    $sendWithTs = static function (string $route, array $obj, string $xTimestamp) use ($v16Disp, $apiKey, $secret, &$v16SeenTs): array {
        $raw = json_encode($obj, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        // Simulate PHP-FPM $_SERVER headers with outbound X-Timestamp present; X-Signature remains strictly over raw body bytes only
        $httpHeaders = [
            'HTTP_X_API_KEY' => $apiKey,
            'HTTP_X_SIGNATURE' => Signing::signBody($raw, $secret),
            'HTTP_X_TIMESTAMP' => $xTimestamp,
        ];
        $v16SeenTs[] = $httpHeaders['HTTP_X_TIMESTAMP'];
        $out = $v16Disp->handle($route, $httpHeaders['HTTP_X_API_KEY'], $httpHeaders['HTTP_X_SIGNATURE'], $raw);
        assertEq($out['statusCode'], 200, 'v16:whHttp200:' . $route);
        return $out['body'];
    };

    $roundId = 'rnd_v16_php_1';
    $rb1 = $sendWithTs('/wallet/bet', [
        'traceId' => 't_php_v16_b1',
        'transactionId' => 'bet_php_v16_1',
        'betId' => 'tkt_php_v16_1',
        'externalTransactionId' => 'tkt_php_v16_1',
        'roundId' => $roundId,
        'username' => 'player_v16',
        'currency' => 'USD',
        'gameCode' => 'BACCARAT:T-A2',
        'amount' => '100.00',
        'token' => $v16Tok,
    ], '1763612001000');
    assertEq($rb1['status'], StatusCode::SC_OK, 'v16:whBet1Status');
    assertEq($rb1['data']['balance'], '900.00', 'v16:whBet1Bal');

    $rb2 = $sendWithTs('/wallet/bet', [
        'traceId' => 't_php_v16_b2',
        'transactionId' => 'bet_php_v16_2',
        'betId' => 'tkt_php_v16_2',
        'externalTransactionId' => 'tkt_php_v16_2',
        'roundId' => $roundId,
        'username' => 'player_v16',
        'currency' => 'USD',
        'gameCode' => 'BACCARAT:T-A2',
        'amount' => '50.00',
        'token' => $v16Tok,
    ], '1763612001100');
    assertEq($rb2['status'], StatusCode::SC_OK, 'v16:whBet2Status');
    assertEq($rb2['data']['balance'], '850.00', 'v16:whBet2Bal');

    // Ticket 1 (non-last): isEndRound: 0
    $stl1 = [
        'traceId' => 't_php_v16_s1',
        'transactionId' => 'stl_php_v16_1',
        'betId' => 'tkt_php_v16_1',
        'externalTransactionId' => 'tkt_php_v16_1',
        'roundId' => $roundId,
        'username' => 'player_v16',
        'currency' => 'USD',
        'gameCode' => 'BACCARAT:T-A2',
        'betAmount' => '100.00',
        'winAmount' => '200.00',
        'effectiveTurnover' => '100.00',
        'winLoss' => '100.00',
        'jackpotAmount' => '0.00',
        'resultType' => 'WIN',
        'isFreespin' => 0,
        'isEndRound' => 0,
        'betTime' => 1763612001000,
    ];
    $rs1 = $sendWithTs('/wallet/bet_result', $stl1, '1763612005000');
    assertEq($rs1['status'], StatusCode::SC_OK, 'v16:whStl1Status');
    assertEq($rs1['data']['balance'], '1050.00', 'v16:whStl1Bal');

    // Replay with different X-Timestamp and traceId still passes raw-body signature & idempotency
    $rs1Replay = $sendWithTs('/wallet/bet_result', array_merge($stl1, ['traceId' => 't_php_v16_s1_retry']), '1763612009999');
    assertEq($rs1Replay['status'], StatusCode::SC_OK, 'v16:whStl1ReplayStatus');
    assertEq($rs1Replay['data']['balance'], '1050.00', 'v16:whStl1ReplayBal');

    // Flipping isEndRound 0 -> 1 on same transactionId triggers SC_TRANSACTION_DUPLICATED
    assertEq(Idempotency::betResultFingerprint($stl1) !== Idempotency::betResultFingerprint(array_merge($stl1, ['isEndRound' => 1])), true, 'v16:fpIsEndRoundDistinct');
    $rs1Conf = $sendWithTs('/wallet/bet_result', array_merge($stl1, ['traceId' => 't_php_v16_s1_conf', 'isEndRound' => 1]), '1763612010500');
    assertEq($rs1Conf['status'], StatusCode::SC_TRANSACTION_DUPLICATED, 'v16:whStl1Conflict');

    // Ticket 2 (last non-REJECTED in same round): isEndRound: 1
    $rs2 = $sendWithTs('/wallet/bet_result', [
        'traceId' => 't_php_v16_s2',
        'transactionId' => 'stl_php_v16_2',
        'betId' => 'tkt_php_v16_2',
        'externalTransactionId' => 'tkt_php_v16_2',
        'roundId' => $roundId,
        'username' => 'player_v16',
        'currency' => 'USD',
        'gameCode' => 'BACCARAT:T-A2',
        'betAmount' => '50.00',
        'winAmount' => '0.00',
        'effectiveTurnover' => '50.00',
        'winLoss' => '-50.00',
        'jackpotAmount' => '0.00',
        'resultType' => 'LOSE',
        'isFreespin' => 0,
        'isEndRound' => 1,
        'betTime' => 1763612001100,
    ], '1763612012000');
    assertEq($rs2['status'], StatusCode::SC_OK, 'v16:whStl2Status');
    assertEq($rs2['data']['balance'], '1050.00', 'v16:whStl2Bal');

    assertEq(count($v16SeenTs), 6, 'v16:seenTsCount');
    foreach ($v16SeenTs as $idx => $ts) {
        assertEq((bool) preg_match('/^\d{13}$/', $ts), true, 'v16:seenTsFormat:' . $idx);
    }
} finally {
    restore_error_handler();
}

echo "PHP SDK: ALL TESTS PASSED\n";

// SPDX-License-Identifier: MIT
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  BaccaratApiError,
  BaccaratSdkError,
  BaccaratTransportError,
  Client,
  Config,
  Environment,
  InMemoryWallet,
  StatusCode,
  WebhookDispatcher,
  adjustmentFingerprint,
  betFingerprint,
  betResultFingerprint,
  decimalToLedgerUnits,
  isRetryableStatus,
  ledgerUnitsToDecimal,
  rollbackFingerprint,
  signBody,
  verifySignature,
  verifyWebhookHeaders,
  walletError,
  walletOk,
} from '../src/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VECTORS = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../test-vectors.json'), 'utf8'));

test('cross-language HMAC-SHA256 & header verification vectors', () => {
  for (const v of VECTORS.hmacVectors) {
    assert.equal(Buffer.byteLength(v.rawBody, 'utf8'), v.utf8ByteLength);
    assert.equal(signBody(v.rawBody, v.secret), v.signature, `signBody failed for ${v.name}`);
    assert.equal(verifySignature(v.rawBody, v.signature, v.secret), true, `verifySignature failed for ${v.name}`);
    if (v.wrongBase64DecodedSignature) {
      assert.equal(verifySignature(v.rawBody, v.wrongBase64DecodedSignature, v.secret), false);
    }
  }

  for (const h of VECTORS.headerVerificationVectors) {
    const actual = verifyWebhookHeaders(h.apiKeyHeader, h.signatureHeader, h.rawBody, h.expectedApiKey, h.hmacSecret);
    assert.equal(actual, h.expectedStatus, `Header vector ${h.name} mismatch`);
  }
});

test('cross-language retry-safe idempotency fingerprints', () => {
  const { bet, betResult, rollback } = VECTORS.idempotencyVectors;
  assert.equal(betFingerprint(bet.initial), bet.expectedFingerprint);
  assert.equal(betFingerprint(bet.retrySameBusiness), bet.expectedFingerprint);
  assert.equal(betFingerprint(bet.conflictDifferentAmount), bet.conflictFingerprint);

  assert.equal(betResultFingerprint(betResult.initial), betResult.expectedFingerprint);
  assert.equal(betResultFingerprint(betResult.retrySameBusiness), betResult.expectedFingerprint);
  assert.equal(betResultFingerprint(betResult.conflictDifferentWinAmount), betResult.conflictFingerprint);

  assert.equal(rollbackFingerprint(rollback.initial), rollback.expectedFingerprint);
  assert.equal(rollbackFingerprint(rollback.retrySameBusiness), rollback.expectedFingerprint);
  assert.equal(rollbackFingerprint(rollback.conflictDifferentAmount), rollback.conflictFingerprint);

  const { adjustment } = VECTORS.idempotencyVectors;
  assert.equal(adjustmentFingerprint(adjustment.initial), adjustment.expectedFingerprint);
  assert.equal(adjustmentFingerprint(adjustment.retrySameBusiness), adjustment.expectedFingerprint);
  assert.equal(adjustmentFingerprint(adjustment.conflictDifferentDirection), adjustment.conflictFingerprint);
});

test('cross-language exact decimal & ledger unit vectors', () => {
  for (const m of VECTORS.moneyVectors.valid) {
    const units = decimalToLedgerUnits(m.raw, m.displayExponent, { allowNegative: m.allowNegative });
    assert.equal(units.toString(), m.expectedUnits, `units mismatch on ${m.name}`);
    assert.equal(ledgerUnitsToDecimal(units, m.displayExponent), m.expectedFormatted, `format mismatch on ${m.name}`);
  }
  for (const inv of VECTORS.moneyVectors.invalid) {
    assert.throws(
      () => decimalToLedgerUnits(inv.raw, inv.displayExponent, { allowNegative: inv.allowNegative }),
      BaccaratSdkError,
      `Expected ${inv.name} to fail`,
    );
  }
  for (const sc of VECTORS.statusCodes) {
    assert.equal(isRetryableStatus(sc.code), sc.retryable, `retryable mismatch on ${sc.code}`);
  }
});

test('Config guards PRODUCTION missing baseUrl and trims trailing slashes', () => {
  assert.throws(() => new Config({ apiKey: 'ak_1', hmacSecret: 'sec' }), BaccaratSdkError);
  const sb = new Config({ apiKey: 'ak_1', hmacSecret: 'sec', environment: Environment.SANDBOX });
  assert.equal(sb.baseUrl, 'https://api.lt.cniia.cloud');
  const prod = new Config({ apiKey: 'ak_1', hmacSecret: 'sec', baseUrl: 'https://api.example.com///' });
  assert.equal(prod.baseUrl, 'https://api.example.com');
});

test('end-to-end S2S Client over real loopback HTTP server + auto-pagination + error envelopes', async () => {
  const apiKey = 'ak_0123456789abcdef0123456789abcdef';
  const secret = 'dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s';

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const rawBuf = Buffer.concat(chunks);
      const status = verifyWebhookHeaders(req.headers['x-api-key'], req.headers['x-signature'], rawBuf, apiKey, secret);
      const body = JSON.parse(rawBuf.toString('utf8'));
      res.setHeader('Content-Type', 'application/json');
      if (status !== StatusCode.SC_OK) {
        res.end(JSON.stringify({ traceId: body.traceId, status, message: 'Auth failed' }));
        return;
      }
      if (req.url === '/operator/v1/game/tables') {
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { tables: [{ tableId: 'T-A2', currency: 'USD' }], pageNo: 1, pageSize: 50, total: 1 } }));
      } else if (req.url === '/operator/v1/game/url') {
        if (body.currency !== 'USD') {
          res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_WRONG_CURRENCY', message: 'Table requires USD' }));
          return;
        }
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { gameUrl: 'https://play.lt.cniia.cloud/?token=b2bt_' + 'a'.repeat(48), token: 'b2bt_' + 'a'.repeat(48) } }));
      } else if (req.url === '/operator/v1/game/terminate') {
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { username: body.username, terminatedSessions: 1, revokedLaunchTokens: 0 } }));
      } else if (req.url === '/operator/v1/transaction/list') {
        const rows = body.pageNo === 1 ? [{ betId: 'b2btkt1' }, { betId: 'b2btkt2' }] : [{ betId: 'b2btkt3' }];
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { transactions: rows, pageNo: body.pageNo, pageSize: 2, total: 3 } }));
      } else if (req.url === '/operator/v1/transaction/detail') {
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { betId: body.betId, status: 1, roundResult: { outcome: 'PLAYER', playerPoints: 8, bankerPoints: 5, playerPair: false, bankerPair: false, natural: true } } }));
      } else if (req.url === '/operator/v1/ping') {
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { operatorId: 'OP_DEMO', operatorName: 'Demo Operator', callerIp: '127.0.0.1', callbackConfigured: true, serverTime: 1763612000000 } }));
      } else if (req.url === '/operator/v1/player/status') {
        if (body.username === 'locked_user') {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_USER_DISABLED', message: 'PLATFORM_RISK_LOCKED' }));
          return;
        }
        if (body.username === 'capped_user' && body.bettingEnabled === true && body.resetPnlWindow !== true) {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_INVALID_REQUEST', message: 'PNL_CAP_BREACHED_RESET_REQUIRED' }));
          return;
        }
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { username: body.username, status: body.status ?? 'ACTIVE', bettingEnabled: body.bettingEnabled ?? false, rgRestricted: false, statusReason: body.resetPnlWindow ? null : (body.reason ?? null), revokedSessions: 0, revokedLaunchTokens: 0 } }));
      } else if (req.url === '/operator/v1/player/limits') {
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { username: body.username, currency: body.currency, maxBet: body.maxBet } }));
      } else if (req.url === '/operator/v1/transaction/unsettled') {
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { transactions: [], pageNo: 1, pageSize: 200, total: 0 } }));
      } else if (req.url === '/operator/v1/wallet/transaction-status') {
        res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_OK', data: { transactions: [{ transactionId: body.transactionId ?? 'bet_user_1', username: body.username ?? 'player_9527', status: 'COMPLETED' }] } }));
      }
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    const client = new Client({ apiKey, hmacSecret: secret, baseUrl: `http://127.0.0.1:${port}` });

    const tablesRes = await client.listTables({ currency: 'USD' });
    assert.equal(tablesRes.data.tables[0].tableId, 'T-A2');

    const urlRes = await client.createGameUrl({
      username: 'player_9527',
      tableId: 'T-A2',
      platform: 'H5',
      currency: 'USD',
      lobbyUrl: 'https://merchant.example.com/lobby',
      ipAddress: '203.0.113.42',
    });
    assert(urlRes.data.token.startsWith('b2bt_'));

    await assert.rejects(
      () => client.createGameUrl({
        username: 'player_9527',
        tableId: 'T-A2',
        platform: 'H5',
        currency: 'JPY',
        lobbyUrl: 'https://merchant.example.com/lobby',
        ipAddress: '203.0.113.42',
      }),
      (err) => err instanceof BaccaratApiError && err.status === 'SC_WRONG_CURRENCY' && !err.isRetryable(),
    );

    const termRes = await client.terminateSessions({ username: 'player_9527' });
    assert.equal(termRes.data.terminatedSessions, 1);

    const allTx = await client.listAllTransactions({ fromTime: 1000, toTime: 2000, pageSize: 2 });
    assert.equal(allTx.length, 3);

    const detailRes = await client.getTransactionDetail({ betId: 'b2btkt1', fromTime: 1000, toTime: 2000 });
    assert.equal(detailRes.data.roundResult.outcome, 'PLAYER');
    const detailNoWindow = await client.getTransactionDetail({ betId: 'b2btkt1' });
    assert.equal(detailNoWindow.data.betId, 'b2btkt1');

    const pingRes = await client.ping();
    assert.equal(pingRes.data.operatorId, 'OP_DEMO');
    assert.equal(pingRes.data.callbackConfigured, true);
    const psRes = await client.updatePlayerStatus({ username: 'player_9527', bettingEnabled: false });
    assert.equal(psRes.data.bettingEnabled, false);
    const psResetRes = await client.updatePlayerStatus({ username: 'capped_user', action: 'SET', bettingEnabled: true, resetPnlWindow: true });
    assert.equal(psResetRes.data.bettingEnabled, true);
    assert.equal(psResetRes.data.statusReason, null);
    await assert.rejects(
      () => client.updatePlayerStatus({ username: 'locked_user', action: 'SET', status: 'ACTIVE' }),
      (err) => err instanceof BaccaratApiError && err.httpStatus === 403 && err.status === 'SC_USER_DISABLED' && err.message === 'PLATFORM_RISK_LOCKED' && !err.isRetryable(),
    );
    await assert.rejects(
      () => client.updatePlayerStatus({ username: 'capped_user', action: 'SET', bettingEnabled: true }),
      (err) => err instanceof BaccaratApiError && err.httpStatus === 409 && err.status === 'SC_INVALID_REQUEST' && err.message === 'PNL_CAP_BREACHED_RESET_REQUIRED' && !err.isRetryable(),
    );
    const plRes = await client.updatePlayerLimits({ username: 'player_9527', currency: 'USD', maxBet: '500.00' });
    assert.equal(plRes.data.maxBet, '500.00');
    const unRes = await client.listUnsettledTransactions({ username: 'player_9527' });
    assert.equal(unRes.data.total, 0);
    const wtsRes = await client.getWalletTransactionStatus({ transactionId: 'bet_1' });
    assert.equal(wtsRes.data.transactions[0].status, 'COMPLETED');
    const wtsUserRes = await client.getWalletTransactionStatus({ username: 'player_9527', fromTime: 0, toTime: 86_400_000 });
    assert.equal(wtsUserRes.data.transactions[0].username, 'player_9527');
    assert.throws(() => client.getWalletTransactionStatus({}), BaccaratSdkError);
    assert.throws(() => client.getWalletTransactionStatus({ username: 'player_9527' }), BaccaratSdkError);
    assert.throws(() => client.getWalletTransactionStatus({ username: 'player_9527', fromTime: 0, toTime: 86_400_001 }), BaccaratSdkError);
    assert.throws(() => client.getWalletTransactionStatus({ transactionId: 'bet_1', fromTime: 1000 }), BaccaratSdkError);
    assert.throws(() => client.getWalletTransactionStatus({ betId: 'b2btkt1', fromTime: 2000, toTime: 1000 }), BaccaratSdkError);
    assert.throws(() => client.getWalletTransactionStatus({ transactionId: 'bet_1', fromTime: null }), BaccaratSdkError);

    assert.throws(() => client.getTransactionDetail({ betId: 'b2btkt1', fromTime: 0, toTime: 604_800_001 }), BaccaratSdkError);
    assert.throws(() => client.getTransactionDetail({ betId: 'b2btkt1', fromTime: null }), BaccaratSdkError);
    assert.throws(() => client.listUnsettledTransactions({ fromTime: null }), BaccaratSdkError);
    assert.throws(() => client.listTransactions({ fromTime: 0, toTime: 8_640_000_000_000_001 }), BaccaratSdkError);
  } finally {
    server.close();
  }
});

test('WebhookDispatcher & InMemoryWallet full seamless wallet lifecycle', async () => {
  const apiKey = 'ak_0123456789abcdef0123456789abcdef';
  const secret = 'dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s';
  const token = 'b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819';

  const wallet = new InMemoryWallet({
    player_9527: { currency: 'USD', balance: '1000.00', exponent: 2, tokens: [token] },
  });
  const dispatcher = new WebhookDispatcher({ apiKey, hmacSecret: secret, environment: Environment.SANDBOX }, wallet);

  const send = (route, obj) => {
    const raw = JSON.stringify(obj);
    return dispatcher.handle(route, apiKey, signBody(raw, secret), raw);
  };

  // 1. Balance probe
  const bal = await send('/wallet/balance', { traceId: 't1', username: 'player_9527', currency: 'USD', token });
  assert.equal(bal.body.status, 'SC_OK');
  assert.equal(bal.body.data.balance, '1000.00');

  // 2. Bet debit + retry with mutated traceId/timestamp + conflict with different amount
  const betReq = VECTORS.idempotencyVectors.bet.initial;
  const bet1 = await send('/wallet/bet', betReq);
  assert.equal(bet1.body.status, 'SC_OK');
  assert.equal(bet1.body.data.balance, '900.00');

  const betReplay = await send('/wallet/bet', VECTORS.idempotencyVectors.bet.retrySameBusiness);
  assert.equal(betReplay.body.status, 'SC_OK');
  assert.equal(betReplay.body.data.balance, '900.00');

  const betConf = await send('/wallet/bet', VECTORS.idempotencyVectors.bet.conflictDifferentAmount);
  assert.equal(betConf.body.status, 'SC_TRANSACTION_DUPLICATED');

  // 3. Even if player account is disabled mid-round, already-deducted bet_result MUST settle!
  wallet.setDisabled('player_9527', true);
  const stl1 = await send('/wallet/bet_result', VECTORS.idempotencyVectors.betResult.initial);
  assert.equal(stl1.body.status, 'SC_OK');
  assert.equal(stl1.body.data.balance, '1100.00');

  const stlReplay = await send('/wallet/bet_result', VECTORS.idempotencyVectors.betResult.retrySameBusiness);
  assert.equal(stlReplay.body.status, 'SC_OK');
  assert.equal(stlReplay.body.data.balance, '1100.00');

  // 3b. Post-settlement adjustment (/wallet/adjustment): CREDIT + replay + conflict + DEBIT insufficient + DEBIT ok
  const adj1 = await send('/wallet/adjustment', VECTORS.idempotencyVectors.adjustment.initial);
  assert.equal(adj1.body.status, 'SC_OK');
  assert.equal(adj1.body.data.balance, '1120.00');
  const adjReplay = await send('/wallet/adjustment', VECTORS.idempotencyVectors.adjustment.retrySameBusiness);
  assert.equal(adjReplay.body.status, 'SC_OK');
  assert.equal(adjReplay.body.data.balance, '1120.00');
  const adjConf = await send('/wallet/adjustment', VECTORS.idempotencyVectors.adjustment.conflictDifferentDirection);
  assert.equal(adjConf.body.status, 'SC_TRANSACTION_DUPLICATED');
  const adjDebitOver = await send('/wallet/adjustment', {
    ...VECTORS.idempotencyVectors.adjustment.initial,
    transactionId: 'adj_debit_over',
    direction: 'DEBIT',
    amount: '5000.00',
  });
  assert.equal(adjDebitOver.body.status, 'SC_INSUFFICIENT_FUNDS');
  const adjDebitOk = await send('/wallet/adjustment', {
    ...VECTORS.idempotencyVectors.adjustment.initial,
    transactionId: 'adj_debit_20',
    direction: 'DEBIT',
    amount: '20.00',
  });
  assert.equal(adjDebitOk.body.status, 'SC_OK');
  assert.equal(adjDebitOk.body.data.balance, '1100.00');

  // 4. Rollback on never-deducted betId -> SC_TRANSACTION_NOT_EXISTS empty-success
  const unknownRb = {
    ...VECTORS.idempotencyVectors.rollback.initial,
    transactionId: 'rb_b2btkt000000000000000000000000',
    betId: 'b2btkt000000000000000000000000',
    externalTransactionId: 'b2btkt000000000000000000000000',
  };
  const rbEmpty = await send('/wallet/rollback', unknownRb);
  assert.equal(rbEmpty.body.status, 'SC_TRANSACTION_NOT_EXISTS');

  // 5. CR-03: Rollback after already-settled betId must be rejected as SC_TRANSACTION_DUPLICATED (no double credit!)
  const rbAfterSettle = await send('/wallet/rollback', VECTORS.idempotencyVectors.rollback.initial);
  assert.equal(rbAfterSettle.body.status, 'SC_TRANSACTION_DUPLICATED');
  assert.equal((await send('/wallet/bet_result', VECTORS.idempotencyVectors.betResult.retrySameBusiness)).body.data.balance, '1100.00');

  // 6. CR-03: Zero-stake bet rejected + settle after rollback rejected
  wallet.setDisabled('player_9527', false);
  const zeroBet = await send('/wallet/bet', { ...betReq, transactionId: 'bet_zero_1', betId: 'b2btkt_zero', externalTransactionId: 'b2btkt_zero', amount: '0.00' });
  assert.equal(zeroBet.body.status, 'SC_INVALID_REQUEST');

  const bet2 = await send('/wallet/bet', { ...betReq, transactionId: 'bet_2', betId: 'b2btkt_2', externalTransactionId: 'b2btkt_2', amount: '50.00' });
  assert.equal(bet2.body.data.balance, '1050.00');
  const rb2 = await send('/wallet/rollback', { ...VECTORS.idempotencyVectors.rollback.initial, transactionId: 'rb_2', betId: 'b2btkt_2', externalTransactionId: 'b2btkt_2', amount: '50.00' });
  assert.equal(rb2.body.status, 'SC_OK');
  assert.equal(rb2.body.data.balance, '1100.00');
  const settleAfterRb = await send('/wallet/bet_result', { ...VECTORS.idempotencyVectors.betResult.initial, transactionId: 'stl_2', betId: 'b2btkt_2', externalTransactionId: 'b2btkt_2', betAmount: '50.00', winAmount: '100.00' });
  assert.equal(settleAfterRb.body.status, 'SC_TRANSACTION_DUPLICATED');

  // 7. CR-01 & CR-04: Pre-auth oversized/unauthenticated payload rejected before parse; traceId: undefined/null generates UUID
  const unauthDeep = await dispatcher.handle('/wallet/bet', 'wrong', 'bad', '['.repeat(50_000));
  assert.equal(unauthDeep.body.status, 'SC_AUTHENTICATION_FAILED');
  const capturedTraces = [];
  const mockClient = new Client(
    { apiKey, hmacSecret: secret, environment: Environment.SANDBOX },
    {
      transport: async (_url, _headers, rawBuf) => {
        const p = JSON.parse(rawBuf.toString('utf8'));
        capturedTraces.push(p.traceId);
        return { httpStatus: 200, rawBody: JSON.stringify({ traceId: p.traceId, status: 'SC_OK', data: {} }) };
      },
    },
  );
  await mockClient.listTables({ traceId: undefined });
  await mockClient.listTables({ traceId: null });
  for (const tid of capturedTraces) {
    assert.match(tid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  }

  // 8. Regressions: sendTimestamp X-Timestamp, non-JSON 429 -> SC_RATE_LIMITED, listAllTransactions backoff + traceId stripping,
  //    JSON missing/empty status fallback (M1), no-arg listAllTransactions (M2), webhook-only PRODUCTION without baseUrl, and plain-object rawBody rejection
  const capturedHeaders = [];
  const capturedListTraces = [];
  let page1Calls = 0;
  const tsClient = new Client(
    { apiKey, hmacSecret: secret, environment: Environment.SANDBOX, sendTimestamp: true },
    {
      transport: async (url, headers, rawBuf) => {
        capturedHeaders.push(headers);
        const p = JSON.parse(rawBuf.toString('utf8'));
        if (url.endsWith('/operator/v1/ping')) {
          if (p.traceId === 'm1_json_429') {
            return { httpStatus: 429, rawBody: JSON.stringify({ statusCode: 429, message: 'Too Many Requests' }) };
          }
          if (p.traceId === 'm1_json_503') {
            return { httpStatus: 503, rawBody: JSON.stringify({ error: 'unavailable' }) };
          }
          if (p.traceId === 'm1_empty_429') {
            return { httpStatus: 429, rawBody: JSON.stringify({ status: '', message: 'Empty status' }) };
          }
          return { httpStatus: 429, rawBody: 'Too Many Requests' };
        }
        capturedListTraces.push(p.traceId);
        if (p.pageNo === 1 && page1Calls === 0) {
          page1Calls += 1;
          return { httpStatus: 200, rawBody: JSON.stringify({ traceId: p.traceId, status: 'SC_RATE_LIMITED', message: 'slow down' }) };
        }
        const rows = p.pageNo === 1 ? [{ betId: 'b1' }, { betId: 'b2' }] : [{ betId: 'b3' }];
        return { httpStatus: 200, rawBody: JSON.stringify({ traceId: p.traceId, status: 'SC_OK', data: { transactions: rows, pageNo: p.pageNo, pageSize: 2, total: 3 } }) };
      },
    },
  );
  await assert.rejects(
    () => tsClient.ping(),
    (err) => err instanceof BaccaratApiError && err.httpStatus === 429 && err.status === StatusCode.SC_RATE_LIMITED && err.isRetryable(),
  );
  assert.match(capturedHeaders[0]['X-Timestamp'], /^\d{13}$/);

  await assert.rejects(
    () => tsClient.ping({ traceId: 'm1_json_429' }),
    (err) => err instanceof BaccaratApiError && err.httpStatus === 429 && err.status === StatusCode.SC_RATE_LIMITED && err.isRetryable(),
  );
  await assert.rejects(
    () => tsClient.ping({ traceId: 'm1_json_503' }),
    (err) => err instanceof BaccaratApiError && err.httpStatus === 503 && err.status === StatusCode.SC_OPERATOR_TIMEOUT && err.isRetryable(),
  );
  await assert.rejects(
    () => tsClient.ping({ traceId: 'm1_empty_429' }),
    (err) => err instanceof BaccaratApiError && err.httpStatus === 429 && err.status === StatusCode.SC_RATE_LIMITED && err.isRetryable(),
  );

  // M2: calling listAllTransactions with no args rejects with BaccaratSdkError (not TypeError)
  await assert.rejects(() => tsClient.listAllTransactions(), (err) => err instanceof BaccaratSdkError && err.code === 'INVALID_ARGUMENT');

  // m1: caller-supplied traceId is stripped so every page & retry attempt gets a fresh unique UUID
  const retriedRows = await tsClient.listAllTransactions({
    fromTime: 1000,
    toTime: 2000,
    pageSize: 2,
    username: 'player_9527',
    traceId: 'caller-fixed-trace',
    rateLimitBackoffMs: 0,
  });
  assert.equal(retriedRows.length, 3);
  assert.equal(page1Calls, 1);
  assert.equal(capturedListTraces.length, 3);
  assert.equal(new Set(capturedListTraces).size, 3);
  assert(!capturedListTraces.includes('caller-fixed-trace'));

  const prodWebhookOnly = new WebhookDispatcher({ apiKey, hmacSecret: secret }, wallet);
  const parsedObjRes = await prodWebhookOnly.handle('/wallet/bet', apiKey, '0'.repeat(64), { traceId: 't_obj', amount: '10.00' });
  assert.equal(parsedObjRes.body.status, StatusCode.SC_INVALID_REQUEST);
  assert.equal(parsedObjRes.body.traceId, 't_obj');

  // M2 & P2-4: real HTTP transport total-deadline timeout, mid-body TCP reset -> BaccaratTransportError,
  // and >16 MiB response body -> BaccaratApiError(SC_INVALID_REQUEST, httpStatus, traceId)
  const edgeSrv = http.createServer((req, res) => {
    req.resume();
    if (req.url === '/operator/v1/ping') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.write('{"partial":');
      const iv = setInterval(() => {
        if (!res.destroyed) res.write(' ');
      }, 30);
      res.on('close', () => clearInterval(iv));
      return;
    }
    if (req.url === '/operator/v1/game/terminate') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      const chunk = Buffer.alloc(65536, 0x61);
      let remaining = 260;
      const writeMore = () => {
        while (remaining > 0 && !res.destroyed) {
          remaining -= 1;
          if (!res.write(chunk)) {
            res.once('drain', writeMore);
            return;
          }
        }
        if (!res.destroyed) res.end();
      };
      writeMore();
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': '1024' });
    res.write('{"partial":');
    setTimeout(() => req.socket.destroy(), 15);
  });
  await new Promise((resolve) => edgeSrv.listen(0, '127.0.0.1', resolve));
  try {
    const edgePort = edgeSrv.address().port;
    const deadlineClient = new Client({ apiKey, hmacSecret: secret, baseUrl: `http://127.0.0.1:${edgePort}`, timeoutMs: 120 });
    await assert.rejects(
      () => deadlineClient.ping(),
      (err) => err instanceof BaccaratTransportError && err instanceof BaccaratSdkError && err.code === StatusCode.SC_OPERATOR_TIMEOUT,
    );
    const resetClient = new Client({ apiKey, hmacSecret: secret, baseUrl: `http://127.0.0.1:${edgePort}`, timeoutMs: 2000 });
    await assert.rejects(
      () => resetClient.listTables(),
      (err) => err instanceof BaccaratTransportError && err instanceof BaccaratSdkError && err.code === StatusCode.SC_OPERATOR_TIMEOUT,
    );
    await assert.rejects(
      () => resetClient.terminateSessions({ traceId: 't_node_overflow' }),
      (err) =>
        err instanceof BaccaratApiError &&
        err.status === StatusCode.SC_INVALID_REQUEST &&
        err.httpStatus === 200 &&
        err.traceId === 't_node_overflow' &&
        !err.isRetryable(),
    );
  } finally {
    edgeSrv.close();
  }
});

test('v1.5.11 regressions: deadlock, S2S ApiError/TransportError/overflow & allowlist SdkError safety, wallet response builders, toScalarString & strict UTF-8', async () => {
  const apiKey = 'ak_0123456789abcdef0123456789abcdef';
  const secret = 'dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s';
  const deadlockWallet = {
    onBalance() { throw new BaccaratSdkError('explicit validation', StatusCode.SC_INSUFFICIENT_FUNDS); },
    onBet(req) {
      decimalToLedgerUnits(String(req.amount ?? 'bad_amt'), 2);
      return walletOk(String(req.traceId ?? ''), 'p1', 'USD', '100.00');
    },
    onBetResult(req) {
      if (req.mode === 'bad_balance') {
        return walletOk(String(req.traceId ?? ''), 'p1', 'USD', '-1.00');
      }
      if (req.mode === 'nan_balance') {
        return walletOk(String(req.traceId ?? ''), 'p1', 'USD', 'NaN');
      }
      if (req.mode === 's2s_api_err') {
        throw new BaccaratApiError({
          traceId: 't_upstream_s2s',
          status: StatusCode.SC_INVALID_REQUEST,
          message: 'upstream S2S failure secret detail',
          httpStatus: 400,
        });
      }
      if (req.mode === 's2s_overflow_err') {
        throw new BaccaratApiError({
          traceId: 't_upstream_overflow',
          status: StatusCode.SC_INVALID_REQUEST,
          message: 'Gateway response exceeded 16 MiB limit',
          httpStatus: 200,
        });
      }
      if (req.mode === 's2s_transport_err') {
        throw new BaccaratTransportError('curl failed: 10.0.1.5:8443 proxy refused');
      }
      if (req.mode === 'sdk_sc_ok') {
        throw new BaccaratSdkError('bogus SC_OK error', StatusCode.SC_OK);
      }
      if (req.mode === 'sdk_sc_custom') {
        throw new BaccaratSdkError('bogus custom error', 'SC_CUSTOM');
      }
      if (req.mode === 'sdk_sc_prefix') {
        throw new BaccaratSdkError('bogus prefix error', 'SC_');
      }
      throw new Error('ERROR: deadlock detected (40P01) on table wallets');
    },
    onRollback() { return walletOk('t_rb', 'p1', 'USD', '100.00', 1700000000000); },
  };
  const disp = new WebhookDispatcher({ apiKey, hmacSecret: secret }, deadlockWallet);

  const settleRaw = Buffer.from(JSON.stringify({ traceId: 't_deadlock', transactionId: 'stl_1', betId: 'b1' }), 'utf8');
  const settleRes = await disp.handle('/wallet/bet_result', apiKey, signBody(settleRaw, secret), settleRaw);
  assert.equal(settleRes.statusCode, 200);
  assert.equal(settleRes.body.traceId, 't_deadlock');
  assert.equal(settleRes.body.status, StatusCode.SC_OPERATOR_TIMEOUT);
  assert.equal(settleRes.body.message, 'Temporary wallet handler error');
  assert.ok(!String(settleRes.body.message).includes('40P01'));
  assert.ok(!String(settleRes.body.message).includes('deadlock'));

  for (const mode of ['bad_balance', 'nan_balance', 's2s_api_err', 's2s_overflow_err', 's2s_transport_err', 'sdk_sc_ok', 'sdk_sc_custom', 'sdk_sc_prefix']) {
    const badBalRaw = Buffer.from(JSON.stringify({ traceId: `t_${mode}`, transactionId: 'stl_bad', mode }), 'utf8');
    const badBalRes = await disp.handle('/wallet/bet_result', apiKey, signBody(badBalRaw, secret), badBalRaw);
    assert.equal(badBalRes.statusCode, 200);
    assert.equal(badBalRes.body.traceId, `t_${mode}`);
    assert.equal(badBalRes.body.status, StatusCode.SC_OPERATOR_TIMEOUT);
    assert.equal(badBalRes.body.message, 'Temporary wallet handler error');
    assert.ok(!String(badBalRes.body.message).includes('walletOk'));
    assert.ok(!String(badBalRes.body.message).includes('INVALID_ARGUMENT'));
    assert.ok(!String(badBalRes.body.message).includes('upstream'));
    assert.ok(!String(badBalRes.body.message).includes('10.0.1.5'));
    assert.ok(!String(badBalRes.body.message).includes('proxy'));
    assert.ok(!String(badBalRes.body.message).includes('16 MiB'));
    assert.ok(!String(badBalRes.body.message).includes('bogus'));
  }

  for (const badAmt of ['not_a_number', '1.123456', '-5.00']) {
    const badDecRaw = Buffer.from(JSON.stringify({ traceId: 't_bad_dec', amount: badAmt }), 'utf8');
    const badDecRes = await disp.handle('/wallet/bet', apiKey, signBody(badDecRaw, secret), badDecRaw);
    assert.equal(badDecRes.statusCode, 200);
    assert.equal(badDecRes.body.traceId, 't_bad_dec');
    assert.equal(badDecRes.body.status, StatusCode.SC_INVALID_REQUEST);
  }

  const sdkErrRaw = Buffer.from(JSON.stringify({ traceId: 't_sdkerr' }), 'utf8');
  const sdkErrRes = await disp.handle('/wallet/balance', apiKey, signBody(sdkErrRaw, secret), sdkErrRaw);
  assert.equal(sdkErrRes.statusCode, 200);
  assert.equal(sdkErrRes.body.status, StatusCode.SC_INSUFFICIENT_FUNDS);

  const ok = walletOk('t_ok', 'player_1', 'JPY', '5000');
  assert.equal(ok.status, StatusCode.SC_OK);
  assert.equal(ok.data.balance, '5000');
  assert.equal(typeof ok.data.timestamp, 'number');
  const err = walletError('t_err', StatusCode.SC_INSUFFICIENT_FUNDS, 'low balance');
  assert.deepEqual(err, { traceId: 't_err', status: StatusCode.SC_INSUFFICIENT_FUNDS, message: 'low balance' });

  for (const badBal of ['', '   ', '-1.00', 'abc', '10.', '.5', '10.00 ', null, undefined]) {
    assert.throws(
      () => walletOk('t_bad', 'player_1', 'USD', badBal),
      (e) => e instanceof BaccaratSdkError && e.code === 'INVALID_ARGUMENT',
    );
  }
  for (const badStatus of ['', '   ', StatusCode.SC_OK, ' SC_OK ', 'sc_ok', 'Sc_Ok', ' sc_ok ', 'SC_', 'SC_TIMEOUT', 'SC_CUSTOM', 'INSUFFICIENT_FUNDS', null, undefined]) {
    assert.throws(
      () => walletError('t_bad', badStatus, 'oops'),
      (e) => e instanceof BaccaratSdkError && e.code === 'INVALID_ARGUMENT',
    );
  }

  // v1.5.11 P1-3: toScalarString guards against {"toString": 1} objects in fingerprints & Client.postSigned
  const tsWallet = new InMemoryWallet({ alice: { currency: 'USD', balance: '100.00', exponent: 2, tokens: ['tok_ok'] } });
  const tsDisp = new WebhookDispatcher({ apiKey, hmacSecret: secret }, tsWallet);
  const badRoundBet = Buffer.from(JSON.stringify({
    traceId: 't_node_tostr',
    transactionId: 'tx_tostr_1',
    betId: 'bet_tostr_1',
    username: 'alice',
    currency: 'USD',
    amount: '10.00',
    token: 'tok_ok',
    roundId: { toString: 1 },
  }), 'utf8');
  const badRoundRes = await tsDisp.handle('/wallet/bet', apiKey, signBody(badRoundBet, secret), badRoundBet);
  assert.equal(badRoundRes.statusCode, 200);
  assert.equal(badRoundRes.body.status, StatusCode.SC_OK);
  assert.equal(badRoundRes.body.data.balance, '90.00');
  const badRoundReplay = await tsDisp.handle('/wallet/bet', apiKey, signBody(badRoundBet, secret), badRoundBet);
  assert.equal(badRoundReplay.body.status, StatusCode.SC_OK);
  assert.equal(badRoundReplay.body.data.balance, '90.00');

  assert.equal(
    betResultFingerprint({ isFreespin: { toString: 1 }, isEndRound: { toString: 1 }, betTime: { toString: 1 } }),
    betResultFingerprint({}),
  );

  const badMsgClient = new Client(
    { apiKey, hmacSecret: secret, environment: Environment.SANDBOX },
    {
      transport: async () => ({
        httpStatus: 400,
        rawBody: JSON.stringify({ status: StatusCode.SC_INVALID_REQUEST, message: { toString: 1 }, traceId: { toString: 1 } }),
      }),
    },
  );
  await assert.rejects(
    () => badMsgClient.ping({ traceId: 't_node_msg_tostr' }),
    (e) => e instanceof BaccaratApiError
      && e.status === StatusCode.SC_INVALID_REQUEST
      && e.message === 'HTTP 400'
      && e.traceId === 't_node_msg_tostr',
  );

  const badOkTraceClient = new Client(
    { apiKey, hmacSecret: secret, environment: Environment.SANDBOX },
    {
      transport: async () => ({
        httpStatus: 200,
        rawBody: JSON.stringify({ status: StatusCode.SC_OK, traceId: { toString: 1 }, data: { ok: true } }),
      }),
    },
  );
  const okTraceRes = await badOkTraceClient.ping({ traceId: 't_node_ok_tostr' });
  assert.equal(okTraceRes.traceId, 't_node_ok_tostr');

  // v1.5.11 P3-2: strict UTF-8 validation in WebhookDispatcher
  const badUtf8Buf = Buffer.concat([
    Buffer.from('{"traceId":"t1', 'utf8'),
    Buffer.from([0xff]),
    Buffer.from('","username":"alice"}', 'utf8'),
  ]);
  const badUtf8Res = await tsDisp.handle('/wallet/balance', apiKey, signBody(badUtf8Buf, secret), badUtf8Buf);
  assert.equal(badUtf8Res.statusCode, 200);
  assert.equal(badUtf8Res.body.status, StatusCode.SC_INVALID_REQUEST);
  assert.equal(badUtf8Res.body.traceId, '');
});

test('v1.6.0: notifyPlayerBalance, getGameCcu, paginated getWalletTransactionStatus, deterministic isEndRound & outbound X-Timestamp', async () => {
  const apiKey = 'ak_0123456789abcdef0123456789abcdef';
  const secret = 'dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s';
  const capturedBodies = [];

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const rawBuf = Buffer.concat(chunks);
      const status = verifyWebhookHeaders(req.headers['x-api-key'], req.headers['x-signature'], rawBuf, apiKey, secret);
      const body = JSON.parse(rawBuf.toString('utf8'));
      capturedBodies.push({ url: req.url, body });
      res.setHeader('Content-Type', 'application/json');
      if (status !== StatusCode.SC_OK) {
        res.end(JSON.stringify({ traceId: body.traceId, status, message: 'Auth failed' }));
        return;
      }
      if (req.url === '/operator/v1/player/balance-notify') {
        const isOnline = body.username === 'player_online';
        res.end(JSON.stringify({
          traceId: body.traceId,
          status: 'SC_OK',
          data: {
            username: body.username,
            currency: body.currency ?? (isOnline ? 'USD' : null),
            notified: isOnline,
            activeSessions: isOnline ? 2 : 0,
            serverTime: 1763612000123,
          },
        }));
        return;
      }
      if (req.url === '/operator/v1/game/ccu') {
        if (body.tableId === 'T-A2') {
          res.end(JSON.stringify({
            traceId: body.traceId,
            status: 'SC_OK',
            data: {
              operatorId: 'OP_DEMO',
              onlinePlayers: 7,
              seatedPlayers: 7,
              lobbyPlayers: 0,
              tables: [{ tableId: 'T-A2', gameCode: 'BACCARAT:T-A2', playerCount: 7 }],
              serverTime: 1763612000456,
            },
          }));
          return;
        }
        res.end(JSON.stringify({
          traceId: body.traceId,
          status: 'SC_OK',
          data: {
            operatorId: 'OP_DEMO',
            onlinePlayers: 15,
            seatedPlayers: 11,
            lobbyPlayers: 4,
            tables: [
              { tableId: 'T-A2', gameCode: 'BACCARAT:T-A2', playerCount: 7 },
              { tableId: 'T-A3', gameCode: 'BACCARAT:T-A3', playerCount: 4 },
            ],
            serverTime: 1763612000456,
          },
        }));
        return;
      }
      if (req.url === '/operator/v1/wallet/transaction-status') {
        const allRows = [
          { transactionId: 'bet_p1', username: 'player_online', status: 'COMPLETED' },
          { transactionId: 'bet_p2', username: 'player_online', status: 'COMPLETED' },
          { transactionId: 'stl_p3', username: 'player_online', status: 'COMPLETED' },
        ];
        const pageNo = body.pageNo ?? 1;
        const pageSize = body.pageSize ?? 200;
        const start = (pageNo - 1) * pageSize;
        const slice = allRows.slice(start, start + pageSize);
        const hasMore = slice.length > 0 && pageNo * pageSize < allRows.length;
        res.end(JSON.stringify({
          traceId: body.traceId,
          status: 'SC_OK',
          data: {
            transactions: slice,
            pageNo,
            pageSize,
            total: allRows.length,
            hasMore,
          },
        }));
        return;
      }
      res.writeHead(404);
      res.end(JSON.stringify({ traceId: body.traceId, status: 'SC_INVALID_REQUEST', message: 'Not found' }));
    });
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  try {
    const client = new Client({ apiKey, hmacSecret: secret, baseUrl: `http://127.0.0.1:${port}` });

    // 1. notifyPlayerBalance: online (with currency & reason) and offline (omitted / null optional fields)
    const onlineRes = await client.notifyPlayerBalance({
      username: 'player_online',
      currency: 'USD',
      reason: 'DEPOSIT',
    });
    assert.match(onlineRes.traceId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.deepEqual(onlineRes.data, {
      username: 'player_online',
      currency: 'USD',
      notified: true,
      activeSessions: 2,
      serverTime: 1763612000123,
    });
    assert.equal(capturedBodies.at(-1).body.reason, 'DEPOSIT');

    const offlineRes = await client.notifyPlayerBalance({
      traceId: 't_bal_offline',
      username: 'player_offline',
      currency: null,
      reason: null,
    });
    assert.equal(offlineRes.traceId, 't_bal_offline');
    assert.deepEqual(offlineRes.data, {
      username: 'player_offline',
      currency: null,
      notified: false,
      activeSessions: 0,
      serverTime: 1763612000123,
    });

    for (const badParams of [undefined, null, {}, { username: '' }, { username: '   ' }, { username: 123 }]) {
      assert.throws(
        () => client.notifyPlayerBalance(badParams),
        (err) => err instanceof BaccaratSdkError && err.code === 'INVALID_ARGUMENT',
      );
    }

    // 2. getGameCcu: aggregate and tableId filter
    const aggCcu = await client.getGameCcu();
    assert.match(aggCcu.traceId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.equal(aggCcu.data.operatorId, 'OP_DEMO');
    assert.equal(aggCcu.data.onlinePlayers, 15);
    assert.equal(aggCcu.data.seatedPlayers, 11);
    assert.equal(aggCcu.data.lobbyPlayers, 4);
    assert.equal(aggCcu.data.tables.length, 2);
    assert.equal(aggCcu.data.serverTime, 1763612000456);

    const tblCcu = await client.getGameCcu({ traceId: 't_ccu_t2', tableId: 'T-A2' });
    assert.equal(tblCcu.traceId, 't_ccu_t2');
    assert.equal(tblCcu.data.onlinePlayers, 7);
    assert.equal(tblCcu.data.seatedPlayers, 7);
    assert.equal(tblCcu.data.lobbyPlayers, 0);
    assert.deepEqual(tblCcu.data.tables, [{ tableId: 'T-A2', gameCode: 'BACCARAT:T-A2', playerCount: 7 }]);

    // 3. getWalletTransactionStatus pagination (pageNo/pageSize + total/hasMore) & backward compatibility
    const wtsDefault = await client.getWalletTransactionStatus({
      username: 'player_online',
      fromTime: 0,
      toTime: 86_400_000,
    });
    assert.equal(wtsDefault.data.transactions.length, 3);
    assert.equal(wtsDefault.data.pageNo, 1);
    assert.equal(wtsDefault.data.pageSize, 200);
    assert.equal(wtsDefault.data.total, 3);
    assert.equal(wtsDefault.data.hasMore, false);
    assert.equal(Object.prototype.hasOwnProperty.call(capturedBodies.at(-1).body, 'pageNo'), false);
    assert.equal(Object.prototype.hasOwnProperty.call(capturedBodies.at(-1).body, 'pageSize'), false);

    const wtsPage1 = await client.getWalletTransactionStatus({
      username: 'player_online',
      fromTime: 0,
      toTime: 86_400_000,
      pageNo: 1,
      pageSize: 2,
    });
    assert.equal(wtsPage1.data.transactions.length, 2);
    assert.equal(wtsPage1.data.pageNo, 1);
    assert.equal(wtsPage1.data.pageSize, 2);
    assert.equal(wtsPage1.data.total, 3);
    assert.equal(wtsPage1.data.hasMore, true);

    const wtsPage2 = await client.getWalletTransactionStatus({
      username: 'player_online',
      fromTime: 0,
      toTime: 86_400_000,
      pageNo: 2,
      pageSize: 2,
    });
    assert.equal(wtsPage2.data.transactions.length, 1);
    assert.equal(wtsPage2.data.pageNo, 2);
    assert.equal(wtsPage2.data.pageSize, 2);
    assert.equal(wtsPage2.data.total, 3);
    assert.equal(wtsPage2.data.hasMore, false);

    for (const badPage of [
      { transactionId: 'bet_1', pageNo: 0 },
      { transactionId: 'bet_1', pageNo: -1 },
      { transactionId: 'bet_1', pageNo: 1.5 },
      { transactionId: 'bet_1', pageNo: '1' },
      { transactionId: 'bet_1', pageSize: 0 },
      { transactionId: 'bet_1', pageSize: 201 },
      { transactionId: 'bet_1', pageSize: 2.5 },
      { transactionId: 'bet_1', pageSize: '10' },
    ]) {
      assert.throws(
        () => client.getWalletTransactionStatus(badPage),
        (err) => err instanceof BaccaratSdkError && err.code === 'INVALID_ARGUMENT',
      );
    }
  } finally {
    server.close();
  }

  // 4. /wallet/bet_result with deterministic isEndRound (0 on non-last, 1 on last) & outbound X-Timestamp header
  const token = 'b2bt_v16_multi_ticket_token_0123456789abcdef01234567';
  const wallet = new InMemoryWallet({
    player_v16: { currency: 'USD', balance: '1000.00', exponent: 2, tokens: [token] },
  });
  const dispatcher = new WebhookDispatcher({ apiKey, hmacSecret: secret }, wallet);
  const seenTimestamps = [];

  const webhookSrv = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const rawBuf = Buffer.concat(chunks);
      seenTimestamps.push(req.headers['x-timestamp']);
      const out = await dispatcher.handle(
        req.url ?? '',
        req.headers['x-api-key'],
        req.headers['x-signature'],
        rawBuf,
      );
      res.writeHead(out.statusCode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(out.body));
    });
  });

  await new Promise((resolve) => webhookSrv.listen(0, '127.0.0.1', resolve));
  const whPort = webhookSrv.address().port;
  const postWebhook = (route, payloadObj, xTimestamp) => new Promise((resolve, reject) => {
    const rawBuf = Buffer.from(JSON.stringify(payloadObj), 'utf8');
    // Outbound X-Timestamp is sent on all /wallet/* callbacks, while X-Signature remains strictly over raw body bytes only
    const sig = signBody(rawBuf, secret);
    const req = http.request(
      `http://127.0.0.1:${whPort}${route}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': String(rawBuf.length),
          'X-API-Key': apiKey,
          'X-Signature': sig,
          'X-Timestamp': xTimestamp,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ statusCode: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }));
      },
    );
    req.on('error', reject);
    req.write(rawBuf);
    req.end();
  });

  try {
    const roundId = 'rnd_v16_multi_1';
    const b1 = await postWebhook('/wallet/bet', {
      traceId: 't_v16_b1',
      transactionId: 'bet_v16_1',
      betId: 'tkt_v16_1',
      externalTransactionId: 'tkt_v16_1',
      roundId,
      username: 'player_v16',
      currency: 'USD',
      gameCode: 'BACCARAT:T-A2',
      amount: '100.00',
      token,
    }, '1763612001000');
    assert.equal(b1.body.status, StatusCode.SC_OK);
    assert.equal(b1.body.data.balance, '900.00');

    const b2 = await postWebhook('/wallet/bet', {
      traceId: 't_v16_b2',
      transactionId: 'bet_v16_2',
      betId: 'tkt_v16_2',
      externalTransactionId: 'tkt_v16_2',
      roundId,
      username: 'player_v16',
      currency: 'USD',
      gameCode: 'BACCARAT:T-A2',
      amount: '50.00',
      token,
    }, '1763612001100');
    assert.equal(b2.body.status, StatusCode.SC_OK);
    assert.equal(b2.body.data.balance, '850.00');

    // Ticket 1 (non-last in round): isEndRound: 0
    const settle1Payload = {
      traceId: 't_v16_s1',
      transactionId: 'stl_v16_1',
      betId: 'tkt_v16_1',
      externalTransactionId: 'tkt_v16_1',
      roundId,
      username: 'player_v16',
      currency: 'USD',
      gameCode: 'BACCARAT:T-A2',
      betAmount: '100.00',
      winAmount: '200.00',
      effectiveTurnover: '100.00',
      winLoss: '100.00',
      jackpotAmount: '0.00',
      resultType: 'WIN',
      isFreespin: 0,
      isEndRound: 0,
      betTime: 1763612001000,
    };
    const s1 = await postWebhook('/wallet/bet_result', settle1Payload, '1763612005000');
    assert.equal(s1.body.status, StatusCode.SC_OK);
    assert.equal(s1.body.data.balance, '1050.00');

    // Replay of ticket 1 with a newer X-Timestamp & traceId still succeeds idempotently (X-Signature over raw body only)
    const s1Replay = await postWebhook('/wallet/bet_result', { ...settle1Payload, traceId: 't_v16_s1_retry' }, '1763612009999');
    assert.equal(s1Replay.body.status, StatusCode.SC_OK);
    assert.equal(s1Replay.body.data.balance, '1050.00');

    // Flipping isEndRound from 0 -> 1 on same transactionId is detected as payload conflict
    assert.notEqual(
      betResultFingerprint(settle1Payload),
      betResultFingerprint({ ...settle1Payload, isEndRound: 1 }),
    );
    const s1Conflict = await postWebhook('/wallet/bet_result', { ...settle1Payload, traceId: 't_v16_s1_conf', isEndRound: 1 }, '1763612010500');
    assert.equal(s1Conflict.body.status, StatusCode.SC_TRANSACTION_DUPLICATED);

    // Ticket 2 (last non-REJECTED ticket in same round): isEndRound: 1
    const s2 = await postWebhook('/wallet/bet_result', {
      traceId: 't_v16_s2',
      transactionId: 'stl_v16_2',
      betId: 'tkt_v16_2',
      externalTransactionId: 'tkt_v16_2',
      roundId,
      username: 'player_v16',
      currency: 'USD',
      gameCode: 'BACCARAT:T-A2',
      betAmount: '50.00',
      winAmount: '0.00',
      effectiveTurnover: '50.00',
      winLoss: '-50.00',
      jackpotAmount: '0.00',
      resultType: 'LOSE',
      isFreespin: 0,
      isEndRound: 1,
      betTime: 1763612001100,
    }, '1763612012000');
    assert.equal(s2.body.status, StatusCode.SC_OK);
    assert.equal(s2.body.data.balance, '1050.00');

    assert.equal(seenTimestamps.length, 6);
    for (const ts of seenTimestamps) {
      assert.match(ts, /^\d{13}$/);
    }
  } finally {
    webhookSrv.close();
  }
});

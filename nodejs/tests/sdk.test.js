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
  Client,
  Config,
  Environment,
  InMemoryWallet,
  StatusCode,
  WebhookDispatcher,
  betFingerprint,
  betResultFingerprint,
  decimalToLedgerUnits,
  isRetryableStatus,
  ledgerUnitsToDecimal,
  rollbackFingerprint,
  signBody,
  verifySignature,
  verifyWebhookHeaders,
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

    assert.throws(() => client.getTransactionDetail({ betId: 'b2btkt1', fromTime: 0, toTime: 604_800_001 }), BaccaratSdkError);
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

  // 4. Rollback on never-deducted betId -> SC_TRANSACTION_NOT_EXISTS empty-success
  const unknownRb = {
    ...VECTORS.idempotencyVectors.rollback.initial,
    transactionId: 'rb_b2btkt000000000000000000000000',
    betId: 'b2btkt000000000000000000000000',
    externalTransactionId: 'b2btkt000000000000000000000000',
  };
  const rbEmpty = await send('/wallet/rollback', unknownRb);
  assert.equal(rbEmpty.body.status, 'SC_TRANSACTION_NOT_EXISTS');
});

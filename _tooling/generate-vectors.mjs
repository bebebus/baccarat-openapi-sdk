#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Authoritative cross-language test vector generator for bebebus/baccarat-openapi-sdk (v1.5.5).
// Every SDK (Node.js, Python, PHP, Go, Java, C++, Rust) MUST pass 100% of test-vectors.json.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_FILE = path.resolve(__dirname, '../test-vectors.json');

const LEDGER_SCALE = 1000n;
const DECIMAL_RE = /^(-?)(\d+)(?:\.(\d+))?$/;

export function signBody(rawUtf8String, hmacSecret) {
  const bytes = Buffer.from(rawUtf8String, 'utf8');
  return crypto.createHmac('sha256', Buffer.from(hmacSecret, 'utf8')).update(bytes).digest('hex');
}

export function encodeTupleFingerprint(domain, fields) {
  const parts = [`v1|${domain}`];
  for (const val of fields) {
    const str = String(val);
    const byteLen = Buffer.byteLength(str, 'utf8');
    parts.push(`${byteLen}:${str}`);
  }
  const canonical = parts.join('|');
  const digest = crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex');
  return { canonical, digest };
}

export function betFingerprint(p) {
  return encodeTupleFingerprint('wallet/bet', [
    p.transactionId,
    p.username,
    p.betId,
    p.externalTransactionId,
    p.roundId,
    p.currency,
    p.gameCode,
    p.amount,
  ]);
}

export function betResultFingerprint(p) {
  return encodeTupleFingerprint('wallet/bet_result', [
    p.transactionId,
    p.username,
    p.betId,
    p.externalTransactionId,
    p.roundId,
    p.currency,
    p.gameCode,
    p.betAmount,
    p.winAmount,
    p.effectiveTurnover,
    p.winLoss,
    p.jackpotAmount,
    p.resultType,
    String(p.isFreespin),
    String(p.isEndRound),
    String(p.betTime),
  ]);
}

export function rollbackFingerprint(p) {
  return encodeTupleFingerprint('wallet/rollback', [
    p.transactionId,
    p.username,
    p.betId,
    p.externalTransactionId,
    p.roundId,
    p.currency,
    p.gameCode,
    p.amount,
  ]);
}

export function adjustmentFingerprint(p) {
  return encodeTupleFingerprint('wallet/adjustment', [
    p.transactionId,
    p.username,
    p.betId,
    p.externalTransactionId,
    p.roundId,
    p.currency,
    p.gameCode,
    p.direction,
    p.amount,
    p.reasonCode,
  ]);
}

export function decimalToLedgerUnits(raw, displayExponent, allowNegative = false) {
  if (!Number.isInteger(displayExponent) || displayExponent < 0 || displayExponent > 18) {
    throw new Error('INVALID_DISPLAY_EXPONENT');
  }
  const text = String(raw).trim();
  const m = DECIMAL_RE.exec(text);
  if (!m) throw new Error('INVALID_DECIMAL_AMOUNT');
  const negative = m[1] === '-';
  const wholePart = m[2];
  const rawFrac = m[3] ?? '';
  const scaleDigits = displayExponent + 3;
  const trimmedFrac = rawFrac.replace(/0+$/, '');
  if (trimmedFrac.length > scaleDigits) throw new Error('DECIMAL_PRECISION_EXCEEDED');
  const divisor = LEDGER_SCALE * 10n ** BigInt(displayExponent);
  const fracPadded = trimmedFrac.padEnd(scaleDigits, '0');
  const abs = BigInt(wholePart) * divisor + (fracPadded ? BigInt(fracPadded) : 0n);
  if (negative && abs > 0n) {
    if (!allowNegative) throw new Error('NEGATIVE_DECIMAL_FORBIDDEN');
    return -abs;
  }
  return abs;
}

export function ledgerUnitsToDecimal(amount, displayExponent) {
  if (!Number.isInteger(displayExponent) || displayExponent < 0 || displayExponent > 18) {
    throw new Error('INVALID_DISPLAY_EXPONENT');
  }
  const negative = amount < 0n;
  const abs = negative ? -amount : amount;
  const divisor = LEDGER_SCALE * 10n ** BigInt(displayExponent);
  const whole = abs / divisor;
  const frac = abs % divisor;
  if (displayExponent === 0) {
    const sub = frac === 0n ? '' : '.' + frac.toString().padStart(3, '0').replace(/0+$/, '');
    return (negative ? '-' : '') + whole.toString() + sub;
  }
  const fracStr = frac.toString().padStart(displayExponent + 3, '0');
  const shown = fracStr.slice(0, displayExponent);
  const sub = fracStr.slice(displayExponent).replace(/0+$/, '');
  return (negative ? '-' : '') + whole.toString() + '.' + shown + (sub ? sub : '');
}

const DEMO_API_KEY = 'ak_0123456789abcdef0123456789abcdef';
// Synthetic 43-char base64url secret (decodes to 32 random-looking bytes if mistakenly base64url-decoded!)
const DEMO_SECRET = 'dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s';
assert.equal(DEMO_SECRET.length, 43);

const body1 = JSON.stringify({
  traceId: 'e62ceec8-1c18-48fc-af0e-9f9f943b2554',
  username: 'player_9527',
  tableId: 'T-A2',
  language: 'zh-CN',
  platform: 'H5',
  currency: 'USD',
  lobbyUrl: 'https://merchant.example.com/lobby',
  ipAddress: '203.0.113.42',
});

const wrongBase64Sig1 = crypto
  .createHmac('sha256', Buffer.from(DEMO_SECRET, 'base64url'))
  .update(Buffer.from(body1, 'utf8'))
  .digest('hex');

const body2 =
  '{"traceId":"9b7e1c20-4412-4a89-9c01-88aa77bb66cc","username":"玩家_陳大文_VIP🎲","tableId":"T-A2","language":"zh-CN","platform":"web","currency":"CNY","lobbyUrl":"https://merchant.example.com/lobby/vip?tab=live&from=h5","ipAddress":"2001:db8::1"}';

const body3 = `{\n  "traceId": "7f19b4a2-3d10-4c9a-9e21-5518a0c21101",\n  "currency": "USD",\n  "pageNo": 1,\n  "pageSize": 50\n}`;

const body4 = '{}';

const betInitial = {
  traceId: '3d55f1a9-7c80-4e11-b022-8f9910a4bc12',
  username: 'player_9527',
  transactionId: 'bet_4a19f08c2e77b3109d44e6128a5bc091',
  betId: 'b2btkt7e41a90c3f82d16b5504e9a2',
  externalTransactionId: 'b2btkt7e41a90c3f82d16b5504e9a2',
  amount: '100.00',
  currency: 'USD',
  token: 'b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819',
  gameCode: 'BACCARAT_T-A2',
  roundId: 'cm3p9y0a0000008l4b1122334',
  timestamp: 1763612010120,
};
const betRetry = {
  ...betInitial,
  traceId: 'ffffffff-1111-4222-8333-999999999999',
  timestamp: 1763612018450,
};
const betConflict = {
  ...betInitial,
  traceId: 'aaaaaaaa-1111-4222-8333-999999999999',
  amount: '200.00',
};

const settleInitial = {
  traceId: '8b7719c2-61a4-49d0-92ef-1102a3b4c5d6',
  username: 'player_9527',
  transactionId: 'stl_90e12d4b7c6a8812f34509ab12cd34ef',
  betId: 'b2btkt7e41a90c3f82d16b5504e9a2',
  externalTransactionId: 'b2btkt7e41a90c3f82d16b5504e9a2',
  roundId: 'cm3p9y0a0000008l4b1122334',
  betAmount: '100.00',
  winAmount: '200.00',
  effectiveTurnover: '100.00',
  winLoss: '100.00',
  jackpotAmount: '0.00',
  resultType: 'WIN',
  isFreespin: 0,
  isEndRound: 1,
  currency: 'USD',
  token: 'b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819',
  gameCode: 'BACCARAT_T-A2',
  betTime: 1763612010120,
  settledTime: 1763612038450,
};
const settleRetry = {
  ...settleInitial,
  traceId: '11112222-3333-4444-8555-666677778888',
  settledTime: 1763612099999,
};
const settleConflict = {
  ...settleInitial,
  winAmount: '195.00',
  winLoss: '95.00',
};

const rollbackInitial = {
  traceId: 'c1094e22-8831-42b7-9901-77a6b5c4d3e2',
  username: 'player_9527',
  transactionId: 'rb_b2btkt7e41a90c3f82d16b5504e9a2',
  betId: 'b2btkt7e41a90c3f82d16b5504e9a2',
  externalTransactionId: 'b2btkt7e41a90c3f82d16b5504e9a2',
  roundId: 'cm3p9y0a0000008l4b1122334',
  amount: '100.00',
  currency: 'USD',
  token: 'b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819',
  gameCode: 'BACCARAT_T-A2',
  timestamp: 1763612042000,
};
const rollbackRetry = {
  ...rollbackInitial,
  traceId: 'deadbeef-0000-4000-8000-000000000001',
  timestamp: 1763612088888,
};
const rollbackConflict = {
  ...rollbackInitial,
  amount: '50.00',
};

const adjustmentInitial = {
  traceId: '7d8812e3-9901-4b23-8c45-66a7b8c9d0e1',
  username: 'player_9527',
  transactionId: 'adj_RA-20261123-1234ABCD_credit',
  betId: 'b2btkt7e41a90c3f82d16b5504e9a2',
  externalTransactionId: 'b2btkt7e41a90c3f82d16b5504e9a2',
  roundId: 'cm3p9y0a0000008l4b1122334',
  direction: 'CREDIT',
  amount: '20.00',
  currency: 'USD',
  reasonCode: 'APPEAL_COMPENSATION',
  referenceNo: 'RA-20261123-1234ABCD',
  memo: 'Appeal RA-20261123-1234ABCD payout difference',
  token: 'b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819',
  gameCode: 'BACCARAT_T-A2',
  timestamp: 1763612300000,
};
const adjustmentRetry = {
  ...adjustmentInitial,
  traceId: '99990000-1111-4222-8333-444455556666',
  timestamp: 1763612399999,
  memo: 'Retry with updated memo',
  referenceNo: 'RA-20261123-1234ABCD-R2',
};
const adjustmentConflict = {
  ...adjustmentInitial,
  direction: 'DEBIT',
};

const body5 = JSON.stringify(settleInitial);

const hmacVectors = [
  {
    name: 'v1_create_game_url_base64url_secret_utf8',
    description: 'Standard /operator/v1/game/url compact JSON signed with raw UTF-8 bytes of 43-char base64url hmacSecret (NEVER base64-decode)',
    secret: DEMO_SECRET,
    rawBody: body1,
    utf8ByteLength: Buffer.byteLength(body1, 'utf8'),
    signature: signBody(body1, DEMO_SECRET),
    wrongBase64DecodedSignature: wrongBase64Sig1,
  },
  {
    name: 'v2_utf8_multibyte_cjk_emoji_and_slashes',
    description: 'Multi-byte UTF-8 username (CJK + 4-byte emoji) and unescaped slashes/ampersands in URL',
    secret: DEMO_SECRET,
    rawBody: body2,
    utf8ByteLength: Buffer.byteLength(body2, 'utf8'),
    signature: signBody(body2, DEMO_SECRET),
  },
  {
    name: 'v3_pretty_printed_json_exact_wire_bytes',
    description: 'Indented multi-line JSON body proving signature is computed over exact wire bytes including whitespace and LF',
    secret: DEMO_SECRET,
    rawBody: body3,
    utf8ByteLength: Buffer.byteLength(body3, 'utf8'),
    signature: signBody(body3, DEMO_SECRET),
  },
  {
    name: 'v4_empty_json_object',
    description: 'Minimal {} body',
    secret: 'sk_minimal_ascii_secret_key_01',
    rawBody: body4,
    utf8ByteLength: 2,
    signature: signBody(body4, 'sk_minimal_ascii_secret_key_01'),
  },
  {
    name: 'v5_outbound_wallet_bet_result_19_fields',
    description: 'Outbound /wallet/bet_result 19-field payload signed by platform',
    secret: DEMO_SECRET,
    rawBody: body5,
    utf8ByteLength: Buffer.byteLength(body5, 'utf8'),
    signature: signBody(body5, DEMO_SECRET),
  },
];

const sigBody1 = signBody(body1, DEMO_SECRET);
const headerVerificationVectors = [
  {
    name: 'hdr_valid_exact',
    expectedApiKey: DEMO_API_KEY,
    hmacSecret: DEMO_SECRET,
    apiKeyHeader: DEMO_API_KEY,
    signatureHeader: sigBody1,
    rawBody: body1,
    expectedStatus: 'SC_OK',
  },
  {
    name: 'hdr_valid_uppercase_and_trimmed',
    expectedApiKey: DEMO_API_KEY,
    hmacSecret: DEMO_SECRET,
    apiKeyHeader: `  ${DEMO_API_KEY}  `,
    signatureHeader: `  ${sigBody1.toUpperCase()}  `,
    rawBody: body1,
    expectedStatus: 'SC_OK',
  },
  {
    name: 'hdr_missing_api_key',
    expectedApiKey: DEMO_API_KEY,
    hmacSecret: DEMO_SECRET,
    apiKeyHeader: '',
    signatureHeader: sigBody1,
    rawBody: body1,
    expectedStatus: 'SC_AUTHENTICATION_FAILED',
  },
  {
    name: 'hdr_wrong_api_key',
    expectedApiKey: DEMO_API_KEY,
    hmacSecret: DEMO_SECRET,
    apiKeyHeader: 'ak_ffffffffffffffffffffffffffffffff',
    signatureHeader: sigBody1,
    rawBody: body1,
    expectedStatus: 'SC_AUTHENTICATION_FAILED',
  },
  {
    name: 'hdr_malformed_signature_not_64_hex',
    expectedApiKey: DEMO_API_KEY,
    hmacSecret: DEMO_SECRET,
    apiKeyHeader: DEMO_API_KEY,
    signatureHeader: 'abc123',
    rawBody: body1,
    expectedStatus: 'SC_INVALID_SIGNATURE',
  },
  {
    name: 'hdr_wrong_base64_decoded_secret_signature',
    expectedApiKey: DEMO_API_KEY,
    hmacSecret: DEMO_SECRET,
    apiKeyHeader: DEMO_API_KEY,
    signatureHeader: wrongBase64Sig1,
    rawBody: body1,
    expectedStatus: 'SC_INVALID_SIGNATURE',
  },
  {
    name: 'hdr_tampered_body_bytes',
    expectedApiKey: DEMO_API_KEY,
    hmacSecret: DEMO_SECRET,
    apiKeyHeader: DEMO_API_KEY,
    signatureHeader: sigBody1,
    rawBody: body1.replace('player_9527', 'player_9528'),
    expectedStatus: 'SC_INVALID_SIGNATURE',
  },
];

const betFp1 = betFingerprint(betInitial);
const betFpRetry = betFingerprint(betRetry);
const betFpConflict = betFingerprint(betConflict);
assert.equal(betFp1.digest, betFpRetry.digest);
assert.notEqual(betFp1.digest, betFpConflict.digest);

const stlFp1 = betResultFingerprint(settleInitial);
const stlFpRetry = betResultFingerprint(settleRetry);
const stlFpConflict = betResultFingerprint(settleConflict);
assert.equal(stlFp1.digest, stlFpRetry.digest);
assert.notEqual(stlFp1.digest, stlFpConflict.digest);

const rbFp1 = rollbackFingerprint(rollbackInitial);
const rbFpRetry = rollbackFingerprint(rollbackRetry);
const rbFpConflict = rollbackFingerprint(rollbackConflict);
assert.equal(rbFp1.digest, rbFpRetry.digest);
assert.notEqual(rbFp1.digest, rbFpConflict.digest);

const adjFp1 = adjustmentFingerprint(adjustmentInitial);
const adjFpRetry = adjustmentFingerprint(adjustmentRetry);
const adjFpConflict = adjustmentFingerprint(adjustmentConflict);
assert.equal(adjFp1.digest, adjFpRetry.digest);
assert.notEqual(adjFp1.digest, adjFpConflict.digest);

const validMoneyInputs = [
  { name: 'usd_100_00', raw: '100.00', displayExponent: 2, allowNegative: false },
  { name: 'usd_0_25', raw: '0.25', displayExponent: 2, allowNegative: false },
  { name: 'usd_subminor_1_0005', raw: '1.0005', displayExponent: 2, allowNegative: false },
  { name: 'usd_trailing_zeros_100_250000', raw: '100.250000', displayExponent: 2, allowNegative: false },
  { name: 'usd_negative_winloss', raw: '-100.00', displayExponent: 2, allowNegative: true },
  { name: 'usd_negative_zero_unsigned_ok', raw: '-0.00', displayExponent: 2, allowNegative: false },
  { name: 'jpy_whole_500', raw: '500', displayExponent: 0, allowNegative: false },
  { name: 'jpy_subminor_0_5', raw: '0.5', displayExponent: 0, allowNegative: false },
  { name: 'exp18_beyond_int64_1_5', raw: '1.500000000000000000', displayExponent: 18, allowNegative: false },
];

const moneyValidVectors = validMoneyInputs.map((v) => {
  const units = decimalToLedgerUnits(v.raw, v.displayExponent, v.allowNegative);
  const formatted = ledgerUnitsToDecimal(units, v.displayExponent);
  return {
    ...v,
    expectedUnits: units.toString(),
    expectedFormatted: formatted,
  };
});

const moneyInvalidVectors = [
  { name: 'neg_forbidden', raw: '-10.00', displayExponent: 2, allowNegative: false },
  { name: 'plus_sign_forbidden', raw: '+100.00', displayExponent: 2, allowNegative: false },
  { name: 'scientific_notation', raw: '1e2', displayExponent: 2, allowNegative: false },
  { name: 'thousand_comma', raw: '1,000.00', displayExponent: 2, allowNegative: false },
  { name: 'trailing_dot', raw: '100.', displayExponent: 2, allowNegative: false },
  { name: 'leading_dot', raw: '.50', displayExponent: 2, allowNegative: false },
  { name: 'empty_string', raw: '   ', displayExponent: 2, allowNegative: false },
  { name: 'nan_literal', raw: 'NaN', displayExponent: 2, allowNegative: false },
  { name: 'excess_precision_exp2', raw: '1.000001', displayExponent: 2, allowNegative: false },
  { name: 'exponent_negative', raw: '10.00', displayExponent: -1, allowNegative: false },
  { name: 'exponent_gt_18', raw: '10.00', displayExponent: 19, allowNegative: false },
];
for (const inv of moneyInvalidVectors) {
  let threw = false;
  try {
    decimalToLedgerUnits(inv.raw, inv.displayExponent, inv.allowNegative);
  } catch {
    threw = true;
  }
  assert(threw, `Expected invalid money vector ${inv.name} to throw`);
}

const statusCodes = [
  { code: 'SC_OK', retryable: false },
  { code: 'SC_INVALID_REQUEST', retryable: false },
  { code: 'SC_AUTHENTICATION_FAILED', retryable: false },
  { code: 'SC_INVALID_SIGNATURE', retryable: false },
  { code: 'SC_INVALID_TOKEN', retryable: false },
  { code: 'SC_INVALID_GAME', retryable: false },
  { code: 'SC_USER_NOT_EXISTS', retryable: false },
  { code: 'SC_USER_DISABLED', retryable: false },
  { code: 'SC_WRONG_CURRENCY', retryable: false },
  { code: 'SC_CURRENCY_NOT_SUPPORTED', retryable: false },
  { code: 'SC_INSUFFICIENT_FUNDS', retryable: false },
  { code: 'SC_TRANSACTION_DUPLICATED', retryable: false },
  { code: 'SC_TRANSACTION_NOT_EXISTS', retryable: false },
  { code: 'SC_TRANSACTION_STILL_PROCESSING', retryable: true },
  { code: 'SC_OPERATOR_TIMEOUT', retryable: true },
  { code: 'SC_UNDER_MAINTENANCE', retryable: false },
  { code: 'SC_GAME_DISABLED', retryable: false },
  { code: 'SC_RATE_LIMITED', retryable: true },
];

const doc = {
  _comment:
    'Authoritative cross-language golden test vectors for Baccarat Live Platform B2B Operator Seamless Wallet SDKs (v1.5.5). Generated by _tooling/generate-vectors.mjs and asserted byte-for-byte across Node.js, Python, PHP, Go, Java, C++, and Rust.',
  specVersion: '1.5.5',
  hmacVectors,
  headerVerificationVectors,
  idempotencyVectors: {
    bet: {
      initial: betInitial,
      retrySameBusiness: betRetry,
      conflictDifferentAmount: betConflict,
      expectedCanonical: betFp1.canonical,
      expectedFingerprint: betFp1.digest,
      conflictFingerprint: betFpConflict.digest,
    },
    betResult: {
      initial: settleInitial,
      retrySameBusiness: settleRetry,
      conflictDifferentWinAmount: settleConflict,
      expectedCanonical: stlFp1.canonical,
      expectedFingerprint: stlFp1.digest,
      conflictFingerprint: stlFpConflict.digest,
    },
    rollback: {
      initial: rollbackInitial,
      retrySameBusiness: rollbackRetry,
      conflictDifferentAmount: rollbackConflict,
      expectedCanonical: rbFp1.canonical,
      expectedFingerprint: rbFp1.digest,
      conflictFingerprint: rbFpConflict.digest,
    },
    adjustment: {
      initial: adjustmentInitial,
      retrySameBusiness: adjustmentRetry,
      conflictDifferentDirection: adjustmentConflict,
      expectedCanonical: adjFp1.canonical,
      expectedFingerprint: adjFp1.digest,
      conflictFingerprint: adjFpConflict.digest,
    },
  },
  moneyVectors: {
    valid: moneyValidVectors,
    invalid: moneyInvalidVectors,
  },
  statusCodes,
};

fs.writeFileSync(OUT_FILE, JSON.stringify(doc, null, 2) + '\n', 'utf8');
console.log(`Generated ${OUT_FILE} (${hmacVectors.length} HMAC, ${headerVerificationVectors.length} header, 4 idempotency groups, ${moneyValidVectors.length}+${moneyInvalidVectors.length} money, ${statusCodes.length} status codes)`);

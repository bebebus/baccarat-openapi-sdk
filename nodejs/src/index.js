// SPDX-License-Identifier: MIT
// Zero-dependency Node.js SDK for Baccarat Live Platform B2B Operator Seamless Wallet API (v1.5.0).

import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';

export const SANDBOX_BASE_URL = 'https://api.lt.cniia.cloud';
export const MAX_DETAIL_WINDOW_MS = 604_800_000; // 7 days in ms
export const MAX_PAGE_SIZE = 20_000;
export const MAX_WEBHOOK_BODY_BYTES = 1_048_576; // 1 MiB
const MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024; // 16 MiB

export const Environment = Object.freeze({
  SANDBOX: 'SANDBOX',
  PRODUCTION: 'PRODUCTION',
});

export const StatusCode = Object.freeze({
  SC_OK: 'SC_OK',
  SC_INVALID_REQUEST: 'SC_INVALID_REQUEST',
  SC_AUTHENTICATION_FAILED: 'SC_AUTHENTICATION_FAILED',
  SC_INVALID_SIGNATURE: 'SC_INVALID_SIGNATURE',
  SC_INVALID_TOKEN: 'SC_INVALID_TOKEN',
  SC_INVALID_GAME: 'SC_INVALID_GAME',
  SC_USER_NOT_EXISTS: 'SC_USER_NOT_EXISTS',
  SC_USER_DISABLED: 'SC_USER_DISABLED',
  SC_WRONG_CURRENCY: 'SC_WRONG_CURRENCY',
  SC_CURRENCY_NOT_SUPPORTED: 'SC_CURRENCY_NOT_SUPPORTED',
  SC_INSUFFICIENT_FUNDS: 'SC_INSUFFICIENT_FUNDS',
  SC_TRANSACTION_DUPLICATED: 'SC_TRANSACTION_DUPLICATED',
  SC_TRANSACTION_NOT_EXISTS: 'SC_TRANSACTION_NOT_EXISTS',
  SC_TRANSACTION_STILL_PROCESSING: 'SC_TRANSACTION_STILL_PROCESSING',
  SC_OPERATOR_TIMEOUT: 'SC_OPERATOR_TIMEOUT',
  SC_UNDER_MAINTENANCE: 'SC_UNDER_MAINTENANCE',
  SC_GAME_DISABLED: 'SC_GAME_DISABLED',
  SC_RATE_LIMITED: 'SC_RATE_LIMITED',
});

const RETRYABLE_STATUSES = new Set([
  StatusCode.SC_TRANSACTION_STILL_PROCESSING,
  StatusCode.SC_OPERATOR_TIMEOUT,
  StatusCode.SC_RATE_LIMITED,
]);

export function isRetryableStatus(status) {
  return RETRYABLE_STATUSES.has(String(status ?? '').trim());
}

export class BaccaratSdkError extends Error {
  constructor(message, code = 'SDK_ERROR') {
    super(message);
    this.name = 'BaccaratSdkError';
    this.code = code;
  }
}

export class BaccaratApiError extends BaccaratSdkError {
  constructor({ traceId = '', status, message = '', validation = undefined, httpStatus = 200 }) {
    super(message || `B2B API error: ${status}`, status);
    this.name = 'BaccaratApiError';
    this.traceId = traceId;
    this.status = status;
    this.validation = validation;
    this.httpStatus = httpStatus;
  }

  isRetryable() {
    return isRetryableStatus(this.status);
  }
}

// ── 1. Raw-Byte HMAC-SHA256 Signing & Timing-Safe Verification ──────────────

const HEX64_RE = /^[0-9a-fA-F]{64}$/;
const TRACE_HINT_RE = /"traceId"\s*:\s*"([A-Za-z0-9_.:-]{1,128})"/;

export function signBody(rawBody, hmacSecret) {
  if (typeof hmacSecret !== 'string' || hmacSecret.length === 0) {
    throw new BaccaratSdkError('hmacSecret must be a non-empty string', 'INVALID_CONFIG');
  }
  const bytes = Buffer.isBuffer(rawBody)
    ? rawBody
    : rawBody instanceof Uint8Array
      ? Buffer.from(rawBody)
      : Buffer.from(String(rawBody ?? ''), 'utf8');
  // CRITICAL: Use raw UTF-8 string bytes of hmacSecret directly — NEVER Base64-decode!
  return crypto.createHmac('sha256', Buffer.from(hmacSecret, 'utf8')).update(bytes).digest('hex');
}

export function verifySignature(rawBody, signatureHeader, hmacSecret) {
  if (typeof hmacSecret !== 'string' || hmacSecret.length === 0) return false;
  if (typeof signatureHeader !== 'string') return false;
  const trimmed = signatureHeader.trim();
  if (!HEX64_RE.test(trimmed)) return false;
  const expectedHex = signBody(rawBody, hmacSecret);
  const actualBuf = Buffer.from(trimmed.toLowerCase(), 'hex');
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (actualBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(actualBuf, expectedBuf);
}

function timingSafeStringEqual(a, b) {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) {
    crypto.timingSafeEqual(bufA, bufA);
    return false;
  }
  return crypto.timingSafeEqual(bufA, bufB);
}

export function verifyWebhookHeaders(apiKeyHeader, signatureHeader, rawBody, expectedApiKey, hmacSecret) {
  const expectedKey = String(expectedApiKey ?? '').trim();
  const actualKey = typeof apiKeyHeader === 'string' ? apiKeyHeader.trim() : '';
  if (!expectedKey || !actualKey || !timingSafeStringEqual(actualKey, expectedKey)) {
    return StatusCode.SC_AUTHENTICATION_FAILED;
  }
  if (!verifySignature(rawBody, signatureHeader, hmacSecret)) {
    return StatusCode.SC_INVALID_SIGNATURE;
  }
  return StatusCode.SC_OK;
}

// ── 2. Exact Decimal & Ledger Unit Utilities (Zero Float Math) ──────────────

const LEDGER_SCALE = 1000n;
const DECIMAL_RE = /^(-?)(\d+)(?:\.(\d+))?$/;

export function decimalToLedgerUnits(raw, displayExponent, { allowNegative = false } = {}) {
  if (!Number.isInteger(displayExponent) || displayExponent < 0 || displayExponent > 18) {
    throw new BaccaratSdkError(`displayExponent out of range: ${displayExponent}`, 'INVALID_DISPLAY_EXPONENT');
  }
  let text;
  if (typeof raw === 'number') {
    if (!Number.isFinite(raw) || Math.abs(raw) > 9_000_000_000_000_000) {
      throw new BaccaratSdkError(`invalid numeric decimal amount: ${raw}`, 'INVALID_DECIMAL_AMOUNT');
    }
    text = String(raw);
  } else if (typeof raw === 'string') {
    text = raw.trim();
  } else {
    throw new BaccaratSdkError('decimal amount must be string or finite number', 'INVALID_DECIMAL_AMOUNT');
  }
  const m = DECIMAL_RE.exec(text);
  if (!m) {
    throw new BaccaratSdkError(`malformed decimal amount: ${text}`, 'INVALID_DECIMAL_AMOUNT');
  }
  const negative = m[1] === '-';
  const wholePart = m[2];
  const rawFrac = m[3] ?? '';
  const scaleDigits = displayExponent + 3;
  const trimmedFrac = rawFrac.replace(/0+$/, '');
  if (trimmedFrac.length > scaleDigits) {
    throw new BaccaratSdkError(
      `decimal amount ${text} exceeds max precision (${scaleDigits} decimals)`,
      'DECIMAL_PRECISION_EXCEEDED',
    );
  }
  const divisor = LEDGER_SCALE * 10n ** BigInt(displayExponent);
  const fracPadded = trimmedFrac.padEnd(scaleDigits, '0');
  const abs = BigInt(wholePart) * divisor + (fracPadded ? BigInt(fracPadded) : 0n);
  if (negative && abs > 0n) {
    if (!allowNegative) {
      throw new BaccaratSdkError(`negative decimal amount forbidden: ${text}`, 'NEGATIVE_DECIMAL_FORBIDDEN');
    }
    return -abs;
  }
  return abs;
}

export function ledgerUnitsToDecimal(amount, displayExponent) {
  if (!Number.isInteger(displayExponent) || displayExponent < 0 || displayExponent > 18) {
    throw new BaccaratSdkError(`displayExponent out of range: ${displayExponent}`, 'INVALID_DISPLAY_EXPONENT');
  }
  const bigAmt = typeof amount === 'bigint' ? amount : BigInt(amount);
  const negative = bigAmt < 0n;
  const abs = negative ? -bigAmt : bigAmt;
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

// ── 3. Canonical Idempotency Fingerprints (Excludes Mutable Retry Fields) ───

export function encodeTupleFingerprint(domain, fields) {
  const parts = [`v1|${domain}`];
  for (const val of fields) {
    const str = String(val ?? '');
    parts.push(`${Buffer.byteLength(str, 'utf8')}:${str}`);
  }
  const canonical = parts.join('|');
  return crypto.createHash('sha256').update(Buffer.from(canonical, 'utf8')).digest('hex');
}

export function betFingerprint(payload) {
  return encodeTupleFingerprint('wallet/bet', [
    payload?.transactionId ?? '',
    payload?.username ?? '',
    payload?.betId ?? '',
    payload?.externalTransactionId ?? '',
    payload?.roundId ?? '',
    payload?.currency ?? '',
    payload?.gameCode ?? '',
    payload?.amount ?? '',
  ]);
}

export function betResultFingerprint(payload) {
  return encodeTupleFingerprint('wallet/bet_result', [
    payload?.transactionId ?? '',
    payload?.username ?? '',
    payload?.betId ?? '',
    payload?.externalTransactionId ?? '',
    payload?.roundId ?? '',
    payload?.currency ?? '',
    payload?.gameCode ?? '',
    payload?.betAmount ?? '',
    payload?.winAmount ?? '',
    payload?.effectiveTurnover ?? '',
    payload?.winLoss ?? '',
    payload?.jackpotAmount ?? '',
    payload?.resultType ?? '',
    String(payload?.isFreespin ?? ''),
    String(payload?.isEndRound ?? ''),
    String(payload?.betTime ?? ''),
  ]);
}

export function rollbackFingerprint(payload) {
  return encodeTupleFingerprint('wallet/rollback', [
    payload?.transactionId ?? '',
    payload?.username ?? '',
    payload?.betId ?? '',
    payload?.externalTransactionId ?? '',
    payload?.roundId ?? '',
    payload?.currency ?? '',
    payload?.gameCode ?? '',
    payload?.amount ?? '',
  ]);
}

export function adjustmentFingerprint(payload) {
  return encodeTupleFingerprint('wallet/adjustment', [
    payload?.transactionId ?? '',
    payload?.username ?? '',
    payload?.betId ?? '',
    payload?.externalTransactionId ?? '',
    payload?.roundId ?? '',
    payload?.currency ?? '',
    payload?.gameCode ?? '',
    payload?.direction ?? '',
    payload?.amount ?? '',
    payload?.reasonCode ?? '',
  ]);
}

// ── 4. Client Configuration & S2S Client (/operator/v1/*) ───────────────────

export class Config {
  constructor({ apiKey, hmacSecret, environment = Environment.PRODUCTION, baseUrl = undefined, timeoutMs = 8000 } = {}) {
    const trimmedKey = String(apiKey ?? '').trim();
    const secretStr = typeof hmacSecret === 'string' ? hmacSecret : '';
    if (!trimmedKey) {
      throw new BaccaratSdkError('apiKey is required', 'INVALID_CONFIG');
    }
    if (!secretStr) {
      throw new BaccaratSdkError('hmacSecret is required', 'INVALID_CONFIG');
    }
    let resolvedUrl = typeof baseUrl === 'string' ? baseUrl.trim() : '';
    if (!resolvedUrl) {
      if (environment === Environment.SANDBOX) {
        resolvedUrl = SANDBOX_BASE_URL;
      } else {
        throw new BaccaratSdkError(
          'baseUrl is required when environment is PRODUCTION (or set environment: Environment.SANDBOX)',
          'INVALID_CONFIG',
        );
      }
    }
    if (!/^https?:\/\//i.test(resolvedUrl)) {
      throw new BaccaratSdkError(`baseUrl must start with http:// or https://, got: ${resolvedUrl}`, 'INVALID_CONFIG');
    }
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new BaccaratSdkError(`timeoutMs must be a positive integer, got: ${timeoutMs}`, 'INVALID_CONFIG');
    }
    this.apiKey = trimmedKey;
    this.hmacSecret = secretStr;
    this.environment = environment;
    this.baseUrl = resolvedUrl.replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
    Object.freeze(this);
  }
}

function defaultHttpPost(urlStr, headers, rawBodyBuf, timeoutMs) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const transport = url.protocol === 'https:' ? https : http;
    let settled = false;
    const finishReject = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    };
    const req = transport.request(
      url,
      {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Length': String(rawBodyBuf.length),
        },
      },
      (res) => {
        const chunks = [];
        let received = 0;
        res.on('data', (chunk) => {
          received += chunk.length;
          if (received > MAX_HTTP_RESPONSE_BYTES) {
            req.destroy();
            finishReject(new BaccaratSdkError('Gateway response exceeded 16 MiB limit', StatusCode.SC_INVALID_REQUEST));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          if (settled) return;
          settled = true;
          resolve({
            httpStatus: res.statusCode ?? 0,
            rawBody: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(new BaccaratSdkError(`Request timed out after ${timeoutMs}ms`, StatusCode.SC_OPERATOR_TIMEOUT));
    });
    req.on('error', (err) => {
      if (err instanceof BaccaratSdkError) finishReject(err);
      else finishReject(new BaccaratSdkError(`Network error: ${err.message}`, StatusCode.SC_OPERATOR_TIMEOUT));
    });
    req.write(rawBodyBuf);
    req.end();
  });
}

export class Client {
  constructor(config, { transport = defaultHttpPost } = {}) {
    this.config = config instanceof Config ? config : new Config(config);
    this.transport = transport;
  }

  async postSigned(routePath, bodyObj) {
    const rawInput = bodyObj && typeof bodyObj === 'object' && !Array.isArray(bodyObj) ? bodyObj : {};
    const rawTrace = rawInput.traceId;
    const resolvedTraceId =
      typeof rawTrace === 'string' && rawTrace.trim().length > 0
        ? rawTrace.trim()
        : rawTrace != null && typeof rawTrace !== 'string' && String(rawTrace).trim().length > 0
          ? String(rawTrace).trim()
          : crypto.randomUUID();
    const payload = {
      ...rawInput,
      traceId: resolvedTraceId,
    };

    const rawJson = JSON.stringify(payload);
    const rawBuf = Buffer.from(rawJson, 'utf8');
    const signature = signBody(rawBuf, this.config.hmacSecret);
    const headers = {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-API-Key': this.config.apiKey,
      'X-Signature': signature,
    };

    const { httpStatus, rawBody } = await this.transport(
      `${this.config.baseUrl}${routePath}`,
      headers,
      rawBuf,
      this.config.timeoutMs,
    );

    let parsed;
    try {
      parsed = JSON.parse(rawBody);
    } catch {
      throw new BaccaratApiError({
        traceId: payload.traceId,
        status: httpStatus >= 500 || httpStatus === 408 || httpStatus === 429
          ? StatusCode.SC_OPERATOR_TIMEOUT
          : StatusCode.SC_INVALID_REQUEST,
        message: `Non-JSON HTTP ${httpStatus} response from gateway`,
        httpStatus,
      });
    }

    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new BaccaratApiError({
        traceId: payload.traceId,
        status: StatusCode.SC_INVALID_REQUEST,
        message: 'Malformed envelope from gateway',
        httpStatus,
      });
    }

    if (httpStatus !== 200 || parsed.status !== StatusCode.SC_OK) {
      throw new BaccaratApiError({
        traceId: String(parsed.traceId ?? payload.traceId),
        status: String(parsed.status ?? StatusCode.SC_INVALID_REQUEST),
        message: String(parsed.message ?? `HTTP ${httpStatus}`),
        validation: parsed.validation,
        httpStatus,
      });
    }

    return {
      traceId: String(parsed.traceId ?? payload.traceId),
      status: StatusCode.SC_OK,
      data: parsed.data,
    };
  }

  ping(params = {}) {
    return this.postSigned('/operator/v1/ping', params);
  }

  createGameUrl(params) {
    return this.postSigned('/operator/v1/game/url', params);
  }

  listTables(params = {}) {
    return this.postSigned('/operator/v1/game/tables', params);
  }

  terminateSessions(params = {}) {
    return this.postSigned('/operator/v1/game/terminate', params);
  }

  updatePlayerStatus(params) {
    return this.postSigned('/operator/v1/player/status', params);
  }

  updatePlayerLimits(params) {
    return this.postSigned('/operator/v1/player/limits', params);
  }

  listTransactions(params) {
    if (params == null || typeof params.fromTime !== 'number' || typeof params.toTime !== 'number') {
      throw new BaccaratSdkError('fromTime and toTime must be non-negative epoch ms integers', 'INVALID_ARGUMENT');
    }
    if (!Number.isInteger(params.fromTime) || !Number.isInteger(params.toTime) || params.fromTime < 0 || params.toTime < params.fromTime) {
      throw new BaccaratSdkError('Invalid [fromTime, toTime] settlement window', 'INVALID_ARGUMENT');
    }
    return this.postSigned('/operator/v1/transaction/list', params);
  }

  async listAllTransactions({ fromTime, toTime, pageSize = 2000, ...rest }) {
    if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > MAX_PAGE_SIZE) {
      throw new BaccaratSdkError(`pageSize must be an integer in 1..${MAX_PAGE_SIZE}`, 'INVALID_ARGUMENT');
    }
    const all = [];
    let pageNo = 1;
    while (true) {
      const res = await this.listTransactions({ ...rest, fromTime, toTime, pageNo, pageSize });
      const rows = Array.isArray(res.data?.transactions) ? res.data.transactions : [];
      all.push(...rows);
      const total = Number(res.data?.total ?? all.length);
      if (all.length >= total || rows.length === 0) break;
      pageNo += 1;
    }
    return all;
  }

  getTransactionDetail(params) {
    if (params == null || typeof params.betId !== 'string' || !params.betId.trim()) {
      throw new BaccaratSdkError('betId is required', 'INVALID_ARGUMENT');
    }
    if (params.fromTime != null || params.toTime != null) {
      if (typeof params.fromTime !== 'number' || typeof params.toTime !== 'number') {
        throw new BaccaratSdkError('fromTime and toTime must both be epoch ms integers when specified', 'INVALID_ARGUMENT');
      }
      const span = params.toTime - params.fromTime;
      if (!Number.isInteger(params.fromTime) || !Number.isInteger(params.toTime) || params.fromTime < 0 || span < 0 || span > MAX_DETAIL_WINDOW_MS) {
        throw new BaccaratSdkError('Detail query window must satisfy 0 <= toTime - fromTime <= 604800000 (7 days)', 'INVALID_ARGUMENT');
      }
    }
    return this.postSigned('/operator/v1/transaction/detail', params);
  }

  listUnsettledTransactions(params = {}) {
    return this.postSigned('/operator/v1/transaction/unsettled', params);
  }

  getWalletTransactionStatus(params) {
    const txId = typeof params?.transactionId === 'string' ? params.transactionId.trim() : '';
    const betId = typeof params?.betId === 'string' ? params.betId.trim() : '';
    const username = typeof params?.username === 'string' ? params.username.trim() : '';
    if (!txId && !betId && !username) {
      throw new BaccaratSdkError('At least one of transactionId, betId, or username is required', 'INVALID_ARGUMENT');
    }
    if (username && !txId && !betId) {
      if (typeof params?.fromTime !== 'number' || typeof params?.toTime !== 'number') {
        throw new BaccaratSdkError('fromTime and toTime epoch ms integers are required when querying by username alone', 'INVALID_ARGUMENT');
      }
      const span = params.toTime - params.fromTime;
      if (!Number.isInteger(params.fromTime) || !Number.isInteger(params.toTime) || params.fromTime < 0 || span < 0 || span > 86_400_000) {
        throw new BaccaratSdkError('Username query window must satisfy 0 <= toTime - fromTime <= 86400000 (24 hours)', 'INVALID_ARGUMENT');
      }
    }
    return this.postSigned('/operator/v1/wallet/transaction-status', params);
  }
}

// ── 5. Seamless Wallet Webhook Dispatcher & Reference In-Memory Wallet ──────

function requireNonEmptyStr(val) {
  return typeof val === 'string' && val.trim().length > 0 ? val.trim() : null;
}

export class InMemoryWallet {
  constructor(initialAccounts = {}) {
    this.accounts = new Map();
    this.transactions = new Map(); // txId -> { fingerprint, betId, type, emptyRollback }
    this.deductedBets = new Map(); // betId -> { txId, username, currency, amountUnits, state: 'DEDUCTED'|'SETTLED'|'ROLLED_BACK' }
    for (const [username, info] of Object.entries(initialAccounts)) {
      const exponent = info.exponent ?? 2;
      const units = decimalToLedgerUnits(info.balance ?? '0.00', exponent);
      this.accounts.set(username, {
        currency: String(info.currency).trim().toUpperCase(),
        exponent,
        balanceUnits: units,
        validTokens: new Set(info.tokens ?? []),
        disabled: Boolean(info.disabled),
      });
    }
  }

  registerToken(username, token) {
    const acct = this.accounts.get(username);
    if (!acct) throw new BaccaratSdkError(`Unknown account ${username}`, StatusCode.SC_USER_NOT_EXISTS);
    acct.validTokens.add(token);
  }

  setDisabled(username, disabled) {
    const acct = this.accounts.get(username);
    if (acct) acct.disabled = Boolean(disabled);
  }

  _requireAccountAndCurrency(username, currency) {
    const acct = this.accounts.get(username);
    if (!acct) return { error: StatusCode.SC_USER_NOT_EXISTS, message: 'User does not exist' };
    if (acct.currency !== String(currency ?? '').trim().toUpperCase()) {
      return { error: StatusCode.SC_WRONG_CURRENCY, message: 'Currency mismatch' };
    }
    return { acct };
  }

  _okEnvelope(traceId, username, acct) {
    return {
      traceId,
      status: StatusCode.SC_OK,
      data: {
        username,
        currency: acct.currency,
        balance: ledgerUnitsToDecimal(acct.balanceUnits, acct.exponent),
        timestamp: Date.now(),
      },
    };
  }

  async onBalance(req) {
    const traceId = typeof req?.traceId === 'string' ? req.traceId : '';
    const username = requireNonEmptyStr(req?.username);
    const currency = requireNonEmptyStr(req?.currency);
    if (!username || !currency) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'username and currency are required' };
    }
    const check = this._requireAccountAndCurrency(username, currency);
    if (check.error) return { traceId, status: check.error, message: check.message };
    const { acct } = check;
    if (acct.disabled) return { traceId, status: StatusCode.SC_USER_DISABLED, message: 'User disabled' };
    if (acct.validTokens.size > 0 && !acct.validTokens.has(req.token)) {
      return { traceId, status: StatusCode.SC_INVALID_TOKEN, message: 'Invalid launch token' };
    }
    return this._okEnvelope(traceId, username, acct);
  }

  async onBet(req) {
    const traceId = typeof req?.traceId === 'string' ? req.traceId : '';
    const txId = requireNonEmptyStr(req?.transactionId);
    const betId = requireNonEmptyStr(req?.betId);
    const username = requireNonEmptyStr(req?.username);
    const currency = requireNonEmptyStr(req?.currency);
    if (!txId || !betId || !username || !currency || req?.amount == null) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Missing required bet fields' };
    }
    const check = this._requireAccountAndCurrency(username, currency);
    if (check.error) return { traceId, status: check.error, message: check.message };
    const { acct } = check;
    const fp = betFingerprint(req);
    const prior = this.transactions.get(txId);
    if (prior) {
      if (prior.type !== 'BET' || prior.fingerprint !== fp) {
        return { traceId, status: StatusCode.SC_TRANSACTION_DUPLICATED, message: 'Conflicting bet payload on same transactionId' };
      }
      return this._okEnvelope(traceId, username, acct);
    }
    if (this.deductedBets.has(betId)) {
      return { traceId, status: StatusCode.SC_TRANSACTION_DUPLICATED, message: 'Duplicate betId under different transactionId' };
    }
    if (acct.disabled) return { traceId, status: StatusCode.SC_USER_DISABLED, message: 'User disabled' };
    if (acct.validTokens.size > 0 && !acct.validTokens.has(req.token)) {
      return { traceId, status: StatusCode.SC_INVALID_TOKEN, message: 'Invalid launch token' };
    }
    const stakeUnits = decimalToLedgerUnits(req.amount, acct.exponent);
    if (stakeUnits <= 0n) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Bet amount must be positive' };
    }
    if (acct.balanceUnits < stakeUnits) {
      return { traceId, status: StatusCode.SC_INSUFFICIENT_FUNDS, message: 'Insufficient funds' };
    }
    acct.balanceUnits -= stakeUnits;
    this.transactions.set(txId, { fingerprint: fp, betId, type: 'BET', emptyRollback: false });
    this.deductedBets.set(betId, { txId, username, currency: acct.currency, amountUnits: stakeUnits, state: 'DEDUCTED' });
    return this._okEnvelope(traceId, username, acct);
  }

  async onBetResult(req) {
    const traceId = typeof req?.traceId === 'string' ? req.traceId : '';
    const txId = requireNonEmptyStr(req?.transactionId);
    const betId = requireNonEmptyStr(req?.betId);
    const username = requireNonEmptyStr(req?.username);
    const currency = requireNonEmptyStr(req?.currency);
    if (!txId || !betId || !username || !currency || req?.winAmount == null || req?.betAmount == null) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Missing required bet_result fields' };
    }
    const check = this._requireAccountAndCurrency(username, currency);
    if (check.error) return { traceId, status: check.error, message: check.message };
    const { acct } = check;
    const fp = betResultFingerprint(req);
    const prior = this.transactions.get(txId);
    if (prior) {
      if (prior.type !== 'SETTLE' || prior.fingerprint !== fp) {
        return { traceId, status: StatusCode.SC_TRANSACTION_DUPLICATED, message: 'Conflicting bet_result payload' };
      }
      return this._okEnvelope(traceId, username, acct);
    }
    // IMPORTANT (v1.2.0 invariant): Honor settlement for already-deducted betId even if player later logged out or was disabled!
    const origBet = this.deductedBets.get(betId);
    if (!origBet) {
      return { traceId, status: StatusCode.SC_TRANSACTION_NOT_EXISTS, message: 'Original betId not found' };
    }
    const betUnits = decimalToLedgerUnits(req.betAmount, acct.exponent);
    const winUnits = decimalToLedgerUnits(req.winAmount, acct.exponent);
    if (origBet.username !== username || origBet.currency !== acct.currency || origBet.amountUnits !== betUnits) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'bet_result does not match original deducted bet' };
    }
    if (origBet.state !== 'DEDUCTED') {
      return { traceId, status: StatusCode.SC_TRANSACTION_DUPLICATED, message: `betId already in terminal state ${origBet.state}` };
    }
    acct.balanceUnits += winUnits;
    origBet.state = 'SETTLED';
    this.transactions.set(txId, { fingerprint: fp, betId, type: 'SETTLE', emptyRollback: false });
    return this._okEnvelope(traceId, username, acct);
  }

  async onRollback(req) {
    const traceId = typeof req?.traceId === 'string' ? req.traceId : '';
    const txId = requireNonEmptyStr(req?.transactionId);
    const betId = requireNonEmptyStr(req?.betId);
    const username = requireNonEmptyStr(req?.username);
    const currency = requireNonEmptyStr(req?.currency);
    if (!txId || !betId || !username || !currency || req?.amount == null) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Missing required rollback fields' };
    }
    const check = this._requireAccountAndCurrency(username, currency);
    if (check.error) return { traceId, status: check.error, message: check.message };
    const { acct } = check;
    const fp = rollbackFingerprint(req);
    const prior = this.transactions.get(txId);
    if (prior) {
      if (prior.type !== 'ROLLBACK' || prior.fingerprint !== fp) {
        return { traceId, status: StatusCode.SC_TRANSACTION_DUPLICATED, message: 'Conflicting rollback payload' };
      }
      if (prior.emptyRollback) {
        return { traceId, status: StatusCode.SC_TRANSACTION_NOT_EXISTS, message: 'Original betId was never deducted' };
      }
      return this._okEnvelope(traceId, username, acct);
    }
    const refundUnits = decimalToLedgerUnits(req.amount, acct.exponent);
    if (refundUnits <= 0n) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Rollback amount must be positive' };
    }
    const origBet = this.deductedBets.get(betId);
    if (!origBet) {
      // Empty-success convergence per v1.2.0 specification
      this.transactions.set(txId, { fingerprint: fp, betId, type: 'ROLLBACK', emptyRollback: true });
      return { traceId, status: StatusCode.SC_TRANSACTION_NOT_EXISTS, message: 'Original betId was never deducted' };
    }
    if (origBet.username !== username || origBet.currency !== acct.currency || origBet.amountUnits !== refundUnits) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Rollback does not match original deducted bet' };
    }
    if (origBet.state !== 'DEDUCTED') {
      return { traceId, status: StatusCode.SC_TRANSACTION_DUPLICATED, message: `betId already in terminal state ${origBet.state}` };
    }
    acct.balanceUnits += refundUnits;
    origBet.state = 'ROLLED_BACK';
    this.transactions.set(txId, { fingerprint: fp, betId, type: 'ROLLBACK', emptyRollback: false });
    return this._okEnvelope(traceId, username, acct);
  }

  async onAdjustment(req) {
    const traceId = typeof req?.traceId === 'string' ? req.traceId : '';
    const txId = requireNonEmptyStr(req?.transactionId);
    const betId = requireNonEmptyStr(req?.betId);
    const username = requireNonEmptyStr(req?.username);
    const currency = requireNonEmptyStr(req?.currency);
    const direction = requireNonEmptyStr(req?.direction)?.toUpperCase();
    const reasonCode = requireNonEmptyStr(req?.reasonCode);
    if (!txId || !betId || !username || !currency || !reasonCode || req?.amount == null || (direction !== 'CREDIT' && direction !== 'DEBIT')) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Missing or invalid adjustment fields' };
    }
    const check = this._requireAccountAndCurrency(username, currency);
    if (check.error) return { traceId, status: check.error, message: check.message };
    const { acct } = check;
    const fp = adjustmentFingerprint(req);
    const prior = this.transactions.get(txId);
    if (prior) {
      if (prior.type !== 'ADJUSTMENT' || prior.fingerprint !== fp) {
        return { traceId, status: StatusCode.SC_TRANSACTION_DUPLICATED, message: 'Conflicting adjustment payload' };
      }
      return this._okEnvelope(traceId, username, acct);
    }
    const origBet = this.deductedBets.get(betId);
    if (!origBet) {
      return { traceId, status: StatusCode.SC_TRANSACTION_NOT_EXISTS, message: 'Original betId not found' };
    }
    if (origBet.username !== username || origBet.currency !== acct.currency) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Adjustment does not match original bet account' };
    }
    const adjUnits = decimalToLedgerUnits(req.amount, acct.exponent);
    if (adjUnits <= 0n) {
      return { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Adjustment amount must be positive' };
    }
    if (direction === 'DEBIT') {
      if (acct.balanceUnits < adjUnits) {
        return { traceId, status: StatusCode.SC_INSUFFICIENT_FUNDS, message: 'Insufficient funds for debit adjustment' };
      }
      acct.balanceUnits -= adjUnits;
    } else {
      acct.balanceUnits += adjUnits;
    }
    this.transactions.set(txId, { fingerprint: fp, betId, type: 'ADJUSTMENT', emptyRollback: false });
    return this._okEnvelope(traceId, username, acct);
  }
}

function extractSafeTraceHint(rawBuf) {
  const head = rawBuf.subarray(0, 1024).toString('utf8');
  const m = TRACE_HINT_RE.exec(head);
  return m ? m[1] : '';
}

export class WebhookDispatcher {
  constructor(config, walletHandler) {
    this.config = config instanceof Config ? config : new Config({ ...config, environment: Environment.SANDBOX });
    if (!walletHandler || typeof walletHandler !== 'object') {
      throw new BaccaratSdkError('walletHandler is required', 'INVALID_CONFIG');
    }
    this.wallet = walletHandler;
  }

  async handle(routePath, apiKeyHeader, signatureHeader, rawBody) {
    const rawBuf = Buffer.isBuffer(rawBody)
      ? rawBody
      : rawBody instanceof Uint8Array
        ? Buffer.from(rawBody)
        : Buffer.from(String(rawBody ?? ''), 'utf8');

    if (rawBuf.length > MAX_WEBHOOK_BODY_BYTES) {
      return {
        statusCode: 200,
        body: { traceId: '', status: StatusCode.SC_INVALID_REQUEST, message: 'Request body exceeds 1 MiB limit' },
      };
    }

    // Verify X-API-Key & X-Signature over raw bytes BEFORE invoking JSON.parse!
    const authStatus = verifyWebhookHeaders(
      apiKeyHeader,
      signatureHeader,
      rawBuf,
      this.config.apiKey,
      this.config.hmacSecret,
    );
    if (authStatus !== StatusCode.SC_OK) {
      return {
        statusCode: 200,
        body: {
          traceId: extractSafeTraceHint(rawBuf),
          status: authStatus,
          message: authStatus === StatusCode.SC_AUTHENTICATION_FAILED ? 'Invalid X-API-Key' : 'Invalid X-Signature',
        },
      };
    }

    let traceId = '';
    let parsed = null;
    try {
      const candidate = JSON.parse(rawBuf.toString('utf8'));
      if (candidate && typeof candidate === 'object' && !Array.isArray(candidate)) {
        parsed = candidate;
        if (typeof candidate.traceId === 'string') traceId = candidate.traceId.trim().slice(0, 128);
      }
    } catch {
      parsed = null;
    }

    if (!parsed) {
      return {
        statusCode: 200,
        body: { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Request body must be a JSON object' },
      };
    }

    const cleanPath = String(routePath ?? '').split('?')[0].replace(/\/+$/, '');
    try {
      let responseBody;
      if (cleanPath.endsWith('/wallet/balance')) {
        responseBody = await this.wallet.onBalance(parsed);
      } else if (cleanPath.endsWith('/wallet/bet')) {
        responseBody = await this.wallet.onBet(parsed);
      } else if (cleanPath.endsWith('/wallet/bet_result')) {
        responseBody = await this.wallet.onBetResult(parsed);
      } else if (cleanPath.endsWith('/wallet/rollback')) {
        responseBody = await this.wallet.onRollback(parsed);
      } else if (cleanPath.endsWith('/wallet/adjustment')) {
        if (typeof this.wallet.onAdjustment !== 'function') {
          responseBody = { traceId, status: StatusCode.SC_INVALID_REQUEST, message: 'Wallet handler does not implement onAdjustment' };
        } else {
          responseBody = await this.wallet.onAdjustment(parsed);
        }
      } else {
        responseBody = { traceId, status: StatusCode.SC_INVALID_REQUEST, message: `Unsupported wallet route: ${cleanPath}` };
      }
      return { statusCode: 200, body: responseBody };
    } catch (err) {
      const status = err instanceof BaccaratSdkError && err.code.startsWith('SC_') ? err.code : StatusCode.SC_INVALID_REQUEST;
      return {
        statusCode: 200,
        body: { traceId, status, message: err instanceof Error ? err.message : 'Wallet handler error' },
      };
    }
  }
}

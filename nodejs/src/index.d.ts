// SPDX-License-Identifier: MIT
export const SANDBOX_BASE_URL: string;
export const MAX_DETAIL_WINDOW_MS: number;
export const MAX_EPOCH_MS: number;
export const MAX_PAGE_SIZE: number;
export const MAX_WEBHOOK_BODY_BYTES: number;

export const Environment: Readonly<{
  SANDBOX: 'SANDBOX';
  PRODUCTION: 'PRODUCTION';
}>;

export type OperatorStatusCode =
  | 'SC_OK'
  | 'SC_INVALID_REQUEST'
  | 'SC_AUTHENTICATION_FAILED'
  | 'SC_INVALID_SIGNATURE'
  | 'SC_INVALID_TOKEN'
  | 'SC_INVALID_GAME'
  | 'SC_USER_NOT_EXISTS'
  | 'SC_USER_DISABLED'
  | 'SC_WRONG_CURRENCY'
  | 'SC_CURRENCY_NOT_SUPPORTED'
  | 'SC_INSUFFICIENT_FUNDS'
  | 'SC_TRANSACTION_DUPLICATED'
  | 'SC_TRANSACTION_NOT_EXISTS'
  | 'SC_TRANSACTION_STILL_PROCESSING'
  | 'SC_OPERATOR_TIMEOUT'
  | 'SC_UNDER_MAINTENANCE'
  | 'SC_GAME_DISABLED'
  | 'SC_RATE_LIMITED';

export const StatusCode: Readonly<Record<OperatorStatusCode, OperatorStatusCode>>;

export function isRetryableStatus(status: string): boolean;
export function signBody(rawBody: Buffer | Uint8Array | string, hmacSecret: string): string;
export function verifySignature(rawBody: Buffer | Uint8Array | string, signatureHeader: string | null | undefined, hmacSecret: string): boolean;
export function verifyWebhookHeaders(
  apiKeyHeader: string | null | undefined,
  signatureHeader: string | null | undefined,
  rawBody: Buffer | Uint8Array | string,
  expectedApiKey: string,
  hmacSecret: string,
): OperatorStatusCode;

export function decimalToLedgerUnits(raw: string | number, displayExponent: number, opts?: { allowNegative?: boolean }): bigint;
export function ledgerUnitsToDecimal(amount: bigint | number | string, displayExponent: number): string;

export function encodeTupleFingerprint(domain: string, fields: ReadonlyArray<string | number>): string;
export function betFingerprint(payload: Record<string, unknown>): string;
export function betResultFingerprint(payload: Record<string, unknown>): string;
export function rollbackFingerprint(payload: Record<string, unknown>): string;
export function adjustmentFingerprint(payload: Record<string, unknown>): string;

export class BaccaratSdkError extends Error {
  readonly code: string;
  constructor(message: string, code?: string);
}

export class BaccaratApiError extends BaccaratSdkError {
  readonly traceId: string;
  readonly status: OperatorStatusCode | string;
  readonly validation?: Record<string, string>;
  readonly httpStatus: number;
  constructor(opts: {
    traceId?: string;
    status: OperatorStatusCode | string;
    message?: string;
    validation?: Record<string, string>;
    httpStatus?: number;
  });
  isRetryable(): boolean;
}

export class BaccaratTransportError extends BaccaratSdkError {
  constructor(message: string, code?: OperatorStatusCode | string);
}

export class Config {
  readonly apiKey: string;
  readonly hmacSecret: string;
  readonly environment: 'SANDBOX' | 'PRODUCTION';
  readonly baseUrl: string;
  readonly timeoutMs: number;
  readonly sendTimestamp: boolean;
  constructor(opts: {
    apiKey: string;
    hmacSecret: string;
    environment?: 'SANDBOX' | 'PRODUCTION';
    baseUrl?: string;
    timeoutMs?: number;
    sendTimestamp?: boolean;
  });
}

export interface TableCatalogItem {
  tableId: string;
  gameCode: string;
  tableName: string;
  gameType: string;
  currency: string;
  status: string;
  minBet: string | null;
  maxBet: string | null;
  chipUnit: string | null;
  languages: string[];
  platforms: string[];
  coverImageUrl: string | null;
  [key: string]: unknown;
}

export class Client {
  readonly config: Config;
  constructor(config: Config | ConstructorParameters<typeof Config>[0], opts?: { transport?: Function });
  postSigned(routePath: string, bodyObj?: Record<string, unknown>): Promise<{
    traceId: string;
    status: 'SC_OK';
    data: unknown;
  }>;
  ping(params?: { traceId?: string }): Promise<{
    traceId: string;
    status: 'SC_OK';
    data: {
      operatorId: string;
      operatorName: string;
      callerIp: string | null;
      callbackConfigured: boolean;
      serverTime: number;
    };
  }>;
  createGameUrl(params: {
    traceId?: string;
    username: string;
    tableId?: string | null;
    entryMode?: 'lobby' | 'table' | 'table_locked' | string | null;
    language?: string | null;
    platform: string;
    currency: string;
    lobbyUrl: string;
    ipAddress: string;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: { gameUrl: string; token: string; entryMode?: string } }>;
  listTables(params?: {
    traceId?: string;
    currency?: string | null;
    pageNo?: number | null;
    pageSize?: number | null;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: { tables: TableCatalogItem[]; pageNo: number; pageSize: number; total: number } }>;
  terminateSessions(params?: {
    traceId?: string;
    username?: string | null;
    scope?: 'USER' | 'ALL' | string | null;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: { scope?: string; username?: string | null; terminatedSessions: number; revokedLaunchTokens: number } }>;
  updatePlayerStatus(params: {
    traceId?: string;
    username: string;
    action?: 'GET' | 'SET' | string | null;
    status?: 'ACTIVE' | 'DISABLED' | string | null;
    bettingEnabled?: boolean | null;
    resetPnlWindow?: boolean | null;
    reason?: string | null;
  }): Promise<{
    traceId: string;
    status: 'SC_OK';
    data: {
      username: string;
      status: 'ACTIVE' | 'DISABLED';
      bettingEnabled: boolean;
      rgRestricted: boolean;
      statusReason: string | null;
      revokedSessions: number;
      revokedLaunchTokens: number;
    };
  }>;
  updatePlayerLimits(params: {
    traceId?: string;
    username: string;
    currency: string;
    action?: 'GET' | 'SET' | 'CLEAR' | string | null;
    minBet?: string | null;
    maxBet?: string | null;
    maxTableRound?: string | null;
    maxUserDay?: string | null;
    maxLossPerDay?: string | null;
    customChips?: string[] | null;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: Record<string, unknown> }>;
  listTransactions(params: {
    traceId?: string;
    fromTime: number;
    toTime: number;
    timeType?: 'SETTLE_TIME' | 'BET_TIME' | string | null;
    status?: number | string | null;
    username?: string | null;
    tableId?: string | null;
    roundId?: string | null;
    pageNo?: number | null;
    pageSize?: number | null;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: { transactions: Array<Record<string, unknown>>; pageNo: number; pageSize: number; total: number } }>;
  listAllTransactions(params: {
    fromTime: number;
    toTime: number;
    pageSize?: number;
    rateLimitMaxRetries?: number;
    rateLimitBackoffMs?: number;
    timeType?: 'SETTLE_TIME' | 'BET_TIME' | string | null;
    status?: number | string | null;
    username?: string | null;
    tableId?: string | null;
    roundId?: string | null;
    [key: string]: unknown;
  }): Promise<Array<Record<string, unknown>>>;
  getTransactionDetail(params: {
    traceId?: string;
    betId: string;
    fromTime?: number;
    toTime?: number;
    language?: string | null;
    detailUrlTtlSec?: number | null;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: Record<string, unknown> }>;
  listUnsettledTransactions(params?: {
    traceId?: string;
    fromTime?: number;
    toTime?: number;
    username?: string | null;
    tableId?: string | null;
    pageNo?: number | null;
    pageSize?: number | null;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: Record<string, unknown> }>;
  getWalletTransactionStatus(params: {
    traceId?: string;
    transactionId?: string | null;
    betId?: string | null;
    username?: string | null;
    fromTime?: number;
    toTime?: number;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: Record<string, unknown> }>;
}

export type WalletOkResponse = {
  traceId: string;
  status: 'SC_OK';
  data: {
    username: string;
    currency: string;
    balance: string;
    timestamp: number;
  };
};

export type WalletErrorResponse = {
  traceId: string;
  status: OperatorStatusCode | string;
  message?: string;
};

export type WalletResponse = WalletOkResponse | WalletErrorResponse | Record<string, unknown>;

export function walletOk(
  traceId: string,
  username: string,
  currency: string,
  balance: string,
  timestamp?: number,
): WalletOkResponse;

export function walletError(
  traceId: string,
  status: OperatorStatusCode | string,
  message?: string,
): WalletErrorResponse;

export interface WalletHandler {
  onBalance(req: Record<string, unknown>): Promise<WalletResponse> | WalletResponse;
  onBet(req: Record<string, unknown>): Promise<WalletResponse> | WalletResponse;
  onBetResult(req: Record<string, unknown>): Promise<WalletResponse> | WalletResponse;
  onRollback(req: Record<string, unknown>): Promise<WalletResponse> | WalletResponse;
  onAdjustment?(req: Record<string, unknown>): Promise<WalletResponse> | WalletResponse;
}

export class InMemoryWallet implements WalletHandler {
  constructor(initialAccounts?: Record<string, { currency: string; balance: string; exponent?: number; tokens?: string[]; disabled?: boolean }>);
  registerToken(username: string, token: string): void;
  setDisabled(username: string, disabled: boolean): void;
  onBalance(req: Record<string, unknown>): Promise<WalletResponse>;
  onBet(req: Record<string, unknown>): Promise<WalletResponse>;
  onBetResult(req: Record<string, unknown>): Promise<WalletResponse>;
  onRollback(req: Record<string, unknown>): Promise<WalletResponse>;
  onAdjustment(req: Record<string, unknown>): Promise<WalletResponse>;
}

export class WebhookDispatcher {
  constructor(config: Config | { apiKey: string; hmacSecret: string; environment?: 'SANDBOX' | 'PRODUCTION'; baseUrl?: string }, walletHandler: WalletHandler);
  handle(
    routePath: string,
    apiKeyHeader: string | null | undefined,
    signatureHeader: string | null | undefined,
    rawBody: Buffer | Uint8Array | string,
  ): Promise<{ statusCode: number; body: WalletResponse }>;
}

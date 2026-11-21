// SPDX-License-Identifier: MIT
export const SANDBOX_BASE_URL: string;
export const MAX_DETAIL_WINDOW_MS: number;
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
  | 'SC_GAME_DISABLED';

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

export class BaccaratSdkError extends Error {
  readonly code: string;
  constructor(message: string, code?: string);
}

export class BaccaratApiError extends BaccaratSdkError {
  readonly traceId: string;
  readonly status: OperatorStatusCode | string;
  readonly validation?: Record<string, string>;
  readonly httpStatus: number;
  isRetryable(): boolean;
}

export class Config {
  readonly apiKey: string;
  readonly hmacSecret: string;
  readonly environment: 'SANDBOX' | 'PRODUCTION';
  readonly baseUrl: string;
  readonly timeoutMs: number;
  constructor(opts: {
    apiKey: string;
    hmacSecret: string;
    environment?: 'SANDBOX' | 'PRODUCTION';
    baseUrl?: string;
    timeoutMs?: number;
  });
}

export class Client {
  readonly config: Config;
  constructor(config: Config | ConstructorParameters<typeof Config>[0], opts?: { transport?: Function });
  createGameUrl(params: {
    traceId?: string;
    username: string;
    tableId: string;
    language?: string | null;
    platform: string;
    currency: string;
    lobbyUrl: string;
    ipAddress: string;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: { gameUrl: string; token: string } }>;
  listTables(params?: {
    traceId?: string;
    currency?: string | null;
    pageNo?: number | null;
    pageSize?: number | null;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: { tables: Array<Record<string, unknown>>; pageNo: number; pageSize: number; total: number } }>;
  terminateSessions(params: {
    traceId?: string;
    username: string;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: { username: string; terminatedSessions: number; revokedLaunchTokens: number } }>;
  listTransactions(params: {
    traceId?: string;
    fromTime: number;
    toTime: number;
    pageNo?: number | null;
    pageSize?: number | null;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: { transactions: Array<Record<string, unknown>>; pageNo: number; pageSize: number; total: number } }>;
  listAllTransactions(params: { fromTime: number; toTime: number; pageSize?: number }): Promise<Array<Record<string, unknown>>>;
  getTransactionDetail(params: {
    traceId?: string;
    betId: string;
    fromTime: number;
    toTime: number;
  }): Promise<{ traceId: string; status: 'SC_OK'; data: Record<string, unknown> }>;
}

export interface WalletHandler {
  onBalance(req: Record<string, unknown>): Promise<Record<string, unknown>> | Record<string, unknown>;
  onBet(req: Record<string, unknown>): Promise<Record<string, unknown>> | Record<string, unknown>;
  onBetResult(req: Record<string, unknown>): Promise<Record<string, unknown>> | Record<string, unknown>;
  onRollback(req: Record<string, unknown>): Promise<Record<string, unknown>> | Record<string, unknown>;
}

export class InMemoryWallet implements WalletHandler {
  constructor(initialAccounts?: Record<string, { currency: string; balance: string; exponent?: number; tokens?: string[]; disabled?: boolean }>);
  registerToken(username: string, token: string): void;
  setDisabled(username: string, disabled: boolean): void;
  onBalance(req: Record<string, unknown>): Promise<Record<string, unknown>>;
  onBet(req: Record<string, unknown>): Promise<Record<string, unknown>>;
  onBetResult(req: Record<string, unknown>): Promise<Record<string, unknown>>;
  onRollback(req: Record<string, unknown>): Promise<Record<string, unknown>>;
}

export class WebhookDispatcher {
  constructor(config: Config | ConstructorParameters<typeof Config>[0], walletHandler: WalletHandler);
  handle(
    routePath: string,
    apiKeyHeader: string | undefined,
    signatureHeader: string | undefined,
    rawBody: Buffer | Uint8Array | string,
  ): Promise<{ statusCode: number; body: Record<string, unknown> }>;
}

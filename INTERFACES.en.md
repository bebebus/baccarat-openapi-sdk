> [中文](./INTERFACES.md) | English

# B2B Operator Seamless Wallet Endpoints & Status Codes (v1.5.6)

Interactive Explorer & OpenAPI 3.1 Spec: `https://openapi.lt.cniia.cloud`

## 1. Inbound S2S Endpoints (Merchant -> Platform)

All endpoints accept `POST` JSON signed with `X-API-Key` and `X-Signature` (plus optional `X-Timestamp` anti-replay within `±300s`), returning `{ traceId, status: "SC_OK", data }` on `HTTP 200` or `{ traceId, status: "SC_*", message, validation? }` on error (`HTTP 200` by default; `POST /operator/v1/player/status` additionally returns structured JSON error envelopes with `HTTP 403` `SC_USER_DISABLED` / `PLATFORM_RISK_LOCKED`, `HTTP 409` `SC_INVALID_REQUEST` / `PNL_CAP_BREACHED_RESET_REQUIRED`, or `HTTP 400` `SC_INVALID_REQUEST`, all parsed into typed API errors across all 7 SDKs):

1. **`POST /operator/v1/ping`** (`ping` / `ping` / `Ping`): Authenticated credential & IP allowlist self-test (`operatorId, operatorName, callerIp, callbackConfigured, serverTime`).
2. **`POST /operator/v1/game/tables`** (`listTables` / `list_tables` / `ListTables`): Lists permitted live tables with operating `currency`, dynamic `minBet`/`maxBet`/`chipUnit`, `status`, and `coverImageUrl`.
3. **`POST /operator/v1/game/url`** (`createGameUrl` / `create_game_url` / `CreateGameUrl`): Issues a single-use launch URL (`gameUrl`) and 53-char `b2bt_<48hex>` wallet token (`entryMode`: `lobby | table | table_locked`).
4. **`POST /operator/v1/game/terminate`** (`terminateSessions` / `terminate_sessions` / `TerminateSessions`): Revokes active sessions and unused launch tokens (`scope`: `USER | ALL`).
5. **`POST /operator/v1/player/status`** (`updatePlayerStatus` / `update_player_status` / `UpdatePlayerStatus`): Queries (`GET`) or updates (`SET`) `ACTIVE | DISABLED` login status, view-only `bettingEnabled` switch, and atomic `resetPnlWindow: true` PnL auto-stop reset (`revokedSessions`, `rgRestricted`, `statusReason`; HTTP `403` on platform risk lock, HTTP `409` when `resetPnlWindow: true` is required).
6. **`POST /operator/v1/player/limits`** (`updatePlayerLimits` / `update_player_limits` / `UpdatePlayerLimits`): Queries (`GET`), sets (`SET`), or clears (`CLEAR`) per-player dynamic bet/loss limits & chips bounded beneath the operator risk template.
7. **`POST /operator/v1/transaction/list`** (`listTransactions` / `list_transactions` / `ListTransactions` + `listAllTransactions` auto-paginator with `SC_RATE_LIMITED` backoff; for optional filters & custom retry backoff use `ListAllTransactionsWithOptions` in Go and `list_all_transactions_with_options` in Rust): Paginated settled & voided ticket feed (`SETTLE_TIME` or `BET_TIME`; `fromTime`/`toTime` non-nullable integer epoch ms; rate limit `120 req / 60s` sliding window; `VOID` rows have `vendorSettleTime: null`).
8. **`POST /operator/v1/transaction/detail`** (`getTransactionDetail` / `get_transaction_detail` / `GetTransactionDetail`): Single-ticket lookup (omit both `fromTime`/`toTime` for trailing 7 days; explicit `null` rejected; supports `language` and `detailUrlTtlSec`) with revealed cards (`BaccaratRevealedCard.suit` numeric `1..4`: `1=♠, 2=♥, 3=♦, 4=♣`), `detailUrl`, and `adjustments[]`.
9. **`POST /operator/v1/transaction/unsettled`** (`listUnsettledTransactions` / `list_unsettled_transactions` / `ListUnsettledTransactions`): Open `ACCEPTED` / `HELD` exposure feed (`fromTime`/`toTime` non-nullable integers; rate limit `120 req / 60s` sliding window).
10. **`POST /operator/v1/wallet/transaction-status`** (`getWalletTransactionStatus` / `get_wallet_transaction_status` / `GetWalletTransactionStatus`): Real-time outbound callback delivery & retry inspection by `transactionId`, `betId`, or `username` (with `<= 24h` non-nullable `[fromTime, toTime]` window). Returns at most **200 rows** ordered by `createdAt ASC` (no pagination; narrow window if 200 rows returned).

## 2. Outbound Seamless Wallet Webhooks (Platform -> Merchant `{callbackUrl}/wallet/*`)

Every SDK ships a framework-agnostic `WebhookDispatcher` and `InMemoryWallet` reference store handling:

1. **`POST /wallet/balance`** — Read-only balance check (`SC_OK` + `data.balance`).
2. **`POST /wallet/bet`** — Idempotent stake deduction by `transactionId = bet_<32hex>`.
3. **`POST /wallet/bet_result`** — Per-ticket settlement by `transactionId = stl_<32hex>` (`WIN` = stake + netPayout; Tie `PUSH` also sends `resultType = "WIN"` with `winAmount = betAmount`, `winLoss = "0.00"` or `"0"` for 0-decimal currencies like `JPY`, `effectiveTurnover = "0.00"` / `"0"`; `LOSE` = `"0.00"` / `"0"` — **never compare zero with `=== "0.00"`**; in multi-bet rounds **`isEndRound: 1` is sent on EVERY ticket** so never finalize round state on the first ticket; honor settled tickets even if player session expired).
4. **`POST /wallet/rollback`** — Void/late-close refund by `transactionId = rb_<betId>` or `late_<betTxId>` (returns `SC_TRANSACTION_NOT_EXISTS` empty-success when original `betId` was never debited).
5. **`POST /wallet/adjustment`** — Post-settlement recalculation or appeal delta adjustment by `transactionId = adj_<ref>` (`CREDIT` or `DEBIT`; returns `SC_INSUFFICIENT_FUNDS` on `DEBIT` shortfall without infinite retries).

> **4 Critical Production Webhook Invariants**:
> 1. **4-way concurrent delivery (NOT serialized per player)**: The platform dispatches up to 4 concurrent `/wallet/*` callbacks per operator and does not serialize requests per player. Guard balance updates with per-player DB row locks (`SELECT ... FOR UPDATE`) or atomic `UPDATE ... SET balance = balance + delta` plus `UNIQUE(transaction_id)`.
> 2. **`isEndRound: 1` on EVERY ticket in multi-bet rounds**: Do not finalize or close round-level state on the first `isEndRound: 1` callback; settle strictly per `betId` / `transactionId`.
> 3. **Terminal HTTP/JSON traps & `~5.07h` retry horizon (1 initial + 12 auto-retries)**: Returning `HTTP 200` with a non-JSON body, or a non-2xx JSON response without a transient `SC_*` status, immediately parks `/wallet/bet_result` winning tickets in `HELD` with **0 retries**. All 7 SDK `WebhookDispatcher` implementations automatically convert unexpected runtime/DB exceptions (e.g. Postgres `40P01` deadlocks) into retryable `SC_OPERATOR_TIMEOUT` with a sanitized message.
> 4. **0-decimal currencies format zero as `"0"`**: Currencies such as `JPY`, `KRW`, and `VND` emit `"0"` instead of `"0.00"`; compare amounts using exact decimal / ledger-unit math, never `=== "0.00"`.

## 3. Retryability Rule

Among all 18 `SC_*` status codes, **`SC_TRANSACTION_STILL_PROCESSING`**, **`SC_OPERATOR_TIMEOUT`**, and **`SC_RATE_LIMITED`** are transient/retryable (`isRetryable === true`), and wallet callbacks MUST be retried with the **exact same `transactionId`**. On outbound settlement/rollback/adjustment webhooks, `SC_UNDER_MAINTENANCE` is also retried automatically by the platform up to 12 attempts before dead-lettering.

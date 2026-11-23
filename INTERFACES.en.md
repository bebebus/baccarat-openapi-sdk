> [中文](./INTERFACES.md) | English

# B2B Operator Seamless Wallet Endpoints & Status Codes (v1.4.0)

Interactive Explorer & OpenAPI 3.1 Spec: `https://openapi.lt.cniia.cloud`

## 1. Inbound S2S Endpoints (Merchant -> Platform)

All endpoints accept `POST` JSON signed with `X-API-Key` and `X-Signature`, returning `HTTP 200` with `{ traceId, status: "SC_OK", data }` or `{ traceId, status: "SC_*", message, validation? }`:

1. **`POST /operator/v1/ping`** (`ping` / `ping` / `Ping`): Authenticated credential & IP allowlist self-test.
2. **`POST /operator/v1/game/tables`** (`listTables` / `list_tables` / `ListTables`): Lists permitted live tables with operating `currency`, dynamic `minBet`/`maxBet`/`chipUnit`, `status`, and `coverImageUrl`.
3. **`POST /operator/v1/game/url`** (`createGameUrl` / `create_game_url` / `CreateGameUrl`): Issues a single-use launch URL (`gameUrl`) and 53-char `b2bt_<48hex>` wallet token (`entryMode`: `lobby | table | table_locked`).
4. **`POST /operator/v1/game/terminate`** (`terminateSessions` / `terminate_sessions` / `TerminateSessions`): Revokes active sessions and unused launch tokens (`scope`: `USER | ALL`).
5. **`POST /operator/v1/player/status`** (`updatePlayerStatus` / `update_player_status` / `UpdatePlayerStatus`): Updates `ACTIVE | SUSPENDED` status and view-only `bettingEnabled` switch.
6. **`POST /operator/v1/player/limits`** (`updatePlayerLimits` / `update_player_limits` / `UpdatePlayerLimits`): Configures per-player dynamic bet/loss limits & chips bounded beneath the operator risk template.
7. **`POST /operator/v1/transaction/list`** (`listTransactions` / `list_transactions` / `ListTransactions` + `listAllTransactions` auto-paginator): Paginated settled & voided ticket feed (`SETTLE_TIME` or `BET_TIME`).
8. **`POST /operator/v1/transaction/detail`** (`getTransactionDetail` / `get_transaction_detail` / `GetTransactionDetail`): Single-ticket lookup (defaults to trailing 7 days when `fromTime`/`toTime` omitted) with revealed cards, `detailUrl`, and `adjustments`.
9. **`POST /operator/v1/transaction/unsettled`** (`listUnsettledTransactions` / `list_unsettled_transactions` / `ListUnsettledTransactions`): Open `ACCEPTED` / `HELD` exposure feed.
10. **`POST /operator/v1/wallet/transaction-status`** (`getWalletTransactionStatus` / `get_wallet_transaction_status` / `GetWalletTransactionStatus`): Real-time outbound callback delivery & retry inspection.

## 2. Outbound Seamless Wallet Webhooks (Platform -> Merchant `{callbackUrl}/wallet/*`)

Every SDK ships a framework-agnostic `WebhookDispatcher` and `InMemoryWallet` reference store handling:

1. **`POST /wallet/balance`** — Read-only balance check (`SC_OK` + `data.balance`).
2. **`POST /wallet/bet`** — Idempotent stake deduction by `transactionId = bet_<32hex>`.
3. **`POST /wallet/bet_result`** — Per-ticket settlement by `transactionId = stl_<32hex>` (`WIN` = stake + netPayout, `PUSH` = stake with `winLoss = "0.00"`, `LOSE` = `"0.00"`; honor settled tickets even if player session expired).
4. **`POST /wallet/rollback`** — Void/late-close refund by `transactionId = rb_<betId>` or `late_<betTxId>` (returns `SC_TRANSACTION_NOT_EXISTS` empty-success when original `betId` was never debited).
5. **`POST /wallet/adjustment`** — Post-settlement recalculation or appeal delta adjustment by `transactionId = adj_<ref>` (`CREDIT` or `DEBIT`; returns `SC_INSUFFICIENT_FUNDS` on `DEBIT` shortfall without infinite retries).

## 3. Retryability Rule

Among all 18 `SC_*` status codes, **`SC_TRANSACTION_STILL_PROCESSING`**, **`SC_OPERATOR_TIMEOUT`**, and **`SC_RATE_LIMITED`** are transient/retryable (`isRetryable === true`), and wallet callbacks MUST be retried with the **exact same `transactionId`**.

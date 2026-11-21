> [中文](./INTERFACES.md) | English

# B2B Operator Seamless Wallet Endpoints & Status Codes (v1.2.0)

Interactive Explorer & OpenAPI 3.1 Spec: `https://openapi.lt.cniia.cloud`

## 1. Inbound S2S Endpoints (Merchant -> Platform)

All endpoints accept `POST` JSON signed with `X-API-Key` and `X-Signature`, returning `HTTP 200` with `{ traceId, status: "SC_OK", data }` or `{ traceId, status: "SC_*", message, validation? }`:

1. **`POST /operator/v1/game/url`** (`createGameUrl` / `create_game_url` / `CreateGameUrl`): Issues a single-use launch URL (`gameUrl`) and 53-char `b2bt_<48hex>` wallet token after a live `/wallet/balance` probe.
2. **`POST /operator/v1/game/tables`** (`listTables` / `list_tables` / `ListTables`): Lists permitted live tables with operating `currency`, dynamic `minBet`/`maxBet`/`chipUnit`, `status` (`OPEN` | `MAINTENANCE`), and `coverImageUrl`.
3. **`POST /operator/v1/game/terminate`** (`terminateSessions` / `terminate_sessions` / `TerminateSessions`): Revokes active Web/WS sessions and unused launch tokens for `username`.
4. **`POST /operator/v1/transaction/list`** (`listTransactions` / `list_transactions` / `ListTransactions` + `listAllTransactions` auto-paginator): Paginated settled ticket feed (`status = 1`: `WIN` / `LOSE` / `PUSH`) by `settledAt` in `[fromTime, toTime]`.
5. **`POST /operator/v1/transaction/detail`** (`getTransactionDetail` / `get_transaction_detail` / `GetTransactionDetail`): Single-ticket lookup within `<= 7 days` (`604800000` ms) across all statuses (`0/1/2/3`) including hardware-verified `roundResult`.

## 2. Outbound Seamless Wallet Webhooks (Platform -> Merchant `{callbackUrl}/wallet/*`)

Every SDK ships a framework-agnostic `WebhookDispatcher` and `InMemoryWallet` reference store handling:

1. **`POST /wallet/balance`** — Read-only balance check (`SC_OK` + `data.balance`).
2. **`POST /wallet/bet`** — Idempotent stake deduction by `transactionId = bet_<32hex>`.
3. **`POST /wallet/bet_result`** — Per-ticket settlement by `transactionId = stl_<32hex>` (`WIN` = stake + netPayout, `PUSH` = stake with `winLoss = "0.00"`, `LOSE` = `"0.00"`; honor settled tickets even if player session expired).
4. **`POST /wallet/rollback`** — Void/late-close refund by `transactionId = rb_<betId>` or `late_<betTxId>` (returns `SC_TRANSACTION_NOT_EXISTS` empty-success when original `betId` was never debited).

## 3. Retryability Rule

Among all 17 `SC_*` status codes, only **`SC_TRANSACTION_STILL_PROCESSING`** and **`SC_OPERATOR_TIMEOUT`** are transient/retryable (`isRetryable === true`), and MUST be retried with the **exact same `transactionId`**.

> 中文 | [English](./INTERFACES.en.md)

# B2B 运营商单一无缝钱包接口与状态码字典（v1.5.1）

在线交互式文档与 OpenAPI 3.1 规范：`https://openapi.lt.cniia.cloud`

## 1. 入站 S2S 接口（商户 → 平台，Base URL：`https://api.lt.cniia.cloud` 或专属正式网关）

所有接口均为 `POST` JSON 请求，常规业务响应返回 `HTTP 200` 结构化信封；其中 `POST /operator/v1/player/status` 针对风控拦截场景额外返回同结构的非 200 HTTP 状态码（`HTTP 403` `SC_USER_DISABLED` / `PLATFORM_RISK_LOCKED`、`HTTP 409` `SC_INVALID_REQUEST` / `PNL_CAP_BREACHED_RESET_REQUIRED`、`HTTP 400` `SC_INVALID_REQUEST`），7 套 SDK 均自动解析为带 `httpStatus` / `status` / `message` 的 API 异常：
- 成功：`{ "traceId": "...", "status": "SC_OK", "data": { ... } }`
- 业务/协议拒绝：`{ "traceId": "...", "status": "SC_*", "message": "...", "validation"?: { ... } }`

| SDK 方法名（JS/Java/PHP/C++ 驼峰 \| Python/Rust 蛇形 \| Go 首字母大写） | HTTP 路径 | 必填入参 | 可选入参 | 返回 `data` 核心字段 |
| --- | --- | --- | --- | --- |
| `ping` / `ping` / `Ping` | `POST /operator/v1/ping` | —（`traceId` 自动补全） | — | `operatorId, operatorName, callerIp, callbackConfigured, serverTime` |
| `listTables` / `list_tables` / `ListTables` | `POST /operator/v1/game/tables` | —（`traceId` 自动补全） | `currency, pageNo (默认 1), pageSize (1..200, 默认 50)` | `tables[], pageNo, pageSize, total` |
| `createGameUrl` / `create_game_url` / `CreateGameUrl` | `POST /operator/v1/game/url` | `username, platform ("web"\|"H5"), currency, lobbyUrl, ipAddress` | `tableId, entryMode ("lobby"\|"table"\|"table_locked"), language (默认 "en")` | `gameUrl, token (b2bt_<48hex>), entryMode` |
| `terminateSessions` / `terminate_sessions` / `TerminateSessions` | `POST /operator/v1/game/terminate` | — | `username, scope ("USER"\|"ALL")` | `scope, username, terminatedSessions, revokedLaunchTokens` |
| `updatePlayerStatus` / `update_player_status` / `UpdatePlayerStatus` | `POST /operator/v1/player/status` | `username` | `action ("GET"\|"SET"), status ("ACTIVE"\|"DISABLED"), bettingEnabled (boolean), resetPnlWindow (boolean), reason` | `username, status, bettingEnabled, rgRestricted, statusReason, revokedSessions, revokedLaunchTokens` |
| `updatePlayerLimits` / `update_player_limits` / `UpdatePlayerLimits` | `POST /operator/v1/player/limits` | `username, currency` | `action ("GET"\|"SET"\|"CLEAR"), minBet, maxBet, maxTableRound, maxUserDay, maxLossPerDay, customChips[]` | `username, currency, cleared, hasOverride, minBet..customChips` |
| `listTransactions` / `list_transactions` / `ListTransactions` | `POST /operator/v1/transaction/list` | `fromTime, toTime`（非负整数毫秒，`toTime >= fromTime`） | `timeType, status, username, tableId, roundId, pageNo, pageSize` | `transactions[], pageNo, pageSize, total` |
| `getTransactionDetail` / `get_transaction_detail` / `GetTransactionDetail` | `POST /operator/v1/transaction/detail` | `betId` | `fromTime, toTime`（省略默认近 7 天；指定时跨度 `<= 604800000` ms）, `language, detailUrlTtlSec` | 对账字段 + `roundResult` + `detailUrl`（含花色牌面与 `opadj` 明细）+ `adjustments[]` |
| `listUnsettledTransactions` / `list_unsettled_transactions` / `ListUnsettledTransactions` | `POST /operator/v1/transaction/unsettled` | — | `fromTime, toTime, username, tableId, pageNo, pageSize` | `transactions[], pageNo, pageSize, total` |
| `getWalletTransactionStatus` / `get_wallet_transaction_status` / `GetWalletTransactionStatus` | `POST /operator/v1/wallet/transaction-status` | `transactionId`、`betId` 或 `username` 三选一 | `fromTime, toTime`（仅传 `username` 时必填且跨度 `<= 86400000` ms 即 24 小时） | `transactions[]`（出站回调实时状态、重试计数与牌局状态） |

此外每套 SDK 均提供 `listAllTransactions` / `list_all_transactions` / `ListAllTransactions` 自动翻页拉取器，按 `(settledAt ASC, ticketId ASC)` 拉齐指定时间区间内的全部已结算对账流水。

## 2. 出站无缝钱包回调（平台 → 商户 `{callbackUrl}/wallet/*`）

7 套 SDK 均内置 `WebhookDispatcher`（验签 + JSON 解析 + 路由 + 异常兜底）及 `InMemoryWallet` 参考幂等引擎：

| 回调路径 | 幂等主键 `transactionId` | 商户钱包动作与特殊约定 | 成功响应 |
| --- | --- | --- | --- |
| `POST /wallet/balance` | 只读查询（无 `transactionId`） | 核对 `token` 与 `currency`，不改余额 | `SC_OK` + `data: { balance, currency, username, timestamp }` |
| `POST /wallet/bet` | `bet_<32hex>` | 按 `transactionId` 幂等扣除 `amount`；余额不足回 `SC_INSUFFICIENT_FUNDS` | `SC_OK` + 最新 `balance` |
| `POST /wallet/bet_result` | `stl_<32hex>` | 逐票结算加款 `winAmount`（`WIN` 为本金+净赢，和局 `PUSH` 为原注本金，`LOSE` 为 `"0.00"`）；**即使玩家会话已过期/被踢也必须放行已扣款注单入账** | `SC_OK` + 最新 `balance` |
| `POST /wallet/rollback` | `rb_<betId>` 或 `late_<betTxId>` | 冲回原注 `amount`；**若原 `betId` 在商户侧从未扣款成功，返回 `SC_TRANSACTION_NOT_EXISTS` 即按空成功收敛** | `SC_OK` + 最新 `balance`，或 `SC_TRANSACTION_NOT_EXISTS` |
| `POST /wallet/adjustment` | `adj_<ref>` | 赛后错牌重算或四眼申诉裁决差额调账（`CREDIT` 加款 / `DEBIT` 扣款）；`DEBIT` 余额不足回 `SC_INSUFFICIENT_FUNDS` 终态失败不死循环 | `SC_OK` + 最新 `balance` |

## 3. 18 项标准状态码（`SC_*`）

| 状态码 | 可同键重试（`isRetryable`） | 说明 |
| --- | --- | --- |
| `SC_OK` | `false` | 成功，或同键同业务内容幂等重放 |
| `SC_INVALID_REQUEST` | `false` | 坏参/缺参/窗口超 7 天/回调缺少 `data.balance` |
| `SC_AUTHENTICATION_FAILED` | `false` | `X-API-Key` 缺失/无效/停用/IP 不在白名单/未配 `callbackUrl` |
| `SC_INVALID_SIGNATURE` | `false` | `X-Signature` 原始字节 HMAC-SHA256 验签失败 |
| `SC_INVALID_TOKEN` | `false` | `b2bt_` 令牌无效（注意：`bet_result`/`rollback` 严禁因会话超时返回此码） |
| `SC_INVALID_GAME` | `false` | `tableId` 不存在、未初始化或未授权 |
| `SC_USER_NOT_EXISTS` | `false` | 用户从未映射（如未调 `game/url` 直接调 `terminate`） |
| `SC_USER_DISABLED` | `false` | 玩家停用或命中自我排除/冷静期 |
| `SC_WRONG_CURRENCY` | `false` | 请求币种与桌台币种或玩家钱包币种不一致 |
| `SC_CURRENCY_NOT_SUPPORTED` | `false` | 平台或商户未开通该币种 |
| `SC_INSUFFICIENT_FUNDS` | `false` | 玩家可用余额不足 |
| `SC_TRANSACTION_DUPLICATED` | `false` | 同一 `transactionId` 携带不同业务参数（冲突） |
| `SC_TRANSACTION_NOT_EXISTS` | `false` | `detail` 查无此单，或 `rollback` 原注单从未扣成（空成功） |
| `SC_TRANSACTION_STILL_PROCESSING` | **`true`** | 同键并发处理租约中，稍后用同一 `transactionId` 重试 |
| `SC_OPERATOR_TIMEOUT` | **`true`** | 出站调用超 8000ms 或网络/5xx 瞬态异常，原键重试 |
| `SC_UNDER_MAINTENANCE` | `false` | 桌台维护挂起或商户风控限额模板未激活 |
| `SC_GAME_DISABLED` | `false` | 游戏类型已停用 |
| `SC_RATE_LIMITED` | **`true`** | 对账或未结注单轮询超出单商户频控阈值，退避后以相同参数重试 |

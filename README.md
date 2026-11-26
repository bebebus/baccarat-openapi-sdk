> 中文 | [English](./README.en.md)

# 真人视讯百家乐 · B2B 商户对接多语言 SDK（v1.5.5）

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI_3.1-v1.5.5-635bff)](https://openapi.lt.cniia.cloud)

为接入真人视讯百家乐平台（B2B 单一无缝钱包模式，OpenAPI `v1.5.5`）的商户研发团队提供 **Node.js、Python、PHP、Go、Java、C++、Rust** 七套生产级双向对接 SDK。

- 在线契约门户与验签台：`https://openapi.lt.cniia.cloud`
- OpenAPI 3.1 规范下载：`https://openapi.lt.cniia.cloud/openapi.yaml` | `https://openapi.lt.cniia.cloud/openapi.json`
- 联调沙箱 S2S 网关：`https://api.lt.cniia.cloud`（24×7 常驻真视觉演播桌 `T-A2`、演示桌 `T-A1` / `T-A3`）

## 核心设计原则

1. **极简 / 零第三方包依赖**：
   - **Node.js / Python / PHP / Go / Java / Rust** 全部为 **零第三方运行时包依赖**（仅用语言标准库或系统原生 `libcurl`）；
   - **C++** 仅依赖标准 CMake + 系统 `OpenSSL` 与 `libcurl`（内置单头文件 RFC-8259 JSON 解析/序列化器，无需拉取任何第三方源码包）。
2. **完整双向契约闭环（10 入站 S2S + 5 出站无缝钱包回调）**：
   - **S2S 客户端**：覆盖 `/operator/v1/ping`、`/game/tables`、`/game/url`（支持大厅/进桌/锁桌 `entryMode`）、`/game/terminate`（单人或全商户 `scope`）、`/player/status`（`ACTIVE | DISABLED` 账号启停、只看不投 `bettingEnabled`、净输赢封顶原子重置 `resetPnlWindow` 与 `HTTP 403`/`409` 结构化风控拒绝解析）、`/player/limits`（受母盘口约束的动态个人限红与筹码）、`/transaction/list`（含 `VOID` 闭环与自动翻页器）、`/transaction/detail`（默认近 7 天窗口 + 亮牌牌面与调账轨迹）、`/transaction/unsettled`、`/wallet/transaction-status`（支持按 `transactionId`、`betId` 或 `username` + `<= 24h` 窗口反查）；
   - **无缝钱包回调路由与幂等防线**：内置 `WebhookDispatcher`（原始字节验签 → JSON 解析 → 5 路由分发：`balance` / `bet` / `bet_result` / `rollback` / `adjustment`）与重试安全业务指纹（自动排除重试可变字段 `traceId`、`timestamp`、`settledTime`、`memo`、`referenceNo`），附带可直接联调的 `InMemoryWallet` 参考实现（含会话超时仍放行已扣款注单结算与申诉补差、`SC_TRANSACTION_NOT_EXISTS` 空成功收敛）。
3. **跨语言逐字节黄金向量护栏**：
   七套语言单测共享并逐字节断言根目录同一份 [`test-vectors.json`](./test-vectors.json)（原始字节 UTF-8 `hmacSecret` 不做 Base64 解码、CJK/Emoji 多字节报文、高精度 `displayExponent=18` 金额换算、4 组幂等重放与冲突指纹、18 个 `SC_*` 状态码）。

## 目录结构

```text
baccarat-openapi-sdk/
├── README.md / README.en.md       # 总览与快速开始
├── SIGNING.md / SIGNING.en.md     # 原始字节 HMAC-SHA256 与幂等冲突指纹权威规范
├── INTERFACES.md / INTERFACES.en.md # 10 入站 S2S + 5 出站钱包回调 + 18 状态码字典
├── test-vectors.json              # 七语言共享标准答案测试向量
├── _tooling/
│   ├── generate-vectors.mjs       # 标准答案向量生成器
│   └── run-all-tests.sh           # 一键串行跑通全部 7 语言编译与单测
├── nodejs/                        # Node.js >= 18 (ESM, 零依赖, node:test)
├── python/                        # Python >= 3.9 (stdlib, 零依赖, unittest)
├── php/                           # PHP >= 8.1 (ext-curl/ext-json, 零依赖 autoload + PSR-4)
├── go/                            # Go >= 1.21 (stdlib, 零依赖, go test)
├── java/                          # Java >= 17 (java.net.http + BigInteger, 零依赖 javac/mvn)
├── cpp/                           # C++17 (CMake + OpenSSL + libcurl, 零第三方库, CTest)
└── rust/                          # Rust 2021 (零第三方 crate, cargo test)
```

## 七语言矩阵与验证命令

| 语言 | 目录 | 引入 / 构建方式 | 运行时外部包依赖 | 本机单测命令 |
| --- | --- | --- | --- | --- |
| **Node.js** | [`nodejs/`](./nodejs/) | 克隆仓库后直接引入 `./nodejs/src/index.js` 或本地路径 `npm install ./baccarat-openapi-sdk/nodejs` | **0**（`node:https`, `node:crypto`） | `cd nodejs && node --test` |
| **Python** | [`python/`](./python/) | `pip install "git+https://github.com/bebebus/baccarat-openapi-sdk.git@v1.5.5#subdirectory=python"` | **0**（`urllib.request`, `hmac`） | `cd python && python3 -m unittest discover -s tests -v` |
| **PHP** | [`php/`](./php/) | `require 'php/autoload.php'` 或克隆后配置 Composer `path` / PSR-4 `Bebebus\BaccaratSdk\` | **0**（`ext-curl`, `ext-json`） | `cd php && php tests/run.php` |
| **Go** | [`go/`](./go/) | `go get github.com/bebebus/baccarat-openapi-sdk/go@v1.5.5` | **0**（`net/http`, `crypto/hmac`） | `cd go && go test -v -count=1 ./...` |
| **Java** | [`java/`](./java/) | `cd java && mvn install` 或源码引入 `cloud.cniia.baccarat.sdk.*` | **0**（`java.net.http`, `javax.crypto`） | `cd java && bash run-tests.sh` |
| **C++** | [`cpp/`](./cpp/) | CMake `add_subdirectory(cpp)` 链接 `baccarat_sdk` | 系统 `OpenSSL` + `libcurl` | `cmake -S cpp -B cpp/build && cmake --build cpp/build && ctest --test-dir cpp/build --output-on-failure` |
| **Rust** | [`rust/`](./rust/) | `baccarat-openapi-sdk = { git = "https://github.com/bebebus/baccarat-openapi-sdk", tag = "v1.5.5" }` | **0 Crates**（`std` + 系统 `libcurl`） | `cd rust && cargo test` |

一键执行全仓 7 语言回归测试：

```bash
bash _tooling/run-all-tests.sh
```

## 环境约定（`SANDBOX` vs `PRODUCTION`）

- **`Environment.SANDBOX`**：默认指向联调沙箱网关 `https://api.lt.cniia.cloud`；
- **`Environment.PRODUCTION`（默认）**：**不硬编码正式网关域名**，构造 `Client` 时必须显式传入商务开通分配的 `baseUrl`（例如 `https://api.<your-assigned-host>`），否则初始化立即报错拦截，彻底杜绝生产流量误打沙箱。（纯回调服务可直接传入 `apiKey` + `hmacSecret` 构造 `WebhookDispatcher`，无需配置 `baseUrl`。）

## 生产对接 4 项强制不变量

1. **4 路并发回调（不按玩家串行）**：平台按单商户最多 4 路并发推送 `/wallet/*` 回调，同一玩家的下注/派彩可能同时抵达；商户 DB 层务必使用玩家行锁（`SELECT ... FOR UPDATE`）或原子 `UPDATE ... SET balance = balance + delta` + `UNIQUE(transaction_id)`。
2. **多注同局每张注单均带 `isEndRound: 1`**：同一局押多个注区时，每条 `/wallet/bet_result` 均携带 `isEndRound: 1`；切勿在收到第一张注单时关闭或锁定局级状态。
3. **非 JSON 200 / 无瞬态码的非 2xx JSON 立即挂起 `HELD`（0 次重试）**：返回 `HTTP 200` 非 JSON 响应体或非 2xx JSON 且未携带瞬态 `SC_*` 时，`/wallet/bet_result` 不会重试而是直接挂起 `HELD`；可重试错误按 **1 次首次 + 12 次自动重试（约 `5.07h` 重试窗口）** 退避投递。`WebhookDispatcher` 会自动将未捕获的运行时/数据库异常映射为 `SC_OPERATOR_TIMEOUT` 且不泄露原始异常信息。
4. **0 位小数币种（如 `JPY`）零值格式为 `"0"`**：切勿用 `=== "0.00"` 判断零金额，请使用 `decimalToLedgerUnits` 或精确十进制数值比较。

## 快速开始示例（Node.js）

```js
import { Client, Config, Environment, InMemoryWallet, WebhookDispatcher } from './nodejs/src/index.js';

// 1. 初始化 S2S 客户端（hmacSecret 传原始 43 字符字符串，SDK 自动按 UTF-8 字节签名）
const config = new Config({
  apiKey: process.env.B2B_API_KEY,        // "ak_..."
  hmacSecret: process.env.B2B_SECRET,     // 切勿 Base64 解码
  environment: Environment.SANDBOX,       // 生产环境请用 Environment.PRODUCTION 并显式传 baseUrl
});
const client = new Client(config);

// 2. 查询授权牌桌并签发玩家进桌 URL
const { data: { tables } } = await client.listTables({ currency: 'USD' });
if (!tables.length) {
  throw new Error('No permitted USD tables available for this operator');
}
const launch = await client.createGameUrl({
  username: 'player_9527',
  tableId: tables[0].tableId,             // 如常驻真视觉演播桌 "T-A2"
  currency: tables[0].currency,
  platform: 'H5',
  language: 'zh-CN',
  lobbyUrl: 'https://merchant.example.com/lobby',
  ipAddress: '203.0.113.42',
});
console.log('进桌链接:', launch.data.gameUrl);

// 3. 在商户回调 HTTP 路由中挂载无缝钱包分发器（传入未解析的原始请求体 Buffer/String）
const wallet = new InMemoryWallet({ player_9527: { currency: 'USD', balance: '1000.00', exponent: 2 } });
const dispatcher = new WebhookDispatcher(config, wallet);
// const { statusCode, body } = await dispatcher.handle('/wallet/bet', req.headers['x-api-key'], req.headers['x-signature'], rawBodyBuffer);
```

其余 6 种语言（Python、PHP、Go、Java、C++、Rust）的完整接入代码请查阅对应子目录下的 `README.md`。

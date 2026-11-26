# 真人视讯百家乐 B2B 商户 SDK — Node.js / TypeScript

零第三方运行时依赖（仅用 `node:https`、`node:http`、`node:crypto`），原生 ESM 并附带完整 TypeScript 类型声明（`src/index.d.ts`）。

## 安装、环境要求与测试

- Node.js >= 18
- **仅支持 ESM（`"type": "module"`）**：请在宿主项目 `package.json` 中声明 `"type": "module"` 或使用 `.mjs` 文件通过 `import` 引入；若宿主为 CommonJS（`.cjs` / 默认未设 `"type": "module"`），请使用动态 `await import('@bebebus/baccarat-openapi-sdk')`。
- 引入方式（本 SDK 通过 Git 仓库分发，未发布至 npm 公共注册表）：

```bash
git clone --branch v1.5.3 --depth 1 https://github.com/bebebus/baccarat-openapi-sdk.git
npm install ./baccarat-openapi-sdk/nodejs
```

- 单测命令：`cd nodejs && node --test`

## 快速开始

```js
import { Client, Config, Environment } from '@bebebus/baccarat-openapi-sdk';

const config = new Config({
  apiKey: process.env.B2B_API_KEY,
  hmacSecret: process.env.B2B_SECRET, // 43 字符原始字符串，SDK 直接按 UTF-8 编码签名，切勿 Base64 解码
  environment: Environment.SANDBOX,   // 正式环境请传 Environment.PRODUCTION 并指定 baseUrl
  // sendTimestamp: true,             // 可选：附加 X-Timestamp 防重放请求头（±300s）
});

const client = new Client(config);
const { data: { tables } } = await client.listTables({ currency: 'USD' });
if (!tables.length) throw new Error('No permitted USD tables');

const { data } = await client.createGameUrl({
  username: 'player_9527',
  tableId: tables[0].tableId,
  platform: 'H5',
  language: 'zh-CN',
  currency: tables[0].currency,
  lobbyUrl: 'https://merchant.example.com/lobby',
  ipAddress: '203.0.113.42',
});
console.log(data.gameUrl, data.token);
```

### Express 回调接入示例（务必在 `express.json()` 之前读取原始字节流）

> **重要**：切勿将 `express.json()` 解析后的对象传给 `dispatcher.handle(...)`（重序列化会破坏原始字节签名；SDK 也会直接拒绝普通对象入参）。请为 `/wallet/*` 路由单独注册 `express.raw({ type: '*/*' })`，或纯回调服务可直接传入 `{ apiKey, hmacSecret }`（无需填写 `baseUrl`）。生产环境请替换为持久化数据库实现的 `WalletHandler`（`InMemoryWallet` 仅用于本地联调与单测）。

```js
import express from 'express';
import { StatusCode, WebhookDispatcher } from '@bebebus/baccarat-openapi-sdk';

const app = express();

/** @type {import('@bebebus/baccarat-openapi-sdk').WalletHandler} */
const dbWallet = {
  async onBalance(req) {
    // 1. 查询数据库玩家余额（只读）
    return { traceId: req.traceId, status: StatusCode.SC_OK, data: { username: req.username, currency: req.currency, balance: '1000.00', timestamp: Date.now() } };
  },
  async onBet(req) {
    // 2. 按 transactionId 唯一索引幂等扣款（同键重放返回 SC_OK + 最新余额；冲突返回 SC_TRANSACTION_DUPLICATED）
    return { traceId: req.traceId, status: StatusCode.SC_OK, data: { username: req.username, currency: req.currency, balance: '900.00', timestamp: Date.now() } };
  },
  async onBetResult(req) {
    // 3. 按 transactionId 幂等派彩（会话过期/停用仍须放行已扣款 betId 结算）
    return { traceId: req.traceId, status: StatusCode.SC_OK, data: { username: req.username, currency: req.currency, balance: '1100.00', timestamp: Date.now() } };
  },
  async onRollback(req) {
    // 4. 按 transactionId 冲正（原 betId 从未扣成返回 SC_TRANSACTION_NOT_EXISTS）
    return { traceId: req.traceId, status: StatusCode.SC_OK, data: { username: req.username, currency: req.currency, balance: '1000.00', timestamp: Date.now() } };
  },
  async onAdjustment(req) {
    // 5. 赛后重算/申诉补差（direction: CREDIT | DEBIT，按 transactionId 幂等）
    return { traceId: req.traceId, status: StatusCode.SC_OK, data: { username: req.username, currency: req.currency, balance: '1020.00', timestamp: Date.now() } };
  },
};

const dispatcher = new WebhookDispatcher(
  { apiKey: process.env.B2B_API_KEY, hmacSecret: process.env.B2B_SECRET },
  dbWallet,
);

// 必须在全局 app.use(express.json()) 之前挂载 /wallet/*
app.post('/wallet/:action', express.raw({ type: '*/*' }), async (req, res) => {
  const { statusCode, body } = await dispatcher.handle(
    req.originalUrl,
    req.header('x-api-key'),
    req.header('x-signature'),
    req.body, // Buffer
  );
  res.status(statusCode).json(body);
});
```

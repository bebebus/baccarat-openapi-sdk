# 真人视讯百家乐 B2B 商户 SDK — Node.js / TypeScript

零第三方运行时依赖（仅用 `node:https`、`node:http`、`node:crypto`），原生 ESM 并附带完整 TypeScript 类型声明（`src/index.d.ts`）。

## 环境要求與测试

- Node.js >= 18
- 单测命令：`node --test`

## 快速开始

```js
import { Client, Config, Environment, InMemoryWallet, WebhookDispatcher } from '@bebebus/baccarat-openapi-sdk';

const config = new Config({
  apiKey: process.env.B2B_API_KEY,
  hmacSecret: process.env.B2B_SECRET, // 43 字符原始字符串，SDK 直接按 UTF-8 编码签名，切勿 Base64 解码
  environment: Environment.SANDBOX,   // 正式环境请传 Environment.PRODUCTION 并指定 baseUrl
});

const client = new Client(config);
const { data } = await client.createGameUrl({
  username: 'player_9527',
  tableId: 'T-A2',
  platform: 'H5',
  language: 'zh-CN',
  currency: 'USD',
  lobbyUrl: 'https://merchant.example.com/lobby',
  ipAddress: '203.0.113.42',
});
console.log(data.gameUrl, data.token);
```

### Express / Fastify 回调接入示例（务必读取原始字节流）

```js
// Express 示例：对 /wallet/* 路由使用 express.raw({ type: 'application/json' })
const wallet = new InMemoryWallet({ player_9527: { currency: 'USD', balance: '1000.00', exponent: 2 } });
const dispatcher = new WebhookDispatcher(config, wallet);

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

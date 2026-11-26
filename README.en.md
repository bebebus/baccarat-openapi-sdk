> [中文](./README.md) | English

# Baccarat Live Platform · Multi-Language B2B Merchant SDKs (v1.5.4)

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI_3.1-v1.5.4-635bff)](https://openapi.lt.cniia.cloud/en/)

Official bidirectional B2B Operator Seamless Wallet SDKs (`bebebus/baccarat-openapi-sdk`) for **Node.js, Python, PHP, Go, Java, C++, and Rust**, aligned 100% with OpenAPI `v1.5.4` (`https://openapi.lt.cniia.cloud/en/`).

## Design Highlights

- **Zero External Package Dependencies**: Node.js, Python, PHP, Go, Java, and Rust have **zero third-party package dependencies**; C++ uses only CMake + system `OpenSSL` and `libcurl` with a built-in single-header RFC-8259 JSON parser/serializer.
- **Full Bidirectional Coverage (10 Inbound S2S + 5 Outbound Webhooks)**:
  - **S2S Client (`/operator/v1/*`)**: `ping`, `listTables`, `createGameUrl` (with `lobby | table | table_locked` `entryMode`), `terminateSessions` (`USER | ALL` `scope`), `updatePlayerStatus` (`ACTIVE | DISABLED`, view-only `bettingEnabled`, atomic `resetPnlWindow`, and structured `HTTP 403`/`409` risk-guard errors), `updatePlayerLimits` (`GET | SET | CLEAR` dynamic per-player limits & chips bounded by operator template), `listTransactions` (+ `listAllTransactions` auto-paginator with automatic `SC_RATE_LIMITED` backoff), `getTransactionDetail`, `listUnsettledTransactions`, and `getWalletTransactionStatus` (by `transactionId`, `betId`, or `username` + `<= 24h` window, max 200 rows), plus optional `X-Timestamp` anti-replay header support.
  - **Seamless Wallet Webhook Router (`{callbackUrl}/wallet/*`)**: Raw-body HMAC-SHA256 verification before JSON parsing across `/wallet/balance`, `/wallet/bet`, `/wallet/bet_result`, `/wallet/rollback`, and `/wallet/adjustment`, retry-safe conflict fingerprinting (excluding mutable `traceId`, `timestamp`, `settledTime`, `memo`, `referenceNo` and additive `v1.3.0+` context fields), and a reference `InMemoryWallet` engine.
- **Byte-for-Byte Cross-Language Golden Vectors**: All 7 SDK test suites execute against the shared [`test-vectors.json`](./test-vectors.json).

## Language Matrix

| Language | Directory | Install / Import | External Packages | Test Command |
| --- | --- | --- | --- | --- |
| **Node.js** (>= 18) | [`nodejs/`](./nodejs/) | Clone & import `./nodejs/src/index.js` or `npm install ./baccarat-openapi-sdk/nodejs` | **0** | `cd nodejs && node --test` |
| **Python** (>= 3.9) | [`python/`](./python/) | `pip install "git+https://github.com/bebebus/baccarat-openapi-sdk.git@v1.5.4#subdirectory=python"` | **0** | `cd python && python3 -m unittest discover -s tests -v` |
| **PHP** (>= 8.1) | [`php/`](./php/) | `require 'php/autoload.php'` or Composer path repo `Bebebus\BaccaratSdk\` | **0** (`ext-curl`, `ext-json`) | `cd php && php tests/run.php` |
| **Go** (>= 1.21) | [`go/`](./go/) | `go get github.com/bebebus/baccarat-openapi-sdk/go@v1.5.4` | **0** | `cd go && go test -v -count=1 ./...` |
| **Java** (>= 17) | [`java/`](./java/) | `cd java && mvn install` or source import `cloud.cniia.baccarat.sdk.*` | **0** | `cd java && bash run-tests.sh` |
| **C++** (C++17) | [`cpp/`](./cpp/) | CMake `add_subdirectory(cpp)` link `baccarat_sdk` | System `OpenSSL` + `libcurl` | `cmake -S cpp -B cpp/build && cmake --build cpp/build && ctest --test-dir cpp/build --output-on-failure` |
| **Rust** (2021) | [`rust/`](./rust/) | `baccarat-openapi-sdk = { git = "https://github.com/bebebus/baccarat-openapi-sdk", tag = "v1.5.4" }` | **0 Crates** (`std` + system `libcurl`) | `cd rust && cargo test` |

Run all 7 test suites sequentially:

```bash
bash _tooling/run-all-tests.sh
```

## Environment Rules (`SANDBOX` vs `PRODUCTION`)

- **`Environment.SANDBOX`**: Defaults to the sandbox gateway `https://api.lt.cniia.cloud`.
- **`Environment.PRODUCTION` (default)**: Never hardcodes a production host. You MUST pass your commercially provisioned `baseUrl` explicitly when creating `Client`, preventing accidental production calls to sandbox. (Webhook-only servers can construct `WebhookDispatcher` directly with `apiKey` + `hmacSecret`.)

## Quick Start (Node.js)

```js
import { Client, Config, Environment, InMemoryWallet, WebhookDispatcher } from './nodejs/src/index.js';

// 1. Initialize S2S client (pass 43-char hmacSecret raw UTF-8 string; NEVER Base64-decode)
const config = new Config({
  apiKey: process.env.B2B_API_KEY,
  hmacSecret: process.env.B2B_SECRET,
  environment: Environment.SANDBOX,
});
const client = new Client(config);

// 2. Discover table currency & launch player URL
const { data: { tables } } = await client.listTables({ currency: 'USD' });
if (!tables.length) {
  throw new Error('No permitted USD tables available');
}
const launch = await client.createGameUrl({
  username: 'player_9527',
  tableId: tables[0].tableId,
  currency: tables[0].currency,
  platform: 'H5',
  language: 'en-US',
  lobbyUrl: 'https://merchant.example.com/lobby',
  ipAddress: '203.0.113.42',
});
console.log('Launch URL:', launch.data.gameUrl);

// 3. Mount webhook dispatcher on raw unparsed HTTP body bytes
const wallet = new InMemoryWallet({ player_9527: { currency: 'USD', balance: '1000.00', exponent: 2 } });
const dispatcher = new WebhookDispatcher(config, wallet);
// const { statusCode, body } = await dispatcher.handle('/wallet/bet', req.headers['x-api-key'], req.headers['x-signature'], rawBodyBuffer);
```

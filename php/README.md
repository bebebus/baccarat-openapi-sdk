# 真人视讯百家乐 B2B 商户 SDK — PHP 8

零第三方依赖（仅需 PHP >= 8.1 核心扩展 `ext-curl` 与 `ext-json`，内置十进制大数字符串算术，无需 `ext-bcmath`）。支持直接 `require 'autoload.php'` 或通过本地克隆配合 Composer `path` 仓库引入 `Bebebus\BaccaratSdk\`。

## 安装与单测

```bash
git clone --branch v1.6.0 --depth 1 https://github.com/bebebus/baccarat-openapi-sdk.git
cd baccarat-openapi-sdk/php && php tests/run.php
```

在项目 `composer.json` 中使用 `path` 仓库引入（本 SDK 未发布至 Packagist；若直接拷贝/vendor `php/` 目录且不包含 `.git` 目录，请在 `php/composer.json` 中补充 `"version": "1.6.0"` 字段，以便 Composer 解析版本约束）：

```json
{
  "repositories": [
    { "type": "path", "url": "./baccarat-openapi-sdk/php" }
  ],
  "require": {
    "bebebus/baccarat-openapi-sdk": "@dev"
  }
}
```

> 自动加载入口：通过 Composer 安装时在业务代码中引入 `require __DIR__ . '/vendor/autoload.php';`；直接克隆源码独立运行时引入 `require __DIR__ . '/autoload.php';`。

## 快速开始（S2S 客户端）

```php
<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php'; // 独立克隆使用：require __DIR__ . '/autoload.php';

use Bebebus\BaccaratSdk\Client;
use Bebebus\BaccaratSdk\Config;

$apiKey = getenv('B2B_API_KEY') ?: '';
$secret = getenv('B2B_SECRET') ?: '';

$config = new Config(
    apiKey: $apiKey,
    hmacSecret: $secret, // 原始字符串直传，切勿 base64_decode
    environment: Config::ENV_SANDBOX, // 生产环境请用 Config::ENV_PRODUCTION 并显式传 baseUrl
    // sendTimestamp: true,           // 可选：附加 X-Timestamp 防重放请求头（±300s）
);
$client = new Client($config);

$tables = $client->listTables(['currency' => 'USD'])['data']['tables'] ?? [];
if ($tables === []) {
    throw new RuntimeException('No permitted USD tables');
}

$res = $client->createGameUrl([
    'username' => 'player_9527',
    'tableId' => $tables[0]['tableId'],
    'platform' => 'H5',
    'language' => 'zh-CN',
    'currency' => $tables[0]['currency'],
    'lobbyUrl' => 'https://merchant.example.com/lobby',
    'ipAddress' => '203.0.113.42',
]);
echo $res['data']['gameUrl'] . PHP_EOL;
```

## PHP-FPM 钱包回调接入（务必使用持久化数据库存储）

> **严重警告**：PHP-FPM 每个 HTTP 请求结束后进程内存都会释放，**严禁在 PHP-FPM 回调入口使用 `InMemoryWallet`**（`InMemoryWallet` 仅用于 CLI 与单元测试）。生产环境请实现基于数据库唯一索引（`UNIQUE(transaction_id)`）的 `WalletHandlerInterface` 与 `WalletAdjustmentHandlerInterface`（处理 `/wallet/adjustment`）。纯回调服务可使用 `WebhookDispatcher::fromCredentials(...)`，无需配置 `baseUrl`。

```php
<?php
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php'; // 独立克隆使用：require __DIR__ . '/autoload.php';

use Bebebus\BaccaratSdk\WalletAdjustmentHandlerInterface;
use Bebebus\BaccaratSdk\WalletHandlerInterface;
use Bebebus\BaccaratSdk\WalletResponse;
use Bebebus\BaccaratSdk\WebhookDispatcher;

final class DbWalletHandler implements WalletHandlerInterface, WalletAdjustmentHandlerInterface
{
    public function onBalance(array $req): array { /* 查询数据库只读余额 */ return WalletResponse::ok((string) ($req['traceId'] ?? ''), (string) ($req['username'] ?? ''), (string) ($req['currency'] ?? ''), '1000.00'); }
    public function onBet(array $req): array { /* 按 transactionId 幂等扣款 */ return WalletResponse::ok((string) ($req['traceId'] ?? ''), (string) ($req['username'] ?? ''), (string) ($req['currency'] ?? ''), '900.00'); }
    public function onBetResult(array $req): array { /* 按 transactionId 幂等派彩（忽略会话过期） */ return WalletResponse::ok((string) ($req['traceId'] ?? ''), (string) ($req['username'] ?? ''), (string) ($req['currency'] ?? ''), '1100.00'); }
    public function onRollback(array $req): array { /* 按 transactionId 冲正（未扣成返回 SC_TRANSACTION_NOT_EXISTS） */ return WalletResponse::ok((string) ($req['traceId'] ?? ''), (string) ($req['username'] ?? ''), (string) ($req['currency'] ?? ''), '1000.00'); }
    public function onAdjustment(array $req): array { /* 按 transactionId 幂等执行 CREDIT/DEBIT 调账 */ return WalletResponse::ok((string) ($req['traceId'] ?? ''), (string) ($req['username'] ?? ''), (string) ($req['currency'] ?? ''), '1020.00'); }
}

$rawBody = (string) file_get_contents('php://input');
$dispatcher = WebhookDispatcher::fromCredentials(
    getenv('B2B_API_KEY') ?: '',
    getenv('B2B_SECRET') ?: '',
    new DbWalletHandler()
);
$out = $dispatcher->handle(
    $_SERVER['REQUEST_URI'] ?? '',
    $_SERVER['HTTP_X_API_KEY'] ?? null,
    $_SERVER['HTTP_X_SIGNATURE'] ?? null,
    $rawBody
);
http_response_code($out['statusCode']);
header('Content-Type: application/json');
echo json_encode($out['body'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
```

### 生产回调 4 项强制不变量（v1.6.0）

1. **按玩家串行结算，但数据库仍须行锁与幂等键**：平台按单商户最多 4 路并发推送 `/wallet/*` 回调；自 `v1.6.0` 起 `/wallet/bet_result` 同局结算按玩家串行投递，但跨玩家并发及余额查询/下注/重试仍可能交错抵达，请始终对玩家钱包行使用 `SELECT ... FOR UPDATE` 或原子 `UPDATE ... SET balance = balance + delta` + `UNIQUE(transaction_id)`。
2. **确定性 `isEndRound` 语义与逐票入账**：同局多注时，非最后一张注单确定性携带 `isEndRound: 0`，最后一张非 `REJECTED` 注单确定性携带 `isEndRound: 1`（按 `(createdAt ASC, id ASC)` 排序，自动重试与补推保持一致）；仍须按 `betId` / `transactionId` 逐票幂等入账。
3. **出站 `X-Timestamp` 请求头与原始字节验签**：平台向 `/wallet/*` 发起的所有出站回调均附带 13 位毫秒级 `X-Timestamp` 请求头（可供可选防重放校验）；**`X-Signature` 仍严格仅对原始请求体字节计算 HMAC-SHA256，不包含 `X-Timestamp`**。
4. **终态拦截、重试窗口与 0 位小数币种**：返回 `HTTP 200` 非 JSON 或无瞬态 `SC_*` 的非 2xx JSON 会使 `/wallet/bet_result` 立即挂起 `HELD` 且 0 次重试；瞬态错误按 **1 次首次 + 12 次自动重试（约 `5.07h`）** 退避重试（`WebhookDispatcher` 已自动将未捕获 `\Throwable` 映射为 `SC_OPERATOR_TIMEOUT`）。0 位小数币种（如 `JPY`）零值为 `"0"`，切勿用 `=== '0.00'` 判零，请使用 `Money::decimalToLedgerUnits(...) === '0'`。

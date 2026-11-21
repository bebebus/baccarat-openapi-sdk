# 真人视讯百家乐 B2B 商户 SDK — PHP 8

零第三方依赖（仅需 PHP >= 8.1 核心扩展 `ext-curl` 与 `ext-json`，内置十进制大数字符串算术，无需 `ext-bcmath`）。支持直接 `require 'autoload.php'` 或通过 Composer PSR-4 `Bebebus\BaccaratSdk\` 引入。

## 单测命令

```bash
php tests/run.php
```

## 快速开始

```php
<?php
require __DIR__ . '/autoload.php';

use Bebebus\BaccaratSdk\Client;
use Bebebus\BaccaratSdk\Config;
use Bebebus\BaccaratSdk\InMemoryWallet;
use Bebebus\BaccaratSdk\WebhookDispatcher;

$config = new Config(
    apiKey: getenv('B2B_API_KEY'),
    hmacSecret: getenv('B2B_SECRET'), // 原始字符串直传，切勿 base64_decode
    environment: Config::ENV_SANDBOX
);
$client = new Client($config);

$res = $client->createGameUrl([
    'username' => 'player_9527',
    'tableId' => 'T-A2',
    'platform' => 'H5',
    'language' => 'zh-CN',
    'currency' => 'USD',
    'lobbyUrl' => 'https://merchant.example.com/lobby',
    'ipAddress' => '203.0.113.42',
]);
echo $res['data']['gameUrl'] . PHP_EOL;

// 钱包回调入口（务必从 php://input 读取未解析的原始字节）
$rawBody = (string) file_get_contents('php://input');
$wallet = new InMemoryWallet(['player_9527' => ['currency' => 'USD', 'balance' => '1000.00']]);
$dispatcher = new WebhookDispatcher($config, $wallet);
$out = $dispatcher->handle($_SERVER['REQUEST_URI'] ?? '', $_SERVER['HTTP_X_API_KEY'] ?? null, $_SERVER['HTTP_X_SIGNATURE'] ?? null, $rawBody);
http_response_code($out['statusCode']);
header('Content-Type: application/json');
echo json_encode($out['body'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
```

# 真人视讯百家乐 B2B 商户 SDK — Rust

**零第三方 Crate 依赖**（`[dependencies]` 为空！纯 Safe Rust 实现 RFC-6234 SHA-256、RFC-2104 HMAC-SHA256、常量时间比较、RFC-8259 JSON 与 `i128` 精确十进制账本算术；默认 HTTP 传输层直接链接系统 `libcurl`，并开放 `HttpTransport` trait 方便自由替换为 `reqwest` / `ureq`）。

## 系统依赖、引入与单测

- 系统需安装 `libcurl` 开发包（Debian/Ubuntu: `sudo apt-get install -y libcurl4-openssl-dev`；RHEL/Fedora: `libcurl-devel`；macOS 默认自带）。
- 在 `Cargo.toml` 中通过 Git 标签引入（Cargo 自动定位仓库内 `rust/Cargo.toml`，**切勿添加无效的 `subdirectory` 字段**）：

```toml
[dependencies]
baccarat-openapi-sdk = { git = "https://github.com/bebebus/baccarat-openapi-sdk", tag = "v1.5.9" }
```

- 单测命令：`cd rust && cargo test`

## 快速开始（S2S 客户端 + `'static` 回调分发器）

```rust
use std::sync::Arc;
use baccarat_openapi_sdk::{
    wallet_ok, Client, Config, Environment, Json, SharedWebhookDispatcher, WalletHandler,
};

// 生产环境请基于数据库唯一索引实现自定义 WalletHandler（含 on_adjustment）
struct DbWallet;

impl WalletHandler for DbWallet {
    fn on_balance(&self, req: &Json) -> Json {
        wallet_ok(req.get("traceId").as_str().unwrap_or(""), req.get("username").as_str().unwrap_or(""), req.get("currency").as_str().unwrap_or(""), "1000.00", None)
    }
    fn on_bet(&self, req: &Json) -> Json {
        wallet_ok(req.get("traceId").as_str().unwrap_or(""), req.get("username").as_str().unwrap_or(""), req.get("currency").as_str().unwrap_or(""), "900.00", None)
    }
    fn on_bet_result(&self, req: &Json) -> Json {
        wallet_ok(req.get("traceId").as_str().unwrap_or(""), req.get("username").as_str().unwrap_or(""), req.get("currency").as_str().unwrap_or(""), "1100.00", None)
    }
    fn on_rollback(&self, req: &Json) -> Json {
        wallet_ok(req.get("traceId").as_str().unwrap_or(""), req.get("username").as_str().unwrap_or(""), req.get("currency").as_str().unwrap_or(""), "1000.00", None)
    }
    fn on_adjustment(&self, req: &Json) -> Json {
        wallet_ok(req.get("traceId").as_str().unwrap_or(""), req.get("username").as_str().unwrap_or(""), req.get("currency").as_str().unwrap_or(""), "1020.00", None)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let api_key = std::env::var("B2B_API_KEY")?;
    let secret = std::env::var("B2B_SECRET")?; // 切勿 Base64 解码

    let cfg = Config {
        api_key: api_key.clone(),
        hmac_secret: secret.clone(),
        environment: Environment::Sandbox, // 正式环境用 Environment::Production 并填 base_url
        base_url: None,
        timeout_ms: 8000,
    };
    // 可选：.with_send_timestamp(true) 附加 X-Timestamp 防重放请求头（±300s）
    let client = Client::new(cfg)?.with_send_timestamp(true);

    // SDK 未传 traceId 时自动生成 UUIDv4
    let mut req = Json::object();
    req.set("username", Json::Str("player_9527".into()));
    req.set("tableId", Json::Str("T-A2".into()));
    req.set("platform", Json::Str("H5".into()));
    req.set("language", Json::Str("zh-CN".into()));
    req.set("currency", Json::Str("USD".into()));
    req.set("lobbyUrl", Json::Str("https://merchant.example.com/lobby".into()));
    req.set("ipAddress", Json::Str("203.0.113.42".into()));

    let res = client.create_game_url(req)?;
    println!("Launch URL: {:?}", res.get("data").get("gameUrl").as_str());

    // 适用于 Axum / Actix 的 'static + Send + Sync 回调分发器（无需 base_url）
    let wallet = Arc::new(DbWallet);
    let dispatcher = Arc::new(SharedWebhookDispatcher::try_new(&api_key, &secret, wallet)?);
    // let reply = dispatcher.handle(path, x_api_key, x_signature, raw_body_bytes);
    // let json_out = reply.dump();
    let _ = dispatcher;
    Ok(())
}
```

### 生产回调 4 项强制不变量

1. **4 路并发（不按玩家串行）**：平台按单商户最多 4 路并发推送回调，请对玩家钱包行使用 `SELECT ... FOR UPDATE` 或原子 `UPDATE ... SET balance = balance + delta` + `UNIQUE(transaction_id)`。
2. **多注同局每张注单均带 `isEndRound: 1`**：切勿收到首张 `isEndRound: 1` 即终结局级状态，必须按 `betId` / `transactionId` 逐票入账。
3. **终态拦截与 `~5.07h` 重试窗口**：返回 `HTTP 200` 非 JSON 或无瞬态 `SC_*` 的非 2xx JSON 会使 `/wallet/bet_result` 立即挂起 `HELD` 且 0 次重试；瞬态错误按 **1 次首次 + 12 次自动重试（约 `5.07h`）** 退避重试（`WebhookDispatcher` 已内置 `catch_unwind`，将未捕获 panic 映射为 `SC_OPERATOR_TIMEOUT`；注意 panic 隔离要求保持默认 `panic = "unwind"`，切勿在 `[profile.release]` 中配置 `panic = "abort"`）。
4. **0 位小数币种（如 `JPY`）零值为 `"0"`**：切勿用 `== "0.00"` 判零，请使用 `decimal_to_ledger_units(...) == Ok(0)` 比较。

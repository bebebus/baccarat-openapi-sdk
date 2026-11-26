# 真人视讯百家乐 B2B 商户 SDK — Rust

**零第三方 Crate 依赖**（`[dependencies]` 为空！纯 Safe Rust 实现 RFC-6234 SHA-256、RFC-2104 HMAC-SHA256、常量时间比较、RFC-8259 JSON 与 `i128` 精确十进制账本算术；默认 HTTP 传输层直接链接系统 `libcurl`，并开放 `HttpTransport` trait 方便自由替换为 `reqwest` / `ureq`）。

## 系统依赖、引入与单测

- 系统需安装 `libcurl` 开发包（Debian/Ubuntu: `sudo apt-get install -y libcurl4-openssl-dev`；RHEL/Fedora: `libcurl-devel`；macOS 默认自带）。
- 在 `Cargo.toml` 中通过 Git 标签引入（Cargo 自动定位仓库内 `rust/Cargo.toml`，**切勿添加无效的 `subdirectory` 字段**）：

```toml
[dependencies]
baccarat-openapi-sdk = { git = "https://github.com/bebebus/baccarat-openapi-sdk", tag = "v1.5.4" }
```

- 单测命令：`cd rust && cargo test`

## 快速开始（S2S 客户端 + `'static` 回调分发器）

```rust
use std::sync::Arc;
use baccarat_openapi_sdk::{
    Client, Config, Environment, InMemoryWallet, Json, SharedWebhookDispatcher,
};

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

    // 适用于 Axum / Actix 的 'static + Send + Sync 回调分发器（无需 base_url；生产请替换为持久化 WalletHandler 实现）
    let wallet = Arc::new(InMemoryWallet::new());
    let dispatcher = Arc::new(SharedWebhookDispatcher::try_new(&api_key, &secret, wallet)?);
    // let reply = dispatcher.handle(path, x_api_key, x_signature, raw_body_bytes);
    let _ = dispatcher;
    Ok(())
}
```

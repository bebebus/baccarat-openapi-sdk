# 真人视讯百家乐 B2B 商户 SDK — Rust

**零第三方 Crate 依赖**（`[dependencies]` 为空！纯 Safe Rust 实现 RFC-6234 SHA-256、RFC-2104 HMAC-SHA256、常量时间比较、RFC-8259 JSON 与 `i128` 精确十进制账本算术；默认 HTTP 传输层直接链接系统 `libcurl`，并开放 `HttpTransport` trait 方便自由替换为 `reqwest` / `ureq`）。

## 引入与单测

```toml
[dependencies]
baccarat-openapi-sdk = { git = "https://github.com/bebebus/baccarat-openapi-sdk", subdirectory = "rust" }
```

*(注：Cargo 1.78+ 直接指定仓库内路径或将本目录作为 workspace path 引入；单测命令：`cd rust && cargo test`)*

## 快速开始

```rust
use baccarat_openapi_sdk::{Client, Config, Environment, Json};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config {
        api_key: std::env::var("B2B_API_KEY")?,
        hmac_secret: std::env::var("B2B_SECRET")?, // 切勿 Base64 解码
        environment: Environment::Sandbox,
        base_url: None,
        timeout_ms: 8000,
    };
    let client = Client::new(cfg)?;

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
    Ok(())
}
```

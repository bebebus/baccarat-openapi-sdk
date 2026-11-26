# 真人视讯百家乐 B2B 商户 SDK — C++17

仅依赖标准 CMake + 系统 `OpenSSL` 与 `libcurl`（内置零依赖单头文件 RFC-8259 JSON 解析/序列化器 `baccarat/json.hpp` 与任意长度字符串金额算术，无需引入第三方 JSON 或大数库）。

## 系统依赖、编译与单测

- Debian / Ubuntu：`sudo apt-get install -y cmake g++ libssl-dev libcurl4-openssl-dev`
- macOS (Homebrew)：`brew install cmake openssl curl`
- Windows (MSVC / MinGW)：`cmake -S cpp -B cpp/build && cmake --build cpp/build`（`WIN32` 平台默认 `-DBACCARAT_BUILD_TESTS=OFF`，因 `tests/sdk_test.cpp` 依赖 POSIX socket 测试桩，仅构建静态库 `baccarat_sdk`）

在仓库根目录执行编译与单测：

```bash
git clone --branch v1.5.9 --depth 1 https://github.com/bebebus/baccarat-openapi-sdk.git
cd baccarat-openapi-sdk
cmake -S cpp -B cpp/build
cmake --build cpp/build
ctest --test-dir cpp/build --output-on-failure
```

## 快速开始（S2S 客户端与钱包回调）

```cpp
#include "baccarat/sdk.hpp"
#include <cstdlib>
#include <iostream>
#include <stdexcept>

// 生产环境请基于数据库唯一索引实现自定义 WalletHandler（含 on_adjustment）
class DbWalletHandler final : public baccarat::WalletHandler {
public:
    baccarat::Json on_balance(const baccarat::Json& req) override { return ok(req, "1000.00"); }
    baccarat::Json on_bet(const baccarat::Json& req) override { return ok(req, "900.00"); }
    baccarat::Json on_bet_result(const baccarat::Json& req) override { return ok(req, "1100.00"); }
    baccarat::Json on_rollback(const baccarat::Json& req) override { return ok(req, "1000.00"); }
    baccarat::Json on_adjustment(const baccarat::Json& req) override { return ok(req, "1020.00"); }
private:
    static baccarat::Json ok(const baccarat::Json& req, const std::string& bal) {
        // timestamp_ms = 0 自动填充当前 Unix 毫秒时间戳
        return baccarat::wallet_ok(
            req.at("traceId").as_string(),
            req.at("username").as_string(),
            req.at("currency").as_string(),
            bal
        );
    }
};

int main() {
    const char* api_key = std::getenv("B2B_API_KEY");
    const char* secret = std::getenv("B2B_SECRET"); // 切勿 Base64 解码
    if (!api_key || !secret) {
        throw std::runtime_error("B2B_API_KEY and B2B_SECRET must be set");
    }

    baccarat::Config cfg{api_key, secret, baccarat::Environment::Sandbox};
    // cfg.send_timestamp = true; // 可选：附加 X-Timestamp 防重放请求头（±300s）
    baccarat::Client client(cfg);

    // SDK 在未传 traceId 时自动生成 UUIDv4
    baccarat::Json req = baccarat::Json::object();
    req.set("username", "player_9527");
    req.set("tableId", "T-A2");
    req.set("platform", "H5");
    req.set("language", "zh-CN");
    req.set("currency", "USD");
    req.set("lobbyUrl", "https://merchant.example.com/lobby");
    req.set("ipAddress", "203.0.113.42");

    baccarat::Json res = client.create_game_url(req);
    std::cout << res.at("data").at("gameUrl").as_string() << "\n";

    // 纯回调服务可直接传 api_key + secret（无需 base_url）
    DbWalletHandler wallet;
    baccarat::WebhookDispatcher dispatcher(api_key, secret, wallet);
    // baccarat::Json reply = dispatcher.handle(route_path, x_api_key, x_signature, raw_http_body);
    // std::string http_body = reply.dump();
    return 0;
}
```

### 生产回调 4 项强制不变量

1. **4 路并发（不按玩家串行）**：平台按单商户最多 4 路并发推送回调，请对玩家钱包行使用 `SELECT ... FOR UPDATE` 或原子 `UPDATE ... SET balance = balance + delta` + `UNIQUE(transaction_id)`。
2. **多注同局每张注单均带 `isEndRound: 1`**：切勿收到首张 `isEndRound: 1` 即终结局级状态，必须按 `betId` / `transactionId` 逐票入账。
3. **终态拦截与 `~5.07h` 重试窗口**：返回 `HTTP 200` 非 JSON 或无瞬态 `SC_*` 的非 2xx JSON 会使 `/wallet/bet_result` 立即挂起 `HELD` 且 0 次重试；瞬态错误按 **1 次首次 + 12 次自动重试（约 `5.07h`）** 退避重试（`WebhookDispatcher` 已自动将未捕获 `std::exception` / `...` 映射为 `SC_OPERATOR_TIMEOUT`）。
4. **0 位小数币种（如 `JPY`）零值为 `"0"`**：切勿用 `== "0.00"` 判零，请使用 `baccarat::decimal_to_ledger_units(...)` 比较。

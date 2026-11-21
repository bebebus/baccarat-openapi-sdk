# 真人视讯百家乐 B2B 商户 SDK — C++17

仅依赖标准 CMake + 系统 `OpenSSL` 与 `libcurl`（内置零依赖单头文件 RFC-8259 JSON 解析/序列化器 `baccarat/json.hpp` 与任意长度字符串金额算术，无需引入第三方 JSON 或大数库）。

## 编译与单测

```bash
cmake -S cpp -B cpp/build
cmake --build cpp/build
ctest --test-dir cpp/build --output-on-failure
```

## 快速开始

```cpp
#include "baccarat/sdk.hpp"
#include <cstdlib>
#include <iostream>

int main() {
    baccarat::Config cfg{
        std::getenv("B2B_API_KEY"),
        std::getenv("B2B_SECRET"), // 切勿 Base64 解码
        baccarat::Environment::Sandbox
    };
    baccarat::Client client(cfg);

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
}
```

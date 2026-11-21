# 真人视讯百家乐 B2B 商户 SDK — Java 17

零第三方依赖（仅用 JDK 17 标准库 `java.net.http.HttpClient`、`javax.crypto.Mac`、`BigInteger` 与内置 RFC-8259 `JsonCodec`）。支持直接拷贝 `src/main/java` 源码引入或使用 `mvn package` 打 JAR 包。

## 编译与单测

```bash
bash run-tests.sh
```

## 快速开始

```java
import cloud.cniia.baccarat.sdk.BaccaratSdk.*;
import java.util.Map;

Config cfg = new Config(
    System.getenv("B2B_API_KEY"),
    System.getenv("B2B_SECRET"), // 切勿 Base64 解码
    Environment.SANDBOX,
    null,
    8000
);
Client client = new Client(cfg);

Map<String, Object> res = client.createGameUrl(Map.of(
    "username", "player_9527",
    "tableId", "T-A2",
    "platform", "H5",
    "language", "zh-CN",
    "currency", "USD",
    "lobbyUrl", "https://merchant.example.com/lobby",
    "ipAddress", "203.0.113.42"
));
System.out.println(res.get("data"));
```

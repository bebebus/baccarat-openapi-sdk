# 真人视讯百家乐 B2B 商户 SDK — Java 17

零第三方依赖（仅用 JDK 17 标准库 `java.net.http.HttpClient`、`javax.crypto.Mac`、`BigInteger` 与内置 RFC-8259 `JsonCodec`）。本 SDK 未发布至 Maven Central，支持直接拷贝 `src/main/java` 源码引入或通过 `mvn install` 安装至本地仓库。

## 安装、编译与单测

```bash
git clone --branch v1.5.4 --depth 1 https://github.com/bebebus/baccarat-openapi-sdk.git
cd baccarat-openapi-sdk/java
bash run-tests.sh          # 零 Maven 依赖直接编译并运行全部单测
# 或安装至本地 ~/.m2：mvn install
```

> **测试提示**：由于本模块保持零第三方依赖（`pom.xml` 未引入 JUnit / Surefire 测试框架），`mvn test` 与 `mvn install` 会跳过独立的 `SdkTestRunner`；请务必运行 `bash run-tests.sh` 执行全部单元测试与跨语言黄金向量校验。

## 快速开始（S2S 客户端）

```java
import cloud.cniia.baccarat.sdk.BaccaratSdk.*;
import java.util.List;
import java.util.Map;

Config cfg = new Config(
    System.getenv("B2B_API_KEY"),
    System.getenv("B2B_SECRET"), // 切勿 Base64 解码
    Environment.SANDBOX,         // 生产环境用 Environment.PRODUCTION 并显式传 baseUrl
    null,
    8000,
    true                         // 可选：附加 X-Timestamp 防重放请求头（±300s）
);
Client client = new Client(cfg);

Map<String, Object> tablesRes = client.listTables(Map.of("currency", "USD"));
@SuppressWarnings("unchecked")
List<Map<String, Object>> tables = (List<Map<String, Object>>) ((Map<String, Object>) tablesRes.get("data")).get("tables");
if (tables == null || tables.isEmpty()) throw new IllegalStateException("No open USD tables");

Map<String, Object> res = client.createGameUrl(Map.of(
    "username", "player_9527",
    "tableId", tables.get(0).get("tableId"),
    "platform", "H5",
    "language", "zh-CN",
    "currency", tables.get(0).get("currency"),
    "lobbyUrl", "https://merchant.example.com/lobby",
    "ipAddress", "203.0.113.42"
));
System.out.println(res.get("data"));
```

## 钱包回调接入示例（纯回调服务无需 `baseUrl`）

> 生产环境请基于数据库唯一索引实现 `WalletHandler`（包括 `onAdjustment`）；`InMemoryWallet` 仅用于本地联调与单测。在 Spring Boot / Servlet 中务必读取未解析的原始请求字节 `byte[] rawBody`。

```java
import cloud.cniia.baccarat.sdk.BaccaratSdk.*;
import java.util.Map;

WalletHandler dbWallet = new WalletHandler() {
    @Override public Map<String, Object> onBalance(Map<String, Object> req) { /* 只读余额 */ return Map.of(); }
    @Override public Map<String, Object> onBet(Map<String, Object> req) { /* 按 transactionId 幂等扣款 */ return Map.of(); }
    @Override public Map<String, Object> onBetResult(Map<String, Object> req) { /* 已扣款注单忽略会话过期放行派彩 */ return Map.of(); }
    @Override public Map<String, Object> onRollback(Map<String, Object> req) { /* 未扣成返回 SC_TRANSACTION_NOT_EXISTS */ return Map.of(); }
    @Override public Map<String, Object> onAdjustment(Map<String, Object> req) { /* CREDIT / DEBIT 调账 */ return Map.of(); }
};

WebhookDispatcher dispatcher = new WebhookDispatcher(
    System.getenv("B2B_API_KEY"),
    System.getenv("B2B_SECRET"),
    dbWallet
);
// Map<String, Object> resp = dispatcher.handle(request.getRequestURI(), request.getHeader("X-API-Key"), request.getHeader("X-Signature"), rawBodyBytes);
```

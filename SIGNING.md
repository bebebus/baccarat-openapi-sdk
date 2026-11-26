> 中文 | [English](./SIGNING.en.md)

# 原始字节 HMAC-SHA256 签名与幂等冲突指纹规范（v1.5.7）

本文件是 `bebebus/baccarat-openapi-sdk` 七套语言 SDK（Node.js、Python、PHP、Go、Java、C++、Rust）共享的密码学与幂等核验唯一事实源，100% 对齐在线契约 `https://openapi.lt.cniia.cloud/openapi.yaml`。

## 1. 双向对称请求头

入站 S2S 接口（商户调平台 `/operator/v1/*`）与出站无缝钱包回调（平台调商户 `{callbackUrl}/wallet/*`）采用完全对称的鉴权头：

- `Content-Type: application/json`
- `X-API-Key: ak_<32位小写hex>`（共 35 字符，上限 128 字符，首尾自动 trim）
- `X-Signature: <64位十六进制>`
- `X-Timestamp`（入站 S2S 可选防重放）：10 位 Unix 秒或 13 位 Unix 毫秒时间戳（`±300s` 时间窗；Node.js / PHP / Java 通过 `sendTimestamp`、Python / C++ 通过 `send_timestamp`、Go 通过 `SendTimestamp` 配置项启用，**Rust 通过 `Client::with_send_timestamp(true)` 启用**以保持 `Config` 结构体字面量向后兼容；`X-Signature` 仍仅对原始请求体字节计算）

## 2. 签名计算铁律（最常见踩坑点）

```text
X-Signature = lowercase_hex( HMAC-SHA256( key = UTF8(hmacSecret), message = rawHttpRequestBodyBytes ) )
```

1. **严禁对 `hmacSecret` 做 Base64 / Base64URL 解码**：
   商户控制台签发的 `hmacSecret` 形如 43 字符的 `base64url` 字符串（例如 `dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s`）。它本身就是完整口令文本，**必须直接按 UTF-8 编码取字节（43 bytes）作为 HMAC 密钥**。若误用 Base64URL 解码成 32 字节，签名将 100% 返回 `SC_INVALID_SIGNATURE`（见 `test-vectors.json` 中的 `wrongBase64DecodedSignature` 负向对照向量）。
2. **必须对实际传输的原始 UTF-8 请求体字节签名**：
   - 发请求时：先将请求对象序列化为 UTF-8 JSON 字节流 `rawBytes`，对 `rawBytes` 算 `X-Signature`，然后把同一份 `rawBytes` 原封不动写入 HTTP 请求体。
   - 收回调时：在 Web 框架把 Body 解析成对象再重序列化之前，直接读取原始 HTTP Body 字节流核验 `X-Signature`（重序列化可能改变键顺序、空格、Unicode 转义或斜杠 `/` 转义）。
3. **常量时间比较（Timing-Safe Equality）**：
   验签时先 `trim` 头部字符串并校验 `^[0-9a-fA-F]{64}$`（大小写十六进制均合法），随后必须使用常量时间字节比较（`crypto.timingSafeEqual`、`hmac.compare_digest`、`hash_equals`、`hmac.Equal`、`MessageDigest.isEqual`、`CRYPTO_memcmp`、Rust 常量时间全字节异或折叠），阻断时序侧信道。

## 3. 各语言序列化注意事项

| 语言 | 推荐做法与排错要点 |
| --- | --- |
| **Node.js** | `Buffer.from(JSON.stringify(payload), 'utf8')`，同一 `Buffer` 同时传给 `createHmac` 与 `req.write()`。 |
| **Python** | `json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")`。 |
| **PHP** | `json_encode($payload, JSON_UNESCAPED_UNICODE \| JSON_UNESCAPED_SLASHES \| JSON_THROW_ON_ERROR)`；收回调读 `file_get_contents('php://input')`。 |
| **Go** | `json.Marshal(payload)` 产出的 `[]byte` 直接同时签名并包入 `bytes.NewReader(raw)`。 |
| **Java** | `rawJson.getBytes(StandardCharsets.UTF_8)` 同时传给 `Mac.doFinal` 与 `HttpRequest.BodyPublishers.ofByteArray`。 |
| **C++** | 对将要传给 `CURLOPT_POSTFIELDS` + `CURLOPT_POSTFIELDSIZE_LARGE` 的 `std::string` 原始字节计算 OpenSSL `HMAC(EVP_sha256(), ...)`。 |
| **Rust** | 对序列化产出的 `Vec<u8>` 直接计算 HMAC-SHA256 并原样写入 HTTP 请求流。 |

## 4. 无缝钱包回调幂等冲突指纹（排除重试可变字段）

平台出站调用商户 `{callbackUrl}/wallet/*` 单次超时为 `8000ms`。当网络超时或收到瞬态错误重发同一 `transactionId` 时，**`traceId`、`timestamp`、`settledTime` 会在每次重试时更新**。商户钱包严禁将这些可变字段纳入幂等冲突比对，否则合法重试会被误判为 `SC_TRANSACTION_DUPLICATED`。

本仓库 7 套 SDK 统一采用单射长度前缀元组编码计算 64 位小写 SHA-256 业务指纹：

```text
canonical = "v1|" + endpoint + "|" + UTF8ByteLen(f1) + ":" + f1 + "|" + UTF8ByteLen(f2) + ":" + f2 + ...
fingerprint = lowercase_hex( SHA256( UTF8(canonical) ) )
```

| 回调端点 | `endpoint` 标识 | 参与指纹的固定业务字段（严格按序） | 显式排除的可变及附加上下文字段 |
| --- | --- | --- | --- |
| `POST /wallet/bet` | `wallet/bet` | `transactionId, username, betId, externalTransactionId, roundId, currency, gameCode, amount` | `traceId, timestamp, token, tableId, shoeId, roundNo, betSide` |
| `POST /wallet/bet_result` | `wallet/bet_result` | `transactionId, username, betId, externalTransactionId, roundId, currency, gameCode, betAmount, winAmount, effectiveTurnover, winLoss, jackpotAmount, resultType, String(isFreespin), String(isEndRound), String(betTime)` | `traceId, settledTime, token, tableId, betSide, roundOutcome` |
| `POST /wallet/rollback` | `wallet/rollback` | `transactionId, username, betId, externalTransactionId, roundId, currency, gameCode, amount` | `traceId, timestamp, token` |
| `POST /wallet/adjustment` | `wallet/adjustment` | `transactionId, username, betId, externalTransactionId, roundId, currency, gameCode, direction, amount, reasonCode` | `traceId, timestamp, token, memo, referenceNo` |

判定规则：
- `transactionId` 未见过 → 执行扣款/派彩/回滚并持久化 `(transactionId, fingerprint)`；
- `transactionId` 已存在且 `fingerprint` **相同** → **幂等重放**：不再变动余额，返回 `HTTP 200` + `status: "SC_OK"` + 玩家**当前最新 `balance`**；
- `transactionId` 已存在且 `fingerprint` **不同** → **幂等冲突**：拒绝操作，返回 `HTTP 200` + `status: "SC_TRANSACTION_DUPLICATED"`。

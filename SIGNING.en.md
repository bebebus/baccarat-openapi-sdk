> [中文](./SIGNING.md) | English

# Raw-Byte HMAC-SHA256 Signing & Idempotency Fingerprint Specification (v1.5.2)

This document is the authoritative cryptographic and idempotency specification shared across all 7 SDKs in `bebebus/baccarat-openapi-sdk` (Node.js, Python, PHP, Go, Java, C++, and Rust), aligned 100% with `https://openapi.lt.cniia.cloud/openapi.yaml`.

## 1. Symmetrical Headers

Both inbound S2S calls (Merchant -> Platform `/operator/v1/*`) and outbound seamless wallet webhooks (Platform -> Merchant `{callbackUrl}/wallet/*`) use identical headers:

- `Content-Type: application/json`
- `X-API-Key: ak_<32-lowercase-hex>` (35 chars, max 128 chars, trimmed)
- `X-Signature: <64-hex-chars>`
- `X-Timestamp` (optional inbound S2S anti-replay): 10-digit Unix seconds or 13-digit Unix ms (`±300s` skew window; enabled via `sendTimestamp` / `send_timestamp` / `SendTimestamp` config flag across all 7 SDKs; `X-Signature` is still computed strictly over raw body bytes)

## 2. Signing Invariants

```text
X-Signature = lowercase_hex( HMAC-SHA256( key = UTF8(hmacSecret), message = rawHttpRequestBodyBytes ) )
```

1. **NEVER Base64-decode `hmacSecret`**:
   Although the issued `hmacSecret` is a 43-character `base64url` string, pass its **raw UTF-8 string bytes directly** as the HMAC key. Base64-decoding it produces a completely different 32-byte key and fails with `SC_INVALID_SIGNATURE` (verified by `wrongBase64DecodedSignature` in `test-vectors.json`).
2. **Sign the exact wire bytes**:
   Compute `X-Signature` over the exact serialized UTF-8 byte sequence sent on the wire; on webhook receipt, verify `X-Signature` against the unparsed raw request body bytes before JSON deserialization.
3. **Constant-time comparison**:
   Trim `X-Signature`, validate `^[0-9a-fA-F]{64}$`, and compare digests in constant time to prevent timing side channels.

## 3. Canonical Webhook Conflict Fingerprints (Retry-Safe)

Across `8000ms` timeout retries, **`traceId`, `timestamp`, and `settledTime` mutate per HTTP attempt** and MUST NOT be included in conflict comparison. All 7 SDKs compute an injective length-prefixed SHA-256 fingerprint:

```text
canonical = "v1|" + endpoint + "|" + UTF8ByteLen(f1) + ":" + f1 + "|" + UTF8ByteLen(f2) + ":" + f2 + ...
fingerprint = lowercase_hex( SHA256( UTF8(canonical) ) )
```

- **`wallet/bet`**: `transactionId, username, betId, externalTransactionId, roundId, currency, gameCode, amount` *(excludes `traceId, timestamp, token, tableId, shoeId, roundNo, betSide`)*
- **`wallet/bet_result`**: `transactionId, username, betId, externalTransactionId, roundId, currency, gameCode, betAmount, winAmount, effectiveTurnover, winLoss, jackpotAmount, resultType, String(isFreespin), String(isEndRound), String(betTime)` *(excludes `traceId, settledTime, token, tableId, betSide, roundOutcome`)*
- **`wallet/rollback`**: `transactionId, username, betId, externalTransactionId, roundId, currency, gameCode, amount` *(excludes `traceId, timestamp, token`)*
- **`wallet/adjustment`**: `transactionId, username, betId, externalTransactionId, roundId, currency, gameCode, direction, amount, reasonCode` *(excludes `traceId, timestamp, token, memo, referenceNo`)*

Same `transactionId` + matching `fingerprint` -> return `HTTP 200` + `SC_OK` + current `data.balance` without mutating funds twice. Same `transactionId` + different `fingerprint` -> return `SC_TRANSACTION_DUPLICATED`.

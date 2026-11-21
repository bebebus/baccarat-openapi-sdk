> [中文](./README.md) | English

# Baccarat Live Platform · Multi-Language B2B Merchant SDKs (v1.2.0)

[![License: MIT](https://img.shields.io/badge/license-MIT-green)](./LICENSE)
[![OpenAPI 3.1](https://img.shields.io/badge/OpenAPI_3.1-v1.2.0-e3b15a)](https://openapi.lt.cniia.cloud/en/)

Official bidirectional B2B Operator Seamless Wallet SDKs (`bebebus/baccarat-openapi-sdk`) for **Node.js, Python, PHP, Go, Java, C++, and Rust**, aligned 100% with OpenAPI `v1.2.0` (`https://openapi.lt.cniia.cloud/en/`).

## Design Highlights

- **Zero External Package Dependencies**: Node.js, Python, PHP, Go, Java, and Rust have **zero third-party package dependencies**; C++ uses only CMake + system `OpenSSL` and `libcurl` with a built-in single-header RFC-8259 JSON parser/serializer.
- **Full Bidirectional Coverage**:
  - **S2S Client (`/operator/v1/*`)**: `createGameUrl`, `listTables`, `terminateSessions`, `listTransactions` (+ `listAllTransactions` auto-paginator), and `getTransactionDetail` (with `<= 7 days` window guard).
  - **Seamless Wallet Webhook Router (`{callbackUrl}/wallet/*`)**: Raw-body HMAC-SHA256 verification before JSON parsing, `/wallet/balance`, `/wallet/bet`, `/wallet/bet_result`, `/wallet/rollback`, retry-safe conflict fingerprinting (excluding mutable `traceId`, `timestamp`, `settledTime`), and a reference `InMemoryWallet` engine.
- **Byte-for-Byte Cross-Language Golden Vectors**: All 7 SDK test suites execute against the shared [`test-vectors.json`](./test-vectors.json).

## Language Matrix

| Language | Directory | External Packages | Test Command |
| --- | --- | --- | --- |
| **Node.js** (>= 18) | [`nodejs/`](./nodejs/) | **0** | `cd nodejs && node --test` |
| **Python** (>= 3.9) | [`python/`](./python/) | **0** | `cd python && python3 -m unittest discover -s tests -v` |
| **PHP** (>= 8.1) | [`php/`](./php/) | **0** (`ext-curl`, `ext-json`) | `cd php && php tests/run.php` |
| **Go** (>= 1.21) | [`go/`](./go/) | **0** | `cd go && go test -v -count=1 ./...` |
| **Java** (>= 17) | [`java/`](./java/) | **0** | `cd java && bash run-tests.sh` |
| **C++** (C++17) | [`cpp/`](./cpp/) | System `OpenSSL` + `libcurl` | `cmake -S cpp -B cpp/build && cmake --build cpp/build && ctest --test-dir cpp/build --output-on-failure` |
| **Rust** (2021) | [`rust/`](./rust/) | **0 Crates** (`std` + system `libcurl`) | `cd rust && cargo test` |

Run all 7 test suites sequentially:

```bash
bash _tooling/run-all-tests.sh
```

# 真人视讯百家乐 B2B 商户 SDK — Python 3

零第三方包依赖（仅使用 Python 标准库 `urllib.request`、`hmac`、`hashlib`、`json`、`unittest`），内置任意精度整数账本换算与线程安全无缝钱包幂等分发器。

## 安装、环境要求与单测

- Python >= 3.9
- 安装（通过 Git 标签安装子目录包）：

```bash
pip install "git+https://github.com/bebebus/baccarat-openapi-sdk.git@v1.6.0#subdirectory=python"
```

- 单测命令：`cd python && python3 -m unittest discover -s tests -v`

## 快速开始（S2S 客户端）

```python
import os
from baccarat_sdk import Client, Config, Environment

config = Config(
    api_key=os.environ["B2B_API_KEY"],
    hmac_secret=os.environ["B2B_SECRET"],  # 切勿 Base64 解码
    environment=Environment.SANDBOX,       # 生产环境请设 Environment.PRODUCTION 并显式传 base_url
    # send_timestamp=True,                 # 可选：附加 X-Timestamp 防重放请求头（±300s）
)
client = Client(config)

tables = client.list_tables(currency="USD")["data"]["tables"]
if not tables:
    raise RuntimeError("No permitted USD tables")

launch = client.create_game_url(
    username="player_9527",
    table_id=tables[0]["tableId"],
    platform="H5",
    language="zh-CN",
    currency=tables[0]["currency"],
    lobby_url="https://merchant.example.com/lobby",
    ip_address="203.0.113.42",
)
print(launch["data"]["gameUrl"])
```

## 无缝钱包回调接入（FastAPI / Flask 分离示例）

> **生产提示**：`InMemoryWallet` 仅用于本地联调与单测；生产环境请实现持久化数据库 `WalletHandler`（覆盖 `on_balance`、`on_bet`、`on_bet_result`、`on_rollback`、`on_adjustment`，可使用 `wallet_ok(...)` / `wallet_error(...)` 构造标准响应信封）。纯回调服务可使用 `WebhookDispatcher.from_credentials(api_key, hmac_secret, wallet)` 而无需填写 `base_url`。

### 生产回调 4 项强制不变量（v1.6.0）

1. **按玩家串行结算，但数据库仍须行锁与幂等键**：平台按单商户最多 4 路并发推送 `/wallet/*` 回调；自 `v1.6.0` 起 `/wallet/bet_result` 同局结算按玩家串行投递，但跨玩家并发及余额查询/下注/重试仍可能交错抵达，数据库层务必始终使用玩家行锁（`SELECT ... FOR UPDATE`）或原子 `UPDATE ... SET balance = balance + delta` + `UNIQUE(transaction_id)`。
2. **确定性 `isEndRound` 语义与逐票入账**：同局多注时，非最后一张注单确定性携带 `isEndRound: 0`，最后一张非 `REJECTED` 注单确定性携带 `isEndRound: 1`（按 `(createdAt ASC, id ASC)` 排序，自动重试与补推保持一致）；仍须按 `betId` / `transactionId` 逐票幂等入账。
3. **出站 `X-Timestamp` 请求头与原始字节验签**：平台向 `/wallet/*` 发起的所有出站回调均附带 13 位毫秒级 `X-Timestamp` 请求头（可供可选防重放校验）；**`X-Signature` 仍严格仅对原始请求体字节计算 HMAC-SHA256，不包含 `X-Timestamp`**。
4. **终态拦截、重试窗口与 0 位小数币种**：返回 `HTTP 200` 非 JSON 或无瞬态 `SC_*` 的非 2xx JSON 会使 `/wallet/bet_result` 立即挂起 `HELD` 且 0 次重试；瞬态错误按 **1 次首次 + 12 次自动重试（约 `5.07h`）** 退避重试（`WebhookDispatcher` 已自动将未捕获异常映射为 `SC_OPERATOR_TIMEOUT`）。0 位小数币种（如 `JPY`）零值为 `"0"`，切勿用 `== "0.00"` 判零，请使用 `decimal_to_ledger_units(...) == 0`。

> **单字段清空说明**：调用 `client.update_player_status(..., reason=None)` 或 `client.update_player_limits(..., max_bet=None)` 时，显式传入 `None` 会序列化为 JSON `null` 以清空对应字段；省略参数（默认 `UNSET`）则不发送该键。

### FastAPI 示例

```python
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from baccarat_sdk import InMemoryWallet, WebhookDispatcher

app = FastAPI()
wallet = InMemoryWallet({"player_9527": {"currency": "USD", "balance": "1000.00", "exponent": 2}})
dispatcher = WebhookDispatcher.from_credentials(os.environ["B2B_API_KEY"], os.environ["B2B_SECRET"], wallet)

@app.post("/wallet/{action}")
async def wallet_webhook(request: Request):
    raw_bytes = await request.body()
    # WalletHandler 为同步接口，在 async 路由中务必通过 run_in_threadpool 卸载阻塞 DB/IO 调用
    status_code, resp_json = await run_in_threadpool(
        dispatcher.handle,
        request.url.path,
        request.headers.get("x-api-key"),
        request.headers.get("x-signature"),
        raw_bytes,
    )
    return JSONResponse(content=resp_json, status_code=status_code)
```

### Flask 示例

```python
import os
from flask import Flask, jsonify, request
from baccarat_sdk import InMemoryWallet, WebhookDispatcher

app = Flask(__name__)
wallet = InMemoryWallet({"player_9527": {"currency": "USD", "balance": "1000.00", "exponent": 2}})
dispatcher = WebhookDispatcher.from_credentials(os.environ["B2B_API_KEY"], os.environ["B2B_SECRET"], wallet)

@app.post("/wallet/<action>")
def wallet_webhook(action: str):
    raw_bytes = request.get_data(cache=False, as_text=False)
    status_code, resp_json = dispatcher.handle(
        request.path,
        request.headers.get("X-API-Key"),
        request.headers.get("X-Signature"),
        raw_bytes,
    )
    return jsonify(resp_json), status_code
```

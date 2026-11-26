# 真人视讯百家乐 B2B 商户 SDK — Python 3

零第三方包依赖（仅使用 Python 标准库 `urllib.request`、`hmac`、`hashlib`、`json`、`unittest`），内置任意精度整数账本换算与线程安全无缝钱包幂等分发器。

## 安装、环境要求与单测

- Python >= 3.9
- 安装（通过 Git 标签安装子目录包）：

```bash
pip install "git+https://github.com/bebebus/baccarat-openapi-sdk.git@v1.5.2#subdirectory=python"
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

> **生产提示**：`InMemoryWallet` 仅用于本地联调与单测；生产环境请实现持久化数据库 `WalletHandler`（覆盖 `on_balance`、`on_bet`、`on_bet_result`、`on_rollback`、`on_adjustment`）。纯回调服务可使用 `WebhookDispatcher.from_credentials(api_key, hmac_secret, wallet)` 而无需填写 `base_url`。

### FastAPI 示例

```python
import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from baccarat_sdk import InMemoryWallet, WebhookDispatcher

app = FastAPI()
wallet = InMemoryWallet({"player_9527": {"currency": "USD", "balance": "1000.00", "exponent": 2}})
dispatcher = WebhookDispatcher.from_credentials(os.environ["B2B_API_KEY"], os.environ["B2B_SECRET"], wallet)

@app.post("/wallet/{action}")
async def wallet_webhook(request: Request):
    raw_bytes = await request.body()
    status_code, resp_json = dispatcher.handle(
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

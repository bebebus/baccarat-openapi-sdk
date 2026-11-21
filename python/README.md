# 真人视讯百家乐 B2B 商户 SDK — Python 3

零第三方包依赖（仅使用 Python 标准库 `urllib.request`、`hmac`、`hashlib`、`json`、`unittest`），内置任意精度整数账本换算与无缝钱包幂等分发器。

## 环境要求与单测

- Python >= 3.9
- 单测命令：`python3 -m unittest discover -s tests -v`

## 快速开始

```python
import os
from baccarat_sdk import Client, Config, Environment, InMemoryWallet, WebhookDispatcher

config = Config(
    api_key=os.environ["B2B_API_KEY"],
    hmac_secret=os.environ["B2B_SECRET"],  # 切勿 Base64 解码
    environment=Environment.SANDBOX,       # 生产环境请设 Environment.PRODUCTION 并显式传 base_url
)
client = Client(config)

launch = client.create_game_url(
    username="player_9527",
    table_id="T-A2",
    platform="H5",
    language="zh-CN",
    currency="USD",
    lobby_url="https://merchant.example.com/lobby",
    ip_address="203.0.113.42",
)
print(launch["data"]["gameUrl"])

# FastAPI / Flask 无缝钱包回调挂载（传入原始字节 await request.body()）
wallet = InMemoryWallet({"player_9527": {"currency": "USD", "balance": "1000.00", "exponent": 2}})
dispatcher = WebhookDispatcher(config, wallet)
# status_code, resp_json = dispatcher.handle(request.url.path, request.headers.get("x-api-key"), request.headers.get("x-signature"), raw_bytes)
```

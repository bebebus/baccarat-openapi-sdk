# 真人视讯百家乐 B2B 商户 SDK — Go

零第三方包依赖（仅使用 Go >= 1.21 标准库 `net/http`、`crypto/hmac`、`math/big`），`WebhookDispatcher` 原生实现 `http.Handler` 接口，可直接挂载至标准库或 Gin / Echo / Chi。

## 安装与单测

```bash
go get github.com/bebebus/baccarat-openapi-sdk/go
cd go && go test -v -count=1 ./...
```

## 快速开始

```go
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	baccarat "github.com/bebebus/baccarat-openapi-sdk/go"
)

func main() {
	client, err := baccarat.NewClient(baccarat.Config{
		APIKey:      os.Getenv("B2B_API_KEY"),
		HMACSecret:  os.Getenv("B2B_SECRET"), // 切勿 Base64 解码
		Environment: baccarat.EnvSandbox,
	})
	if err != nil {
		panic(err)
	}

	launch, _, err := client.CreateGameUrl(context.Background(), baccarat.CreateGameUrlRequest{
		Username:  "player_9527",
		TableID:   "T-A2",
		Platform:  "H5",
		Language:  "zh-CN",
		Currency:  "USD",
		LobbyURL:  "https://merchant.example.com/lobby",
		IPAddress: "203.0.113.42",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("Launch URL:", launch.GameURL)

	// 无缝钱包回调直接作为标准 http.Handler 挂载
	wallet, _ := baccarat.NewInMemoryWallet(map[string]baccarat.AccountInit{
		"player_9527": {Currency: "USD", Balance: "1000.00", Exponent: 2},
	})
	disp, _ := baccarat.NewWebhookDispatcher(os.Getenv("B2B_API_KEY"), os.Getenv("B2B_SECRET"), wallet)
	http.Handle("/wallet/", disp)
}
```

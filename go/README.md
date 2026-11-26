# 真人视讯百家乐 B2B 商户 SDK — Go

零第三方包依赖（仅使用 Go >= 1.21 标准库 `net/http`、`crypto/hmac`、`math/big`），`WebhookDispatcher` 原生实现 `http.Handler` 接口，可直接挂载至标准库或 Gin / Echo / Chi。

## 安装与单测

```bash
go get github.com/bebebus/baccarat-openapi-sdk/go@v1.5.2
cd go && go test -v -count=1 ./...
```

## 快速开始

```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	baccarat "github.com/bebebus/baccarat-openapi-sdk/go"
)

// 生产环境请实现基于数据库的持久化 WalletHandler + WalletAdjustmentHandler
type dbWallet struct{}

func (w *dbWallet) OnBalance(_ context.Context, req baccarat.WalletBalanceRequest) baccarat.WalletResponse {
	return baccarat.WalletResponse{
		TraceID: req.TraceID, Status: baccarat.SC_OK,
		Data: &baccarat.WalletResponseData{Username: req.Username, Currency: req.Currency, Balance: "1000.00", Timestamp: time.Now().UnixMilli()},
	}
}
func (w *dbWallet) OnBet(ctx context.Context, req baccarat.WalletBetRequest) baccarat.WalletResponse {
	// 按 req.TransactionID 唯一索引幂等扣款；req.TableID / req.BetSide 为附加上下文
	return w.OnBalance(ctx, baccarat.WalletBalanceRequest{TraceID: req.TraceID, Username: req.Username, Currency: req.Currency})
}
func (w *dbWallet) OnBetResult(ctx context.Context, req baccarat.WalletBetResultRequest) baccarat.WalletResponse {
	// 已扣款 betId 即使玩家会话超时也必须放行结算
	return w.OnBalance(ctx, baccarat.WalletBalanceRequest{TraceID: req.TraceID, Username: req.Username, Currency: req.Currency})
}
func (w *dbWallet) OnRollback(ctx context.Context, req baccarat.WalletRollbackRequest) baccarat.WalletResponse {
	// 原 betId 未扣成时返回 SC_TRANSACTION_NOT_EXISTS 空成功
	return w.OnBalance(ctx, baccarat.WalletBalanceRequest{TraceID: req.TraceID, Username: req.Username, Currency: req.Currency})
}
func (w *dbWallet) OnAdjustment(ctx context.Context, req baccarat.WalletAdjustmentRequest) baccarat.WalletResponse {
	// 处理 POST /wallet/adjustment（CREDIT 加款 / DEBIT 扣款）
	return w.OnBalance(ctx, baccarat.WalletBalanceRequest{TraceID: req.TraceID, Username: req.Username, Currency: req.Currency})
}

func main() {
	apiKey := os.Getenv("B2B_API_KEY")
	secret := os.Getenv("B2B_SECRET") // 切勿 Base64 解码

	client, err := baccarat.NewClient(baccarat.Config{
		APIKey:        apiKey,
		HMACSecret:    secret,
		Environment:   baccarat.EnvSandbox, // 正式环境用 EnvProduction 并显式传 BaseURL
		SendTimestamp: true,                // 可选：附加 X-Timestamp 防重放请求头（±300s）
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	tables, _, err := client.ListTables(ctx, baccarat.ListTablesRequest{Currency: "USD"})
	if err != nil || len(tables.Tables) == 0 {
		log.Fatalf("no open USD tables: %v", err)
	}

	launch, _, err := client.CreateGameUrl(ctx, baccarat.CreateGameUrlRequest{
		Username:  "player_9527",
		TableID:   tables.Tables[0].TableID,
		Platform:  "H5",
		Language:  "zh-CN",
		Currency:  tables.Tables[0].Currency,
		LobbyURL:  "https://merchant.example.com/lobby",
		IPAddress: "203.0.113.42",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Launch URL:", launch.GameURL)

	// 可选指针字段示例（如 UpdatePlayerStatus / GetTransactionDetail）
	allowBet := false
	_, _, err = client.UpdatePlayerStatus(ctx, baccarat.UpdatePlayerStatusRequest{
		Username:       "player_9527",
		Action:         "SET",
		BettingEnabled: &allowBet,
	})
	if err != nil {
		log.Fatal(err)
	}

	// 无缝钱包回调直接作为标准 http.Handler 挂载（纯回调服务无需 BaseURL）
	disp, err := baccarat.NewWebhookDispatcher(apiKey, secret, &dbWallet{})
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/wallet/", disp)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

# 真人视讯百家乐 B2B 商户 SDK — Go

零第三方包依赖（仅使用 Go >= 1.21 标准库 `net/http`、`crypto/hmac`、`math/big`），`WebhookDispatcher` 原生实现 `http.Handler` 接口，可直接挂载至标准库或 Gin / Echo / Chi。

## 安装与单测

```bash
go get github.com/bebebus/baccarat-openapi-sdk/go@v1.5.8
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

	baccarat "github.com/bebebus/baccarat-openapi-sdk/go"
)

// 生产环境请实现基于数据库的持久化 WalletHandler + WalletAdjustmentHandler
type dbWallet struct{}

func (w *dbWallet) OnBalance(_ context.Context, req baccarat.WalletBalanceRequest) baccarat.WalletResponse {
	return baccarat.WalletOK(req.TraceID, req.Username, req.Currency, "1000.00", 0)
}
func (w *dbWallet) OnBet(_ context.Context, req baccarat.WalletBetRequest) baccarat.WalletResponse {
	// 按 req.TransactionID 唯一索引幂等扣款；req.TableID / req.BetSide 为附加上下文
	return baccarat.WalletOK(req.TraceID, req.Username, req.Currency, "900.00", 0)
}
func (w *dbWallet) OnBetResult(_ context.Context, req baccarat.WalletBetResultRequest) baccarat.WalletResponse {
	// 已扣款 betId 即使玩家会话超时也必须放行结算
	return baccarat.WalletOK(req.TraceID, req.Username, req.Currency, "1100.00", 0)
}
func (w *dbWallet) OnRollback(_ context.Context, req baccarat.WalletRollbackRequest) baccarat.WalletResponse {
	// 原 betId 未扣成时返回 baccarat.WalletError(req.TraceID, baccarat.SC_TRANSACTION_NOT_EXISTS, "never deducted")
	return baccarat.WalletOK(req.TraceID, req.Username, req.Currency, "1000.00", 0)
}
func (w *dbWallet) OnAdjustment(_ context.Context, req baccarat.WalletAdjustmentRequest) baccarat.WalletResponse {
	// 处理 POST /wallet/adjustment（CREDIT 加款 / DEBIT 扣款）
	return baccarat.WalletOK(req.TraceID, req.Username, req.Currency, "1020.00", 0)
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

### 生产回调 4 项强制不变量

1. **4 路并发（不按玩家串行）**：平台按单商户最多 4 路并发推送回调，请对玩家钱包行使用 `SELECT ... FOR UPDATE` 或原子 `UPDATE ... SET balance = balance + delta` + `UNIQUE(transaction_id)`。
2. **多注同局每张注单均带 `isEndRound: 1`**：切勿收到首张 `isEndRound: 1` 即终结局级状态，必须按 `betId` / `transactionId` 逐票入账。
3. **终态拦截与 `~5.07h` 重试窗口**：返回 `HTTP 200` 非 JSON 或无瞬态 `SC_*` 的非 2xx JSON 会使 `/wallet/bet_result` 立即挂起 `HELD` 且 0 次重试；瞬态错误按 **1 次首次 + 12 次自动重试（约 `5.07h`）** 退避重试（`WebhookDispatcher` 已内置 `recover()`，将未捕获 panic 映射为 `SC_OPERATOR_TIMEOUT`）。
4. **0 位小数币种（如 `JPY`）零值为 `"0"`**：切勿用 `== "0.00"` 判零，请使用 `DecimalToLedgerUnits` 比较。

> **单字段清空说明**：在 `UpdatePlayerStatusRequest` 上设置 `ClearReason: true` 或在 `UpdatePlayerLimitsRequest` 上设置 `ClearMinBet` / `ClearMaxBet` / `ClearMaxTableRound` / `ClearMaxUserDay` / `ClearMaxLossPerDay` 可显式输出 JSON `null`（`ClearCustomChips: true` 输出 `[]`）以清空单个字段。

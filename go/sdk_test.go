// SPDX-License-Identifier: MIT
package baccarat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testVectorsDoc struct {
	HMACVectors []struct {
		Name                        string `json:"name"`
		Secret                      string `json:"secret"`
		RawBody                     string `json:"rawBody"`
		UTF8ByteLength              int    `json:"utf8ByteLength"`
		Signature                   string `json:"signature"`
		WrongBase64DecodedSignature string `json:"wrongBase64DecodedSignature"`
	} `json:"hmacVectors"`
	HeaderVerificationVectors []struct {
		Name            string `json:"name"`
		ExpectedAPIKey  string `json:"expectedApiKey"`
		HMACSecret      string `json:"hmacSecret"`
		APIKeyHeader    string `json:"apiKeyHeader"`
		SignatureHeader string `json:"signatureHeader"`
		RawBody         string `json:"rawBody"`
		ExpectedStatus  string `json:"expectedStatus"`
	} `json:"headerVerificationVectors"`
	IdempotencyVectors struct {
		Bet struct {
			Initial                 WalletBetRequest `json:"initial"`
			RetrySameBusiness       WalletBetRequest `json:"retrySameBusiness"`
			ConflictDifferentAmount WalletBetRequest `json:"conflictDifferentAmount"`
			ExpectedFingerprint     string           `json:"expectedFingerprint"`
			ConflictFingerprint     string           `json:"conflictFingerprint"`
		} `json:"bet"`
		BetResult struct {
			Initial                    WalletBetResultRequest `json:"initial"`
			RetrySameBusiness          WalletBetResultRequest `json:"retrySameBusiness"`
			ConflictDifferentWinAmount WalletBetResultRequest `json:"conflictDifferentWinAmount"`
			ExpectedFingerprint        string                 `json:"expectedFingerprint"`
			ConflictFingerprint        string                 `json:"conflictFingerprint"`
		} `json:"betResult"`
		Rollback struct {
			Initial                 WalletRollbackRequest `json:"initial"`
			RetrySameBusiness       WalletRollbackRequest `json:"retrySameBusiness"`
			ConflictDifferentAmount WalletRollbackRequest `json:"conflictDifferentAmount"`
			ExpectedFingerprint     string                `json:"expectedFingerprint"`
			ConflictFingerprint     string                `json:"conflictFingerprint"`
		} `json:"rollback"`
		Adjustment struct {
			Initial                    WalletAdjustmentRequest `json:"initial"`
			RetrySameBusiness          WalletAdjustmentRequest `json:"retrySameBusiness"`
			ConflictDifferentDirection WalletAdjustmentRequest `json:"conflictDifferentDirection"`
			ExpectedFingerprint        string                  `json:"expectedFingerprint"`
			ConflictFingerprint        string                  `json:"conflictFingerprint"`
		} `json:"adjustment"`
	} `json:"idempotencyVectors"`
	MoneyVectors struct {
		Valid []struct {
			Name              string `json:"name"`
			Raw               string `json:"raw"`
			DisplayExponent   int    `json:"displayExponent"`
			AllowNegative     bool   `json:"allowNegative"`
			ExpectedUnits     string `json:"expectedUnits"`
			ExpectedFormatted string `json:"expectedFormatted"`
		} `json:"valid"`
		Invalid []struct {
			Name            string `json:"name"`
			Raw             string `json:"raw"`
			DisplayExponent int    `json:"displayExponent"`
			AllowNegative   bool   `json:"allowNegative"`
		} `json:"invalid"`
	} `json:"moneyVectors"`
	StatusCodes []struct {
		Code      string `json:"code"`
		Retryable bool   `json:"retryable"`
	} `json:"statusCodes"`
}

func loadVectors(t *testing.T) testVectorsDoc {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "test-vectors.json"))
	if err != nil {
		t.Fatalf("read test-vectors.json: %v", err)
	}
	var doc testVectorsDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal test-vectors.json: %v", err)
	}
	return doc
}

func TestCrossLanguageGoldenVectors(t *testing.T) {
	doc := loadVectors(t)
	for _, v := range doc.HMACVectors {
		if len(v.RawBody) != v.UTF8ByteLength {
			t.Fatalf("%s byte len mismatch", v.Name)
		}
		sig, err := SignBody([]byte(v.RawBody), v.Secret)
		if err != nil || sig != v.Signature {
			t.Fatalf("%s sign mismatch: got %s want %s (err=%v)", v.Name, sig, v.Signature, err)
		}
		if !VerifySignature([]byte(v.RawBody), v.Signature, v.Secret) {
			t.Fatalf("%s verify failed", v.Name)
		}
		if v.WrongBase64DecodedSignature != "" && VerifySignature([]byte(v.RawBody), v.WrongBase64DecodedSignature, v.Secret) {
			t.Fatalf("%s accepted wrong base64-decoded secret signature", v.Name)
		}
	}
	for _, h := range doc.HeaderVerificationVectors {
		got := VerifyWebhookHeaders(h.APIKeyHeader, h.SignatureHeader, []byte(h.RawBody), h.ExpectedAPIKey, h.HMACSecret)
		if got != h.ExpectedStatus {
			t.Fatalf("%s header status got %s want %s", h.Name, got, h.ExpectedStatus)
		}
	}

	idem := doc.IdempotencyVectors
	if BetFingerprint(idem.Bet.Initial) != idem.Bet.ExpectedFingerprint ||
		BetFingerprint(idem.Bet.RetrySameBusiness) != idem.Bet.ExpectedFingerprint ||
		BetFingerprint(idem.Bet.ConflictDifferentAmount) != idem.Bet.ConflictFingerprint {
		t.Fatal("bet fingerprint mismatch")
	}
	if BetResultFingerprint(idem.BetResult.Initial) != idem.BetResult.ExpectedFingerprint ||
		BetResultFingerprint(idem.BetResult.RetrySameBusiness) != idem.BetResult.ExpectedFingerprint ||
		BetResultFingerprint(idem.BetResult.ConflictDifferentWinAmount) != idem.BetResult.ConflictFingerprint {
		t.Fatal("bet_result fingerprint mismatch")
	}
	if RollbackFingerprint(idem.Rollback.Initial) != idem.Rollback.ExpectedFingerprint ||
		RollbackFingerprint(idem.Rollback.RetrySameBusiness) != idem.Rollback.ExpectedFingerprint ||
		RollbackFingerprint(idem.Rollback.ConflictDifferentAmount) != idem.Rollback.ConflictFingerprint {
		t.Fatal("rollback fingerprint mismatch")
	}
	if AdjustmentFingerprint(idem.Adjustment.Initial) != idem.Adjustment.ExpectedFingerprint ||
		AdjustmentFingerprint(idem.Adjustment.RetrySameBusiness) != idem.Adjustment.ExpectedFingerprint ||
		AdjustmentFingerprint(idem.Adjustment.ConflictDifferentDirection) != idem.Adjustment.ConflictFingerprint {
		t.Fatal("adjustment fingerprint mismatch")
	}

	for _, m := range doc.MoneyVectors.Valid {
		u, err := DecimalToLedgerUnits(m.Raw, m.DisplayExponent, m.AllowNegative)
		if err != nil || u.String() != m.ExpectedUnits {
			t.Fatalf("money valid %s units got %v (%v), want %s", m.Name, u, err, m.ExpectedUnits)
		}
		fmtStr, err := LedgerUnitsToDecimal(u, m.DisplayExponent)
		if err != nil || fmtStr != m.ExpectedFormatted {
			t.Fatalf("money valid %s fmt got %s (%v), want %s", m.Name, fmtStr, err, m.ExpectedFormatted)
		}
	}
	for _, inv := range doc.MoneyVectors.Invalid {
		if _, err := DecimalToLedgerUnits(inv.Raw, inv.DisplayExponent, inv.AllowNegative); err == nil {
			t.Fatalf("expected invalid money vector %s to fail", inv.Name)
		}
	}
	for _, sc := range doc.StatusCodes {
		if IsRetryableStatus(sc.Code) != sc.Retryable {
			t.Fatalf("retryable mismatch on %s", sc.Code)
		}
	}
}

func TestS2SClientAndWebhookHTTPServer(t *testing.T) {
	doc := loadVectors(t)
	apiKey := "ak_0123456789abcdef0123456789abcdef"
	secret := "dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s"

	s2sSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		st := VerifyWebhookHeaders(r.Header.Get("X-API-Key"), r.Header.Get("X-Signature"), raw, apiKey, secret)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		if st != SC_OK {
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": st, "message": "bad auth"})
			return
		}
		switch r.URL.Path {
		case "/operator/v1/game/tables":
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"tables": []map[string]any{{"tableId": "T-A2", "currency": "USD"}}, "pageNo": 1, "pageSize": 50, "total": 1}})
		case "/operator/v1/game/url":
			if body["currency"] != "USD" {
				_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_WRONG_CURRENCY, "message": "USD required"})
				return
			}
			tok := "b2bt_" + strings.Repeat("d", 48)
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"gameUrl": "https://play.lt.cniia.cloud/?token=" + tok, "token": tok}})
		case "/operator/v1/game/terminate":
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"username": body["username"], "terminatedSessions": 1, "revokedLaunchTokens": 0}})
		case "/operator/v1/transaction/list":
			pNo := int(body["pageNo"].(float64))
			rows := []map[string]any{
				{"betId": "b2btkt1", "betTransactionId": "bet_tx_1", "settleTransactionId": "stl_tx_1", "payoutVersion": "v1", "isAdjusted": true, "roundOutcome": "PLAYER"},
				{"betId": "b2btkt2"},
			}
			if pNo > 1 {
				rows = []map[string]any{{"betId": "b2btkt3"}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"transactions": rows, "pageNo": pNo, "pageSize": 2, "total": 3}})
		case "/operator/v1/player/status":
			if body["username"] == "locked_user" {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_USER_DISABLED, "message": "PLATFORM_RISK_LOCKED"})
				return
			}
			if body["username"] == "capped_user" && body["bettingEnabled"] == true && body["resetPnlWindow"] != true {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_INVALID_REQUEST, "message": "PNL_CAP_BREACHED_RESET_REQUIRED"})
				return
			}
			_, hasReason := body["reason"]
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"username": body["username"], "status": "ACTIVE", "bettingEnabled": true, "rgRestricted": false, "statusReason": body["reason"], "hasReasonKey": hasReason, "revokedSessions": 0, "revokedLaunchTokens": 0}})
		case "/operator/v1/wallet/transaction-status":
			_, hasFrom := body["fromTime"]
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"hasFromTimeKey": hasFrom, "transactions": []map[string]any{{"transactionId": "bet_go_1", "username": body["username"], "status": "COMPLETED"}}}})
		case "/operator/v1/transaction/detail":
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"betId": body["betId"], "status": 1, "roundResult": map[string]any{"outcome": "PLAYER", "playerPoints": 9, "bankerPoints": 2, "natural": true}}})
		}
	}))
	defer s2sSrv.Close()

	client, err := NewClient(Config{APIKey: apiKey, HMACSecret: secret, BaseURL: s2sSrv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tables, _, err := client.ListTables(ctx, ListTablesRequest{Currency: "USD"})
	if err != nil || tables.Tables[0].TableID != "T-A2" {
		t.Fatalf("listTables failed: %v", err)
	}
	launch, _, err := client.CreateGameUrl(ctx, CreateGameUrlRequest{
		Username: "player_9527", TableID: "T-A2", Platform: "H5", Currency: "USD",
		LobbyURL: "https://merchant.example.com/lobby", IPAddress: "203.0.113.42",
	})
	if err != nil || !strings.HasPrefix(launch.Token, "b2bt_") {
		t.Fatalf("createGameUrl failed: %v", err)
	}
	_, _, err = client.CreateGameUrl(ctx, CreateGameUrlRequest{
		Username: "player_9527", TableID: "T-A2", Platform: "H5", Currency: "JPY",
		LobbyURL: "https://merchant.example.com/lobby", IPAddress: "203.0.113.42",
	})
	var apiErr *ApiError
	if !errors.As(err, &apiErr) || apiErr.Status != SC_WRONG_CURRENCY || apiErr.IsRetryable() {
		t.Fatalf("expected SC_WRONG_CURRENCY ApiError, got %v", err)
	}

	term, _, err := client.TerminateSessions(ctx, TerminateSessionsRequest{Username: "player_9527"})
	if err != nil || term.TerminatedSessions != 1 {
		t.Fatalf("terminate failed: %v", err)
	}
	allRows, err := client.ListAllTransactions(ctx, 1000, 2000, 2)
	if err != nil || len(allRows) != 3 {
		t.Fatalf("listAllTransactions failed: %v (%d)", err, len(allRows))
	}
	if allRows[0].BetTransactionID == nil || *allRows[0].BetTransactionID != "bet_tx_1" ||
		allRows[0].SettleTransactionID == nil || *allRows[0].SettleTransactionID != "stl_tx_1" ||
		allRows[0].PayoutVersion == nil || *allRows[0].PayoutVersion != "v1" ||
		!allRows[0].IsAdjusted ||
		allRows[0].RoundOutcome == nil || *allRows[0].RoundOutcome != "PLAYER" {
		t.Fatalf("expected all 5 extended ReconcileTransactionRow fields populated, got %+v", allRows[0])
	}
	i64 := func(v int64) *int64 { return &v }
	det, _, err := client.GetTransactionDetail(ctx, TransactionDetailRequest{BetID: "b2btkt1", FromTime: i64(1000), ToTime: i64(2000)})
	if err != nil || det.RoundResult == nil || det.RoundResult.Outcome != "PLAYER" {
		t.Fatalf("detail failed: %v", err)
	}
	if _, _, err := client.GetTransactionDetail(ctx, TransactionDetailRequest{BetID: "b2btkt1", FromTime: i64(1000)}); err == nil {
		t.Fatal("expected partial detail window to fail")
	}
	tTrue := true
	emptyReason := ""
	psData, _, err := client.UpdatePlayerStatus(ctx, UpdatePlayerStatusRequest{Username: "capped_user", Action: "SET", BettingEnabled: &tTrue, ResetPnlWindow: &tTrue, Reason: &emptyReason})
	if err != nil || psData["bettingEnabled"] != true || psData["hasReasonKey"] != true || psData["statusReason"] != "" {
		t.Fatalf("updatePlayerStatus reset with explicit empty reason failed: %v %+v", err, psData)
	}
	_, _, err = client.UpdatePlayerStatus(ctx, UpdatePlayerStatusRequest{Username: "locked_user", Action: "SET", Status: "ACTIVE"})
	var apiErr403 *ApiError
	if !errors.As(err, &apiErr403) || apiErr403.HTTPStatus != 403 || apiErr403.Status != SC_USER_DISABLED || apiErr403.Message != "PLATFORM_RISK_LOCKED" || apiErr403.IsRetryable() {
		t.Fatalf("expected non-retryable 403 PLATFORM_RISK_LOCKED, got %v", err)
	}
	_, _, err = client.UpdatePlayerStatus(ctx, UpdatePlayerStatusRequest{Username: "capped_user", Action: "SET", BettingEnabled: &tTrue})
	var apiErr409 *ApiError
	if !errors.As(err, &apiErr409) || apiErr409.HTTPStatus != 409 || apiErr409.Status != SC_INVALID_REQUEST || apiErr409.Message != "PNL_CAP_BREACHED_RESET_REQUIRED" || apiErr409.IsRetryable() {
		t.Fatalf("expected non-retryable 409 PNL_CAP_BREACHED_RESET_REQUIRED, got %v", err)
	}
	wtsData, _, err := client.GetWalletTransactionStatus(ctx, WalletTransactionStatusRequest{Username: "player_9527", FromTime: i64(0), ToTime: i64(86400000)})
	if err != nil || len(wtsData["transactions"].([]any)) != 1 || wtsData["hasFromTimeKey"] != true {
		t.Fatalf("wallet status by username at epoch 0 failed: %v %+v", err, wtsData)
	}
	if _, _, err := client.GetWalletTransactionStatus(ctx, WalletTransactionStatusRequest{Username: "player_9527", FromTime: i64(0), ToTime: i64(0)}); err != nil {
		t.Fatalf("expected [0, 0] window to succeed, got %v", err)
	}
	if _, _, err := client.GetWalletTransactionStatus(ctx, WalletTransactionStatusRequest{}); err == nil {
		t.Fatal("expected empty wallet status query to fail")
	}
	if _, _, err := client.GetWalletTransactionStatus(ctx, WalletTransactionStatusRequest{Username: "player_9527"}); err == nil {
		t.Fatal("expected username query without window to fail")
	}
	if _, _, err := client.GetWalletTransactionStatus(ctx, WalletTransactionStatusRequest{Username: "player_9527", FromTime: i64(0), ToTime: i64(86400001)}); err == nil {
		t.Fatal("expected >24h username query to fail")
	}
	if _, _, err := client.GetWalletTransactionStatus(ctx, WalletTransactionStatusRequest{TransactionID: "bet_1", FromTime: i64(1000)}); err == nil {
		t.Fatal("expected partial window alongside transactionId to fail")
	}
	if _, _, err := client.GetWalletTransactionStatus(ctx, WalletTransactionStatusRequest{BetID: "b2btkt1", FromTime: i64(2000), ToTime: i64(1000)}); err == nil {
		t.Fatal("expected inverted window alongside betId to fail")
	}
	if _, _, err := client.ListUnsettledTransactions(ctx, ListUnsettledRequest{FromTime: i64(1000)}); err == nil {
		t.Fatal("expected partial unsettled window to fail")
	}

	// Webhook HTTP server end-to-end
	tok := "b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819"
	wallet, err := NewInMemoryWallet(map[string]AccountInit{
		"player_9527": {Currency: "USD", Balance: "1000.00", Exponent: 2, Tokens: []string{tok}},
	})
	if err != nil {
		t.Fatal(err)
	}
	disp, err := NewWebhookDispatcher(apiKey, secret, wallet)
	if err != nil {
		t.Fatal(err)
	}
	wbSrv := httptest.NewServer(disp)
	defer wbSrv.Close()

	postWb := func(route string, payload any) WalletResponse {
		raw, _ := json.Marshal(payload)
		sig, _ := SignBody(raw, secret)
		req, _ := http.NewRequest(http.MethodPost, wbSrv.URL+route, bytes.NewReader(raw))
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("X-Signature", sig)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out WalletResponse
		_ = json.NewDecoder(res.Body).Decode(&out)
		return out
	}

	if r := postWb("/wallet/balance", WalletBalanceRequest{TraceID: "t1", Username: "player_9527", Currency: "USD", Token: tok}); r.Status != SC_OK || r.Data.Balance != "1000.00" {
		t.Fatalf("balance failed: %+v", r)
	}
	if r := postWb("/wallet/bet", doc.IdempotencyVectors.Bet.Initial); r.Status != SC_OK || r.Data.Balance != "900.00" {
		t.Fatalf("bet failed: %+v", r)
	}
	if r := postWb("/wallet/bet", doc.IdempotencyVectors.Bet.RetrySameBusiness); r.Status != SC_OK || r.Data.Balance != "900.00" {
		t.Fatalf("bet replay failed: %+v", r)
	}
	if r := postWb("/wallet/bet", doc.IdempotencyVectors.Bet.ConflictDifferentAmount); r.Status != SC_TRANSACTION_DUPLICATED {
		t.Fatalf("bet conflict failed: %+v", r)
	}
	wallet.SetDisabled("player_9527", true)
	if r := postWb("/wallet/bet_result", doc.IdempotencyVectors.BetResult.Initial); r.Status != SC_OK || r.Data.Balance != "1100.00" {
		t.Fatalf("settle after disable failed: %+v", r)
	}
	if r := postWb("/wallet/adjustment", doc.IdempotencyVectors.Adjustment.Initial); r.Status != SC_OK || r.Data.Balance != "1120.00" {
		t.Fatalf("adjustment credit failed: %+v", r)
	}
	if r := postWb("/wallet/adjustment", doc.IdempotencyVectors.Adjustment.RetrySameBusiness); r.Status != SC_OK || r.Data.Balance != "1120.00" {
		t.Fatalf("adjustment replay failed: %+v", r)
	}
	if r := postWb("/wallet/adjustment", doc.IdempotencyVectors.Adjustment.ConflictDifferentDirection); r.Status != SC_TRANSACTION_DUPLICATED {
		t.Fatalf("adjustment conflict failed: %+v", r)
	}
	debitAdj := doc.IdempotencyVectors.Adjustment.Initial
	debitAdj.TransactionID = "adj_debit_go"
	debitAdj.Direction = "DEBIT"
	if r := postWb("/wallet/adjustment", debitAdj); r.Status != SC_OK || r.Data.Balance != "1100.00" {
		t.Fatalf("adjustment debit failed: %+v", r)
	}
	unknownRb := doc.IdempotencyVectors.Rollback.Initial
	unknownRb.TransactionID = "rb_b2btkt000000000000000000000000"
	unknownRb.BetID = "b2btkt000000000000000000000000"
	unknownRb.ExternalTransactionID = "b2btkt000000000000000000000000"
	if r := postWb("/wallet/rollback", unknownRb); r.Status != SC_TRANSACTION_NOT_EXISTS {
		t.Fatalf("empty rollback failed: %+v", r)
	}

	// CR-01..CR-10 regressions: rollback after settle rejected, literal "null" body rejected, zero-stake rejected
	if r := postWb("/wallet/rollback", doc.IdempotencyVectors.Rollback.Initial); r.Status != SC_TRANSACTION_DUPLICATED {
		t.Fatalf("expected rollback after settle to be SC_TRANSACTION_DUPLICATED, got %+v", r)
	}
	nullSig, _ := SignBody([]byte("null"), secret)
	if r := disp.HandleRaw(ctx, "/wallet/balance", apiKey, nullSig, []byte("null")); r.Status != SC_INVALID_REQUEST || r.Message != "request body must be a JSON object" {
		t.Fatalf("expected JSON literal null to be rejected as non-object, got %+v", r)
	}
	wallet.SetDisabled("player_9527", false)
	zeroBet := doc.IdempotencyVectors.Bet.Initial
	zeroBet.TransactionID = "bet_zero_go"
	zeroBet.BetID = "b2btkt_zero_go"
	zeroBet.Amount = "0.00"
	if r := postWb("/wallet/bet", zeroBet); r.Status != SC_INVALID_REQUEST {
		t.Fatalf("expected zero stake to fail, got %+v", r)
	}

	// v1.5.2 regressions: GET -> 405 Method Not Allowed, SendTimestamp -> X-Timestamp, non-JSON 429 -> SC_RATE_LIMITED,
	// ListAllTransactionsWithOptions rate-limit retry + filters, typed BaccaratRevealedCard & TicketAdjustmentItem,
	// and v1.3.0+ additive webhook fields on WalletBetRequest / WalletBetResultRequest
	getRes, err := http.Get(wbSrv.URL + "/wallet/balance")
	if err != nil {
		t.Fatal(err)
	}
	_ = getRes.Body.Close()
	if getRes.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET webhook, got %d", getRes.StatusCode)
	}

	var p1Count int
	var lastTsHeader string
	rlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastTsHeader = r.Header.Get("X-Timestamp")
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		switch r.URL.Path {
		case "/operator/v1/ping":
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Too Many Requests"))
		case "/operator/v1/transaction/list":
			w.Header().Set("Content-Type", "application/json")
			pNo := int(body["pageNo"].(float64))
			if pNo == 1 && p1Count == 0 {
				p1Count++
				_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_RATE_LIMITED, "message": "slow down"})
				return
			}
			rows := []map[string]any{{"betId": "b1"}, {"betId": "b2"}}
			if pNo > 1 {
				rows = []map[string]any{{"betId": "b3"}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"transactions": rows, "pageNo": pNo, "pageSize": 2, "total": 3}})
		case "/operator/v1/transaction/detail":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"traceId": body["traceId"],
				"status":  SC_OK,
				"data": map[string]any{
					"betId": "b1",
					"adjustments": []map[string]any{
						{"transactionId": "adj_1", "direction": "CREDIT", "amount": "20.00", "reasonCode": nil, "referenceNo": "RA-1", "completedAt": 1763612300000},
					},
					"roundResult": map[string]any{
						"outcome":      "PLAYER",
						"playerPoints": 8,
						"bankerPoints": 5,
						"playerCards":  []map[string]any{{"suit": 1, "rank": 3, "label": "♠3"}, {"suit": 2, "rank": 5, "label": "♥5"}},
						"bankerCards":  []map[string]any{{"suit": 3, "rank": 13, "label": "♦K"}, {"suit": 4, "rank": 5, "label": "♣5"}},
					},
				},
			})
		}
	}))
	defer rlSrv.Close()

	tsClient, err := NewClient(Config{APIKey: apiKey, HMACSecret: secret, BaseURL: rlSrv.URL, SendTimestamp: true})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = tsClient.Ping(ctx, PingRequest{})
	var err429 *ApiError
	if !errors.As(err, &err429) || err429.HTTPStatus != 429 || err429.Status != SC_RATE_LIMITED || !err429.IsRetryable() {
		t.Fatalf("expected retryable 429 SC_RATE_LIMITED, got %v", err)
	}
	if len(lastTsHeader) != 13 {
		t.Fatalf("expected 13-digit X-Timestamp header, got %q", lastTsHeader)
	}
	retried, err := tsClient.ListAllTransactionsWithOptions(ctx, ListTransactionsRequest{FromTime: 1000, ToTime: 2000, PageSize: 2, Username: "player_9527"}, 3, 0)
	if err != nil || len(retried) != 3 || p1Count != 1 {
		t.Fatalf("expected 3 retried rows after 1 rate limit, got len=%d p1Count=%d err=%v", len(retried), p1Count, err)
	}
	typedDet, _, err := tsClient.GetTransactionDetail(ctx, TransactionDetailRequest{BetID: "b1"})
	if err != nil || typedDet.RoundResult == nil || len(typedDet.RoundResult.PlayerCards) != 2 || typedDet.RoundResult.PlayerCards[0].Suit != 1 || len(typedDet.Adjustments) != 1 || typedDet.Adjustments[0].ReasonCode != nil {
		t.Fatalf("typed card/adjustment deserialization failed: %+v err=%v", typedDet, err)
	}
	var betCtx WalletBetRequest
	if err := json.Unmarshal([]byte(`{"transactionId":"bet_1","tableId":"T-A2","shoeId":"shoe_1","roundNo":18,"betSide":"PLAYER"}`), &betCtx); err != nil || betCtx.TableID != "T-A2" || betCtx.RoundNo == nil || *betCtx.RoundNo != 18 || betCtx.BetSide == nil || *betCtx.BetSide != "PLAYER" {
		t.Fatalf("WalletBetRequest v1.3.0+ context fields failed: %+v err=%v", betCtx, err)
	}
	var stlCtx WalletBetResultRequest
	if err := json.Unmarshal([]byte(`{"transactionId":"stl_1","tableId":"T-A2","betSide":"PLAYER","roundOutcome":"PLAYER"}`), &stlCtx); err != nil || stlCtx.TableID != "T-A2" || stlCtx.RoundOutcome == nil || *stlCtx.RoundOutcome != "PLAYER" {
		t.Fatalf("WalletBetResultRequest v1.3.0+ context fields failed: %+v err=%v", stlCtx, err)
	}
}

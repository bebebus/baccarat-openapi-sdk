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
	"unicode/utf8"
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

	// Regressions: GET -> 405 Method Not Allowed, SendTimestamp -> X-Timestamp, non-JSON & JSON missing-status 429/503 (M1),
	// 3xx redirect blocked (M7), ClearCustomChips (m4), UTF-8 rune-safe traceId truncation (m10),
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
	var redirectHit bool
	rlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastTsHeader = r.Header.Get("X-Timestamp")
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		switch r.URL.Path {
		case "/leaked":
			redirectHit = true
			w.WriteHeader(http.StatusOK)
		case "/operator/v1/ping":
			switch body["traceId"] {
			case "m1_json_429":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"statusCode":429,"message":"Too Many Requests"}`))
			case "m1_json_503":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"unavailable"}`))
			case "m7_redirect":
				w.Header().Set("Location", "/leaked")
				w.WriteHeader(http.StatusTemporaryRedirect)
			case "m4_overflow":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				chunk := bytes.Repeat([]byte("a"), 65536)
				for i := 0; i < 260; i++ {
					if _, err := w.Write(chunk); err != nil {
						return
					}
				}
			default:
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte("Too Many Requests"))
			}
		case "/operator/v1/player/limits":
			w.Header().Set("Content-Type", "application/json")
			_, hasChips := body["customChips"]
			chipsLen := -1
			if arr, ok := body["customChips"].([]any); ok {
				chipsLen = len(arr)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"hasCustomChips": hasChips, "chipsLen": chipsLen}})
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

	// M1: JSON 429 & 503 with missing status field
	_, _, err = tsClient.Ping(ctx, PingRequest{TraceID: "m1_json_429"})
	var errM1429 *ApiError
	if !errors.As(err, &errM1429) || errM1429.HTTPStatus != 429 || errM1429.Status != SC_RATE_LIMITED || !errM1429.IsRetryable() {
		t.Fatalf("expected retryable 429 SC_RATE_LIMITED for JSON without status, got %v", err)
	}
	_, _, err = tsClient.Ping(ctx, PingRequest{TraceID: "m1_json_503"})
	var errM1503 *ApiError
	if !errors.As(err, &errM1503) || errM1503.HTTPStatus != 503 || errM1503.Status != SC_OPERATOR_TIMEOUT || !errM1503.IsRetryable() {
		t.Fatalf("expected retryable 503 SC_OPERATOR_TIMEOUT for JSON without status, got %v", err)
	}

	// M7: 3xx redirect must NOT be followed
	_, _, err = tsClient.Ping(ctx, PingRequest{TraceID: "m7_redirect"})
	var errRedir *ApiError
	if !errors.As(err, &errRedir) || errRedir.HTTPStatus != http.StatusTemporaryRedirect || redirectHit {
		t.Fatalf("expected 307 without following redirect (redirectHit=%v), got %v", redirectHit, err)
	}

	// P2-4: >16 MiB response body returns non-retryable *ApiError carrying SC_INVALID_REQUEST, HTTPStatus, and TraceID
	_, ovTrace, err := tsClient.Ping(ctx, PingRequest{TraceID: "m4_overflow"})
	var errOv *ApiError
	if !errors.As(err, &errOv) || errOv.Status != SC_INVALID_REQUEST || errOv.HTTPStatus != http.StatusOK || errOv.TraceID != "m4_overflow" || ovTrace != "m4_overflow" || errOv.IsRetryable() {
		t.Fatalf("expected non-retryable ApiError(SC_INVALID_REQUEST, 200, m4_overflow) on >16 MiB overflow, got trace=%q err=%v", ovTrace, err)
	}

	// m4: ClearCustomChips emits explicit "customChips": [] while default omits it
	limClear, _, err := tsClient.UpdatePlayerLimits(ctx, UpdatePlayerLimitsRequest{
		Username: "player_9527", Currency: "USD", Action: "SET", ClearCustomChips: true,
	})
	if err != nil || limClear["hasCustomChips"] != true || limClear["chipsLen"] != float64(0) {
		t.Fatalf("expected ClearCustomChips to send empty customChips array, got %+v err=%v", limClear, err)
	}
	limOmit, _, err := tsClient.UpdatePlayerLimits(ctx, UpdatePlayerLimitsRequest{
		Username: "player_9527", Currency: "USD", Action: "SET",
	})
	if err != nil || limOmit["hasCustomChips"] != false {
		t.Fatalf("expected omitted customChips when ClearCustomChips is false, got %+v err=%v", limOmit, err)
	}

	// m10: UTF-8 rune-safe traceId truncation
	utf8Trace := strings.Repeat("中", 140)
	utf8Body, _ := json.Marshal(map[string]any{"traceId": utf8Trace})
	utf8Sig, _ := SignBody(utf8Body, secret)
	utf8Resp := disp.HandleRaw(ctx, "/wallet/unknown", apiKey, utf8Sig, utf8Body)
	if utf8Resp.Status != SC_INVALID_REQUEST || !utf8.ValidString(utf8Resp.TraceID) || len([]rune(utf8Resp.TraceID)) != 128 {
		t.Fatalf("expected valid 128-rune UTF-8 traceId, got %+v", utf8Resp)
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

type panickingWallet struct {
	InMemoryWallet
}

func (p *panickingWallet) OnBalance(_ context.Context, req WalletBalanceRequest) WalletResponse {
	return WalletError(req.TraceID, SC_INSUFFICIENT_FUNDS, "explicit insufficient")
}

func (p *panickingWallet) OnBet(_ context.Context, req WalletBetRequest) WalletResponse {
	if _, err := DecimalToLedgerUnits(req.Amount, 2, false); err != nil {
		return WalletError(req.TraceID, SC_INVALID_REQUEST, err.Error())
	}
	return WalletOK(req.TraceID, "p1", "USD", "100.00", 0)
}

func (p *panickingWallet) OnBetResult(_ context.Context, req WalletBetResultRequest) WalletResponse {
	if req.TransactionID == "stl_bad_bal" {
		return WalletOK(req.TraceID, "p1", "USD", "-1.00", 0)
	}
	if req.TransactionID == "stl_nan_bal" {
		return WalletOK(req.TraceID, "p1", "USD", "NaN", 0)
	}
	panic("ERROR: deadlock detected (40P01) on table wallets")
}

func TestV155NullClearingBuildersAndPanicSafety(t *testing.T) {
	// 1. UpdatePlayerStatusRequest ClearReason emits explicit "reason": null
	statusOmit, err := json.Marshal(UpdatePlayerStatusRequest{TraceID: "t1", Username: "p1", Action: "SET"})
	if err != nil {
		t.Fatalf("marshal statusOmit: %v", err)
	}
	var mStatusOmit map[string]any
	_ = json.Unmarshal(statusOmit, &mStatusOmit)
	if _, exists := mStatusOmit["reason"]; exists {
		t.Fatalf("expected reason omitted, got %s", string(statusOmit))
	}
	statusClear, err := json.Marshal(UpdatePlayerStatusRequest{TraceID: "t2", Username: "p1", Action: "SET", ClearReason: true})
	if err != nil {
		t.Fatalf("marshal statusClear: %v", err)
	}
	var mStatusClear map[string]any
	_ = json.Unmarshal(statusClear, &mStatusClear)
	if val, exists := mStatusClear["reason"]; !exists || val != nil {
		t.Fatalf("expected explicit reason:null, got %s", string(statusClear))
	}

	// 2. UpdatePlayerLimitsRequest Clear* flags emit explicit JSON null for individual fields
	minBet := "10.00"
	limClear, err := json.Marshal(UpdatePlayerLimitsRequest{
		TraceID:            "t3",
		Username:           "p1",
		Currency:           "USD",
		Action:             "SET",
		MinBet:             &minBet,
		ClearMaxBet:        true,
		ClearMaxTableRound: true,
		ClearMaxUserDay:    true,
		ClearMaxLossPerDay: true,
		ClearCustomChips:   true,
	})
	if err != nil {
		t.Fatalf("marshal limClear: %v", err)
	}
	var mLim map[string]any
	_ = json.Unmarshal(limClear, &mLim)
	if mLim["minBet"] != "10.00" {
		t.Fatalf("expected minBet=10.00, got %s", string(limClear))
	}
	for _, k := range []string{"maxBet", "maxTableRound", "maxUserDay", "maxLossPerDay"} {
		if val, exists := mLim[k]; !exists || val != nil {
			t.Fatalf("expected %s:null, got %s", k, string(limClear))
		}
	}
	if chips, ok := mLim["customChips"].([]any); !ok || len(chips) != 0 {
		t.Fatalf("expected customChips:[], got %s", string(limClear))
	}
	limClearMin, err := json.Marshal(UpdatePlayerLimitsRequest{
		TraceID: "t4", Username: "p1", Currency: "USD", Action: "SET", ClearMinBet: true,
	})
	if err != nil {
		t.Fatalf("marshal limClearMin: %v", err)
	}
	var mLimMin map[string]any
	_ = json.Unmarshal(limClearMin, &mLimMin)
	if val, exists := mLimMin["minBet"]; !exists || val != nil {
		t.Fatalf("expected minBet:null, got %s", string(limClearMin))
	}

	// 3. WalletOK / WalletError builders & defensive validation
	okResp := WalletOK("t_ok", "player_1", "JPY", "0", 0)
	if okResp.Status != SC_OK || okResp.Data == nil || okResp.Data.Balance != "0" || okResp.Data.Timestamp <= 0 {
		t.Fatalf("WalletOK unexpected: %+v", okResp)
	}
	errResp := WalletError("t_err", SC_INSUFFICIENT_FUNDS, "low balance")
	if errResp.Status != SC_INSUFFICIENT_FUNDS || errResp.Message != "low balance" {
		t.Fatalf("WalletError unexpected: %+v", errResp)
	}
	for _, badStatus := range []string{"", "   ", SC_OK, " SC_OK ", "sc_ok", "Sc_Ok", " sc_ok ", "SC_", "SC_TIMEOUT", "SC_CUSTOM", "INSUFFICIENT_FUNDS"} {
		coerced := WalletError("t_coerce", badStatus, "guarded")
		if coerced.Status != SC_OPERATOR_TIMEOUT || coerced.Message != "Temporary wallet handler error" {
			t.Fatalf("WalletError(%q) expected coerced retryable SC_OPERATOR_TIMEOUT, got %+v", badStatus, coerced)
		}
		coercedEmpty := WalletError("t_coerce_empty", badStatus, "")
		if coercedEmpty.Status != SC_OPERATOR_TIMEOUT || coercedEmpty.Message != "Temporary wallet handler error" {
			t.Fatalf("WalletError(%q, empty) expected coerced retryable SC_OPERATOR_TIMEOUT, got %+v", badStatus, coercedEmpty)
		}
	}
	for _, badBal := range []string{"", "   ", "-1.00", "abc", "10.", ".5", "10.00 "} {
		panicked := false
		func() {
			defer func() {
				if recover() != nil {
					panicked = true
				}
			}()
			_ = WalletOK("t_bad", "player_1", "USD", badBal, 0)
		}()
		if !panicked {
			t.Fatalf("expected WalletOK(%q) to panic", badBal)
		}
	}

	// 4. Panic recovery in WebhookDispatcher.HandleRaw maps to retryable SC_OPERATOR_TIMEOUT without leaking panic payload
	apiKey := "ak_0123456789abcdef0123456789abcdef"
	secret := "dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s"
	pw := &panickingWallet{}
	disp, err := NewWebhookDispatcher(apiKey, secret, pw)
	if err != nil {
		t.Fatalf("NewWebhookDispatcher: %v", err)
	}
	raw := []byte(`{"traceId":"t_go_panic","transactionId":"stl_1","betId":"b1"}`)
	sig, _ := SignBody(raw, secret)
	resp := disp.HandleRaw(context.Background(), "/wallet/bet_result", apiKey, sig, raw)
	if resp.Status != SC_OPERATOR_TIMEOUT || resp.TraceID != "t_go_panic" || resp.Message != "Temporary wallet handler error" {
		t.Fatalf("expected sanitized SC_OPERATOR_TIMEOUT on panic, got %+v", resp)
	}
	if strings.Contains(resp.Message, "40P01") || strings.Contains(resp.Message, "deadlock") {
		t.Fatalf("panic payload leaked: %q", resp.Message)
	}
	for _, txID := range []string{"stl_bad_bal", "stl_nan_bal"} {
		bbRaw := []byte(`{"traceId":"t_go_` + txID + `","transactionId":"` + txID + `","betId":"b1"}`)
		bbSig, _ := SignBody(bbRaw, secret)
		bbResp := disp.HandleRaw(context.Background(), "/wallet/bet_result", apiKey, bbSig, bbRaw)
		if bbResp.Status != SC_OPERATOR_TIMEOUT || bbResp.TraceID != "t_go_"+txID || bbResp.Message != "Temporary wallet handler error" {
			t.Fatalf("expected sanitized SC_OPERATOR_TIMEOUT for %s, got %+v", txID, bbResp)
		}
		if strings.Contains(bbResp.Message, "WalletOK") {
			t.Fatalf("validator detail leaked: %q", bbResp.Message)
		}
	}
	for _, badAmt := range []string{"not_a_number", "1.123456", "-5.00"} {
		bdRaw := []byte(`{"traceId":"t_go_bad_dec","amount":"` + badAmt + `"}`)
		bdSig, _ := SignBody(bdRaw, secret)
		bdResp := disp.HandleRaw(context.Background(), "/wallet/bet", apiKey, bdSig, bdRaw)
		if bdResp.Status != SC_INVALID_REQUEST {
			t.Fatalf("expected SC_INVALID_REQUEST for bad decimal %q, got %+v", badAmt, bdResp)
		}
	}
	balRaw := []byte(`{"traceId":"t_go_insuff"}`)
	balSig, _ := SignBody(balRaw, secret)
	balResp := disp.HandleRaw(context.Background(), "/wallet/balance", apiKey, balSig, balRaw)
	if balResp.Status != SC_INSUFFICIENT_FUNDS {
		t.Fatalf("expected SC_INSUFFICIENT_FUNDS, got %+v", balResp)
	}
}

func TestV1511CustomHTTPClientRedirectDuplicateHeadersAndStrictUTF8(t *testing.T) {
	apiKey := "ak_0123456789abcdef0123456789abcdef"
	secret := "dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s"

	// P2-2: custom cfg.HTTPClient with CheckRedirect == nil refuses 302 redirects cleanly without mutating caller's struct
	redirectFollowed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirected" {
			redirectFollowed = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"traceId":"t_redir","status":"SC_OK","data":{}}`))
			return
		}
		http.Redirect(w, r, "/redirected", http.StatusFound)
	}))
	defer srv.Close()

	callerHC := &http.Client{}
	c, err := NewClient(Config{
		APIKey:      apiKey,
		HMACSecret:  secret,
		Environment: EnvProduction,
		BaseURL:     srv.URL,
		HTTPClient:  callerHC,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if callerHC.CheckRedirect != nil || callerHC.Timeout != 0 {
		t.Fatalf("NewClient must not mutate caller's http.Client struct")
	}
	_, _, err = c.Ping(context.Background(), PingRequest{TraceID: "t_go_302"})
	var apiErr *ApiError
	if !errors.As(err, &apiErr) || apiErr.HTTPStatus != http.StatusFound {
		t.Fatalf("expected ApiError with HTTP 302 on redirect, got %T %v", err, err)
	}
	if redirectFollowed {
		t.Fatalf("custom HTTPClient unexpectedly followed 302 redirect")
	}

	// P3-1: WebhookDispatcher.ServeHTTP rejects duplicate X-API-Key and duplicate X-Signature headers
	wallet, err := NewInMemoryWallet(map[string]AccountInit{
		"alice": {Currency: "USD", Balance: "100.00", Exponent: 2},
	})
	if err != nil {
		t.Fatalf("NewInMemoryWallet: %v", err)
	}
	disp, err := NewWebhookDispatcher(apiKey, secret, wallet)
	if err != nil {
		t.Fatalf("NewWebhookDispatcher: %v", err)
	}
	validBody := []byte(`{"traceId":"t_dup_hdr","username":"alice","currency":"USD"}`)
	validSig, err := SignBody(validBody, secret)
	if err != nil {
		t.Fatalf("SignBody: %v", err)
	}

	dupKeyReq := httptest.NewRequest(http.MethodPost, "/wallet/balance", bytes.NewReader(validBody))
	dupKeyReq.Header.Add("X-API-Key", apiKey)
	dupKeyReq.Header.Add("X-API-Key", "ak_other")
	dupKeyReq.Header.Set("X-Signature", validSig)
	dupKeyRec := httptest.NewRecorder()
	disp.ServeHTTP(dupKeyRec, dupKeyReq)
	var dupKeyResp WalletResponse
	if err := json.Unmarshal(dupKeyRec.Body.Bytes(), &dupKeyResp); err != nil {
		t.Fatalf("unmarshal dupKeyResp: %v", err)
	}
	if dupKeyResp.Status != SC_AUTHENTICATION_FAILED {
		t.Fatalf("expected SC_AUTHENTICATION_FAILED for duplicate X-API-Key, got %+v", dupKeyResp)
	}

	dupSigReq := httptest.NewRequest(http.MethodPost, "/wallet/balance", bytes.NewReader(validBody))
	dupSigReq.Header.Set("X-API-Key", apiKey)
	dupSigReq.Header.Add("X-Signature", validSig)
	dupSigReq.Header.Add("X-Signature", validSig)
	dupSigRec := httptest.NewRecorder()
	disp.ServeHTTP(dupSigRec, dupSigReq)
	var dupSigResp WalletResponse
	if err := json.Unmarshal(dupSigRec.Body.Bytes(), &dupSigResp); err != nil {
		t.Fatalf("unmarshal dupSigResp: %v", err)
	}
	if dupSigResp.Status != SC_INVALID_SIGNATURE {
		t.Fatalf("expected SC_INVALID_SIGNATURE for duplicate X-Signature, got %+v", dupSigResp)
	}

	// P3-2: strict UTF-8 validation in WebhookDispatcher.HandleRaw
	badUTF8 := []byte("{\"traceId\":\"t1\xff\",\"username\":\"alice\"}")
	badUTF8Sig, err := SignBody(badUTF8, secret)
	if err != nil {
		t.Fatalf("SignBody badUTF8: %v", err)
	}
	badUTF8Resp := disp.HandleRaw(context.Background(), "/wallet/balance", apiKey, badUTF8Sig, badUTF8)
	if badUTF8Resp.Status != SC_INVALID_REQUEST || badUTF8Resp.TraceID != "" {
		t.Fatalf("expected SC_INVALID_REQUEST with empty traceId on invalid UTF-8, got %+v", badUTF8Resp)
	}
}

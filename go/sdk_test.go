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
			rows := []map[string]any{{"betId": "b2btkt1"}, {"betId": "b2btkt2"}}
			if pNo > 1 {
				rows = []map[string]any{{"betId": "b2btkt3"}}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"traceId": body["traceId"], "status": SC_OK, "data": map[string]any{"transactions": rows, "pageNo": pNo, "pageSize": 2, "total": 3}})
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
	det, _, err := client.GetTransactionDetail(ctx, TransactionDetailRequest{BetID: "b2btkt1", FromTime: 1000, ToTime: 2000})
	if err != nil || det.RoundResult == nil || det.RoundResult.Outcome != "PLAYER" {
		t.Fatalf("detail failed: %v", err)
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
}

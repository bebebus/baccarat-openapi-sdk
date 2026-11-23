// SPDX-License-Identifier: MIT
// Package baccarat provides a zero-dependency Go SDK for the Baccarat Live Platform
// B2B Operator Seamless Wallet API (v1.4.0).
package baccarat

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SandboxBaseURL       = "https://api.lt.cniia.cloud"
	MaxDetailWindowMs    = int64(604_800_000) // 7 days in ms
	MaxPageSize          = 20_000
	MaxWebhookBodyBytes  = 1_048_576          // 1 MiB
	maxHTTPResponseBytes = 16 * 1024 * 1024   // 16 MiB

	EnvSandbox    = "SANDBOX"
	EnvProduction = "PRODUCTION"

	SC_OK                           = "SC_OK"
	SC_INVALID_REQUEST              = "SC_INVALID_REQUEST"
	SC_AUTHENTICATION_FAILED        = "SC_AUTHENTICATION_FAILED"
	SC_INVALID_SIGNATURE            = "SC_INVALID_SIGNATURE"
	SC_INVALID_TOKEN                = "SC_INVALID_TOKEN"
	SC_INVALID_GAME                 = "SC_INVALID_GAME"
	SC_USER_NOT_EXISTS              = "SC_USER_NOT_EXISTS"
	SC_USER_DISABLED                = "SC_USER_DISABLED"
	SC_WRONG_CURRENCY               = "SC_WRONG_CURRENCY"
	SC_CURRENCY_NOT_SUPPORTED       = "SC_CURRENCY_NOT_SUPPORTED"
	SC_INSUFFICIENT_FUNDS           = "SC_INSUFFICIENT_FUNDS"
	SC_TRANSACTION_DUPLICATED       = "SC_TRANSACTION_DUPLICATED"
	SC_TRANSACTION_NOT_EXISTS       = "SC_TRANSACTION_NOT_EXISTS"
	SC_TRANSACTION_STILL_PROCESSING = "SC_TRANSACTION_STILL_PROCESSING"
	SC_OPERATOR_TIMEOUT             = "SC_OPERATOR_TIMEOUT"
	SC_UNDER_MAINTENANCE            = "SC_UNDER_MAINTENANCE"
	SC_GAME_DISABLED                = "SC_GAME_DISABLED"
	SC_RATE_LIMITED                 = "SC_RATE_LIMITED"
)

var (
	hex64Re     = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	decimalRe   = regexp.MustCompile(`^(-?)(\d+)(?:\.(\d+))?$`)
	traceHintRe = regexp.MustCompile(`"traceId"\s*:\s*"([A-Za-z0-9_.:-]{1,128})"`)
)

func IsRetryableStatus(status string) bool {
	s := strings.TrimSpace(status)
	return s == SC_TRANSACTION_STILL_PROCESSING || s == SC_OPERATOR_TIMEOUT || s == SC_RATE_LIMITED
}

type SdkError struct {
	Code    string
	Message string
}

func (e *SdkError) Error() string {
	return e.Message
}

type ApiError struct {
	TraceID    string
	Status     string
	Message    string
	Validation map[string]string
	HTTPStatus int
}

func (e *ApiError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("B2B API error: %s", e.Status)
}

func (e *ApiError) IsRetryable() bool {
	return IsRetryableStatus(e.Status)
}

// ── 1. Raw-Byte HMAC-SHA256 Signing & Timing-Safe Verification ──────────────

func SignBody(rawBody []byte, hmacSecret string) (string, error) {
	if hmacSecret == "" {
		return "", &SdkError{Code: "INVALID_CONFIG", Message: "hmacSecret must be non-empty"}
	}
	// CRITICAL: Use raw UTF-8 string bytes of hmacSecret directly — NEVER Base64-decode!
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write(rawBody)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func VerifySignature(rawBody []byte, signatureHeader string, hmacSecret string) bool {
	if hmacSecret == "" {
		return false
	}
	trimmed := strings.TrimSpace(signatureHeader)
	if !hex64Re.MatchString(trimmed) {
		return false
	}
	actualBytes, err := hex.DecodeString(strings.ToLower(trimmed))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(hmacSecret))
	mac.Write(rawBody)
	expectedBytes := mac.Sum(nil)
	return hmac.Equal(actualBytes, expectedBytes)
}

func VerifyWebhookHeaders(apiKeyHeader, signatureHeader string, rawBody []byte, expectedApiKey, hmacSecret string) string {
	expKey := strings.TrimSpace(expectedApiKey)
	actKey := strings.TrimSpace(apiKeyHeader)
	if expKey == "" || actKey == "" || subtle.ConstantTimeCompare([]byte(actKey), []byte(expKey)) != 1 {
		return SC_AUTHENTICATION_FAILED
	}
	if !VerifySignature(rawBody, signatureHeader, hmacSecret) {
		return SC_INVALID_SIGNATURE
	}
	return SC_OK
}

// ── 2. Arbitrary-Precision Decimal <-> Ledger Units (math/big.Int) ──────────

func DecimalToLedgerUnits(raw string, displayExponent int, allowNegative bool) (*big.Int, error) {
	if displayExponent < 0 || displayExponent > 18 {
		return nil, &SdkError{Code: "INVALID_DISPLAY_EXPONENT", Message: "displayExponent out of range 0..18"}
	}
	text := strings.TrimSpace(raw)
	m := decimalRe.FindStringSubmatch(text)
	if m == nil {
		return nil, &SdkError{Code: "INVALID_DECIMAL_AMOUNT", Message: "malformed decimal amount: " + raw}
	}
	negative := m[1] == "-"
	wholePart := m[2]
	rawFrac := m[3]
	scaleDigits := displayExponent + 3
	trimmedFrac := strings.TrimRight(rawFrac, "0")
	if len(trimmedFrac) > scaleDigits {
		return nil, &SdkError{Code: "DECIMAL_PRECISION_EXCEEDED", Message: "decimal precision exceeded"}
	}
	fracPadded := trimmedFrac + strings.Repeat("0", scaleDigits-len(trimmedFrac))
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scaleDigits)), nil)

	wholeInt, ok := new(big.Int).SetString(wholePart, 10)
	if !ok {
		return nil, &SdkError{Code: "INVALID_DECIMAL_AMOUNT", Message: "invalid whole part"}
	}
	fracInt := big.NewInt(0)
	if fracPadded != "" {
		fracInt, _ = new(big.Int).SetString(fracPadded, 10)
	}
	abs := new(big.Int).Mul(wholeInt, divisor)
	abs.Add(abs, fracInt)
	if negative && abs.Sign() > 0 {
		if !allowNegative {
			return nil, &SdkError{Code: "NEGATIVE_DECIMAL_FORBIDDEN", Message: "negative decimal amount forbidden"}
		}
		return abs.Neg(abs), nil
	}
	return abs, nil
}

func LedgerUnitsToDecimal(amount *big.Int, displayExponent int) (string, error) {
	if displayExponent < 0 || displayExponent > 18 {
		return "", &SdkError{Code: "INVALID_DISPLAY_EXPONENT", Message: "displayExponent out of range 0..18"}
	}
	if amount == nil {
		amount = big.NewInt(0)
	}
	negative := amount.Sign() < 0
	abs := new(big.Int).Abs(amount)
	scaleDigits := displayExponent + 3
	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(scaleDigits)), nil)
	whole, frac := new(big.Int).QuoRem(abs, divisor, new(big.Int))
	sign := ""
	if negative {
		sign = "-"
	}
	if displayExponent == 0 {
		if frac.Sign() == 0 {
			return sign + whole.String(), nil
		}
		fracStr := frac.String()
		if len(fracStr) < 3 {
			fracStr = strings.Repeat("0", 3-len(fracStr)) + fracStr
		}
		sub := strings.TrimRight(fracStr, "0")
		return sign + whole.String() + "." + sub, nil
	}
	fracStr := frac.String()
	if len(fracStr) < scaleDigits {
		fracStr = strings.Repeat("0", scaleDigits-len(fracStr)) + fracStr
	}
	shown := fracStr[:displayExponent]
	sub := strings.TrimRight(fracStr[displayExponent:], "0")
	return sign + whole.String() + "." + shown + sub, nil
}

// ── 3. Canonical Idempotency Fingerprints ───────────────────────────────────

func EncodeTupleFingerprint(domain string, fields []string) string {
	var b strings.Builder
	b.WriteString("v1|")
	b.WriteString(domain)
	for _, f := range fields {
		b.WriteByte('|')
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

type WalletBalanceRequest struct {
	TraceID  string `json:"traceId"`
	Username string `json:"username"`
	Currency string `json:"currency"`
	Token    string `json:"token"`
}

type WalletBetRequest struct {
	TraceID               string `json:"traceId"`
	Username              string `json:"username"`
	TransactionID         string `json:"transactionId"`
	BetID                 string `json:"betId"`
	ExternalTransactionID string `json:"externalTransactionId"`
	Amount                string `json:"amount"`
	Currency              string `json:"currency"`
	Token                 string `json:"token"`
	GameCode              string `json:"gameCode"`
	RoundID               string `json:"roundId"`
	Timestamp             int64  `json:"timestamp"`
}

type WalletBetResultRequest struct {
	TraceID               string `json:"traceId"`
	Username              string `json:"username"`
	TransactionID         string `json:"transactionId"`
	BetID                 string `json:"betId"`
	ExternalTransactionID string `json:"externalTransactionId"`
	RoundID               string `json:"roundId"`
	BetAmount             string `json:"betAmount"`
	WinAmount             string `json:"winAmount"`
	EffectiveTurnover     string `json:"effectiveTurnover"`
	WinLoss               string `json:"winLoss"`
	JackpotAmount         string `json:"jackpotAmount"`
	ResultType            string `json:"resultType"`
	IsFreespin            int    `json:"isFreespin"`
	IsEndRound            int    `json:"isEndRound"`
	Currency              string `json:"currency"`
	Token                 string `json:"token"`
	GameCode              string `json:"gameCode"`
	BetTime               int64  `json:"betTime"`
	SettledTime           int64  `json:"settledTime"`
}

type WalletRollbackRequest struct {
	TraceID               string `json:"traceId"`
	Username              string `json:"username"`
	TransactionID         string `json:"transactionId"`
	BetID                 string `json:"betId"`
	ExternalTransactionID string `json:"externalTransactionId"`
	RoundID               string `json:"roundId"`
	Amount                string `json:"amount"`
	Currency              string `json:"currency"`
	Token                 string `json:"token"`
	GameCode              string `json:"gameCode"`
	Timestamp             int64  `json:"timestamp"`
}

type WalletAdjustmentRequest struct {
	TraceID               string `json:"traceId"`
	Username              string `json:"username"`
	TransactionID         string `json:"transactionId"`
	BetID                 string `json:"betId"`
	ExternalTransactionID string `json:"externalTransactionId"`
	RoundID               string `json:"roundId"`
	Direction             string `json:"direction"`
	Amount                string `json:"amount"`
	Currency              string `json:"currency"`
	ReasonCode            string `json:"reasonCode"`
	ReferenceNo           string `json:"referenceNo,omitempty"`
	Memo                  string `json:"memo,omitempty"`
	Token                 string `json:"token,omitempty"`
	GameCode              string `json:"gameCode"`
	Timestamp             int64  `json:"timestamp"`
}

func BetFingerprint(p WalletBetRequest) string {
	return EncodeTupleFingerprint("wallet/bet", []string{
		p.TransactionID, p.Username, p.BetID, p.ExternalTransactionID,
		p.RoundID, p.Currency, p.GameCode, p.Amount,
	})
}

func BetResultFingerprint(p WalletBetResultRequest) string {
	return EncodeTupleFingerprint("wallet/bet_result", []string{
		p.TransactionID, p.Username, p.BetID, p.ExternalTransactionID,
		p.RoundID, p.Currency, p.GameCode, p.BetAmount, p.WinAmount,
		p.EffectiveTurnover, p.WinLoss, p.JackpotAmount, p.ResultType,
		strconv.Itoa(p.IsFreespin), strconv.Itoa(p.IsEndRound), strconv.FormatInt(p.BetTime, 10),
	})
}

func RollbackFingerprint(p WalletRollbackRequest) string {
	return EncodeTupleFingerprint("wallet/rollback", []string{
		p.TransactionID, p.Username, p.BetID, p.ExternalTransactionID,
		p.RoundID, p.Currency, p.GameCode, p.Amount,
	})
}

func AdjustmentFingerprint(p WalletAdjustmentRequest) string {
	return EncodeTupleFingerprint("wallet/adjustment", []string{
		p.TransactionID, p.Username, p.BetID, p.ExternalTransactionID,
		p.RoundID, p.Currency, p.GameCode, p.Direction, p.Amount, p.ReasonCode,
	})
}

// ── 4. Config & S2S Client (/operator/v1/*) ─────────────────────────────────

type Config struct {
	APIKey      string
	HMACSecret  string
	Environment string
	BaseURL     string
	Timeout     time.Duration
	HTTPClient  *http.Client
}

type Client struct {
	apiKey     string
	hmacSecret string
	baseURL    string
	httpClient *http.Client
}

func NewClient(cfg Config) (*Client, error) {
	key := strings.TrimSpace(cfg.APIKey)
	if key == "" {
		return nil, &SdkError{Code: "INVALID_CONFIG", Message: "APIKey is required"}
	}
	if cfg.HMACSecret == "" {
		return nil, &SdkError{Code: "INVALID_CONFIG", Message: "HMACSecret is required"}
	}
	env := cfg.Environment
	if env == "" {
		env = EnvProduction
	}
	base := strings.TrimSpace(cfg.BaseURL)
	if base == "" {
		if env == EnvSandbox {
			base = SandboxBaseURL
		} else {
			return nil, &SdkError{Code: "INVALID_CONFIG", Message: "BaseURL is required when Environment is PRODUCTION"}
		}
	}
	lower := strings.ToLower(base)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return nil, &SdkError{Code: "INVALID_CONFIG", Message: "BaseURL must start with http:// or https://"}
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: timeout}
	}
	return &Client{
		apiKey:     key,
		hmacSecret: cfg.HMACSecret,
		baseURL:    strings.TrimRight(base, "/"),
		httpClient: hc,
	}, nil
}

func newUUIDv4() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func marshalNoEscapeHTML(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

func isJSONObjectBytes(raw []byte) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

type rawEnvelope struct {
	TraceID    string            `json:"traceId"`
	Status     string            `json:"status"`
	Message    string            `json:"message"`
	Validation map[string]string `json:"validation"`
	Data       json.RawMessage   `json:"data"`
}

func (c *Client) postSigned(ctx context.Context, route string, reqBody any, traceID string, outData any) (string, error) {
	rawBytes, err := marshalNoEscapeHTML(reqBody)
	if err != nil {
		return "", err
	}
	sig, err := SignBody(rawBytes, c.hmacSecret)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+route, bytes.NewReader(rawBytes))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("X-API-Key", c.apiKey)
	httpReq.Header.Set("X-Signature", sig)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", &SdkError{Code: SC_OPERATOR_TIMEOUT, Message: "network error: " + err.Error()}
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes+1))
	if err != nil {
		return "", &SdkError{Code: SC_OPERATOR_TIMEOUT, Message: "read error: " + err.Error()}
	}
	if len(respBytes) > maxHTTPResponseBytes {
		return "", &SdkError{Code: SC_INVALID_REQUEST, Message: "gateway response exceeded 16 MiB limit"}
	}
	var env rawEnvelope
	if !isJSONObjectBytes(respBytes) || json.Unmarshal(respBytes, &env) != nil {
		st := SC_INVALID_REQUEST
		if resp.StatusCode >= 500 || resp.StatusCode == 408 || resp.StatusCode == 429 {
			st = SC_OPERATOR_TIMEOUT
		}
		return "", &ApiError{TraceID: traceID, Status: st, Message: fmt.Sprintf("non-JSON HTTP %d", resp.StatusCode), HTTPStatus: resp.StatusCode}
	}
	effTrace := env.TraceID
	if effTrace == "" {
		effTrace = traceID
	}
	if resp.StatusCode != http.StatusOK || env.Status != SC_OK {
		st := env.Status
		if st == "" {
			st = SC_INVALID_REQUEST
		}
		return effTrace, &ApiError{
			TraceID:    effTrace,
			Status:     st,
			Message:    env.Message,
			Validation: env.Validation,
			HTTPStatus: resp.StatusCode,
		}
	}
	if outData != nil && len(env.Data) > 0 {
		if err := json.Unmarshal(env.Data, outData); err != nil {
			return effTrace, err
		}
	}
	return effTrace, nil
}

type PingRequest struct {
	TraceID string `json:"traceId"`
}

type PingData struct {
	OperatorID        string   `json:"operatorId"`
	Status            string   `json:"status"`
	ServerTime        int64    `json:"serverTime"`
	AllowedCurrencies []string `json:"allowedCurrencies"`
	AllowedTableCount int      `json:"allowedTableCount"`
}

func (c *Client) Ping(ctx context.Context, req PingRequest) (*PingData, string, error) {
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data PingData
	traceID, err := c.postSigned(ctx, "/operator/v1/ping", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return &data, traceID, nil
}

type CreateGameUrlRequest struct {
	TraceID   string `json:"traceId"`
	Username  string `json:"username"`
	TableID   string `json:"tableId,omitempty"`
	EntryMode string `json:"entryMode,omitempty"`
	Language  string `json:"language,omitempty"`
	Platform  string `json:"platform"`
	Currency  string `json:"currency"`
	LobbyURL  string `json:"lobbyUrl"`
	IPAddress string `json:"ipAddress"`
}

type CreateGameUrlData struct {
	GameURL   string  `json:"gameUrl"`
	Token     string  `json:"token"`
	EntryMode string  `json:"entryMode,omitempty"`
	TableID   *string `json:"tableId,omitempty"`
}

func (c *Client) CreateGameUrl(ctx context.Context, req CreateGameUrlRequest) (*CreateGameUrlData, string, error) {
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data CreateGameUrlData
	traceID, err := c.postSigned(ctx, "/operator/v1/game/url", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return &data, traceID, nil
}

type ListTablesRequest struct {
	TraceID  string `json:"traceId"`
	Currency string `json:"currency,omitempty"`
	PageNo   int    `json:"pageNo,omitempty"`
	PageSize int    `json:"pageSize,omitempty"`
}

type TableCatalogItem struct {
	TableID       string   `json:"tableId"`
	GameCode      string   `json:"gameCode"`
	TableName     string   `json:"tableName"`
	GameType      string   `json:"gameType"`
	Currency      string   `json:"currency"`
	Status        string   `json:"status"`
	MinBet        *string  `json:"minBet"`
	MaxBet        *string  `json:"maxBet"`
	ChipUnit      *string  `json:"chipUnit"`
	Languages     []string `json:"languages"`
	Platforms     []string `json:"platforms"`
	CoverImageURL *string  `json:"coverImageUrl"`
}

type ListTablesData struct {
	Tables   []TableCatalogItem `json:"tables"`
	PageNo   int                `json:"pageNo"`
	PageSize int                `json:"pageSize"`
	Total    int                `json:"total"`
}

func (c *Client) ListTables(ctx context.Context, req ListTablesRequest) (*ListTablesData, string, error) {
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data ListTablesData
	traceID, err := c.postSigned(ctx, "/operator/v1/game/tables", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return &data, traceID, nil
}

type TerminateSessionsRequest struct {
	TraceID  string `json:"traceId"`
	Username string `json:"username,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

type TerminateSessionsData struct {
	Scope               string `json:"scope,omitempty"`
	Username            string `json:"username,omitempty"`
	TerminatedSessions  int    `json:"terminatedSessions"`
	RevokedLaunchTokens int    `json:"revokedLaunchTokens"`
}

func (c *Client) TerminateSessions(ctx context.Context, req TerminateSessionsRequest) (*TerminateSessionsData, string, error) {
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data TerminateSessionsData
	traceID, err := c.postSigned(ctx, "/operator/v1/game/terminate", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return &data, traceID, nil
}

type UpdatePlayerStatusRequest struct {
	TraceID        string `json:"traceId"`
	Username       string `json:"username"`
	Status         string `json:"status,omitempty"`
	BettingEnabled *bool  `json:"bettingEnabled,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

func (c *Client) UpdatePlayerStatus(ctx context.Context, req UpdatePlayerStatusRequest) (map[string]any, string, error) {
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data map[string]any
	traceID, err := c.postSigned(ctx, "/operator/v1/player/status", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return data, traceID, nil
}

type UpdatePlayerLimitsRequest struct {
	TraceID       string   `json:"traceId"`
	Username      string   `json:"username"`
	Currency      string   `json:"currency"`
	MinBet        *string  `json:"minBet,omitempty"`
	MaxBet        *string  `json:"maxBet,omitempty"`
	MaxTableRound *string  `json:"maxTableRound,omitempty"`
	MaxUserDay    *string  `json:"maxUserDay,omitempty"`
	MaxLossPerDay *string  `json:"maxLossPerDay,omitempty"`
	CustomChips   []string `json:"customChips,omitempty"`
}

func (c *Client) UpdatePlayerLimits(ctx context.Context, req UpdatePlayerLimitsRequest) (map[string]any, string, error) {
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data map[string]any
	traceID, err := c.postSigned(ctx, "/operator/v1/player/limits", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return data, traceID, nil
}

type ListTransactionsRequest struct {
	TraceID  string `json:"traceId"`
	FromTime int64  `json:"fromTime"`
	ToTime   int64  `json:"toTime"`
	TimeType string `json:"timeType,omitempty"`
	Status   *int   `json:"status,omitempty"`
	Username string `json:"username,omitempty"`
	TableID  string `json:"tableId,omitempty"`
	RoundID  string `json:"roundId,omitempty"`
	PageNo   int    `json:"pageNo,omitempty"`
	PageSize int    `json:"pageSize,omitempty"`
}

type ReconcileTransactionRow struct {
	BetID                 string `json:"betId"`
	RoundID               string `json:"roundId"`
	ExternalTransactionID string `json:"externalTransactionId"`
	Username              string `json:"username"`
	CurrencyCode          string `json:"currencyCode"`
	GameCode              string `json:"gameCode"`
	BetSide               string `json:"betSide"`
	BetAmount             string `json:"betAmount"`
	WinAmount             string `json:"winAmount"`
	WinLoss               string `json:"winLoss"`
	EffectiveTurnover     string `json:"effectiveTurnover"`
	Status                int    `json:"status"`
	VendorBetTime         int64  `json:"vendorBetTime"`
	VendorSettleTime      *int64 `json:"vendorSettleTime"`
}

type ListTransactionsData struct {
	Transactions []ReconcileTransactionRow `json:"transactions"`
	PageNo       int                       `json:"pageNo"`
	PageSize     int                       `json:"pageSize"`
	Total        int                       `json:"total"`
}

func (c *Client) ListTransactions(ctx context.Context, req ListTransactionsRequest) (*ListTransactionsData, string, error) {
	if req.FromTime < 0 || req.ToTime < req.FromTime {
		return nil, "", &SdkError{Code: "INVALID_ARGUMENT", Message: "invalid [FromTime, ToTime] window"}
	}
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data ListTransactionsData
	traceID, err := c.postSigned(ctx, "/operator/v1/transaction/list", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return &data, traceID, nil
}

func (c *Client) ListAllTransactions(ctx context.Context, fromTime, toTime int64, pageSize int) ([]ReconcileTransactionRow, error) {
	if pageSize == 0 {
		pageSize = 2000
	}
	if pageSize < 1 || pageSize > MaxPageSize {
		return nil, &SdkError{Code: "INVALID_ARGUMENT", Message: fmt.Sprintf("pageSize must be in 1..%d", MaxPageSize)}
	}
	var all []ReconcileTransactionRow
	pageNo := 1
	for {
		data, _, err := c.ListTransactions(ctx, ListTransactionsRequest{
			FromTime: fromTime,
			ToTime:   toTime,
			PageNo:   pageNo,
			PageSize: pageSize,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, data.Transactions...)
		if len(all) >= data.Total || len(data.Transactions) == 0 {
			break
		}
		pageNo++
	}
	return all, nil
}

type TransactionDetailRequest struct {
	TraceID  string `json:"traceId"`
	BetID    string `json:"betId"`
	FromTime int64  `json:"fromTime"`
	ToTime   int64  `json:"toTime"`
}

type VerifiedRoundResult struct {
	Outcome      string `json:"outcome"`
	PlayerPoints int    `json:"playerPoints"`
	BankerPoints int    `json:"bankerPoints"`
	PlayerPair   bool   `json:"playerPair"`
	BankerPair   bool   `json:"bankerPair"`
	Natural      bool   `json:"natural"`
}

type TransactionDetailData struct {
	ReconcileTransactionRow
	RoundResult *VerifiedRoundResult `json:"roundResult"`
	Adjustments []map[string]any     `json:"adjustments,omitempty"`
}

func (c *Client) GetTransactionDetail(ctx context.Context, req TransactionDetailRequest) (*TransactionDetailData, string, error) {
	if strings.TrimSpace(req.BetID) == "" {
		return nil, "", &SdkError{Code: "INVALID_ARGUMENT", Message: "betId is required"}
	}
	if req.FromTime != 0 || req.ToTime != 0 {
		if req.FromTime < 0 || req.ToTime < req.FromTime || (req.ToTime-req.FromTime) > MaxDetailWindowMs {
			return nil, "", &SdkError{Code: "INVALID_ARGUMENT", Message: "detail window must satisfy 0 <= ToTime - FromTime <= 604800000"}
		}
	}
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data TransactionDetailData
	traceID, err := c.postSigned(ctx, "/operator/v1/transaction/detail", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return &data, traceID, nil
}

type ListUnsettledRequest struct {
	TraceID  string `json:"traceId"`
	FromTime int64  `json:"fromTime,omitempty"`
	ToTime   int64  `json:"toTime,omitempty"`
	Username string `json:"username,omitempty"`
	TableID  string `json:"tableId,omitempty"`
	PageNo   int    `json:"pageNo,omitempty"`
	PageSize int    `json:"pageSize,omitempty"`
}

func (c *Client) ListUnsettledTransactions(ctx context.Context, req ListUnsettledRequest) (map[string]any, string, error) {
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data map[string]any
	traceID, err := c.postSigned(ctx, "/operator/v1/transaction/unsettled", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return data, traceID, nil
}

type WalletTransactionStatusRequest struct {
	TraceID       string `json:"traceId"`
	TransactionID string `json:"transactionId,omitempty"`
	BetID         string `json:"betId,omitempty"`
}

func (c *Client) GetWalletTransactionStatus(ctx context.Context, req WalletTransactionStatusRequest) (map[string]any, string, error) {
	if strings.TrimSpace(req.TransactionID) == "" && strings.TrimSpace(req.BetID) == "" {
		return nil, "", &SdkError{Code: "INVALID_ARGUMENT", Message: "transactionId or betId is required"}
	}
	if strings.TrimSpace(req.TraceID) == "" {
		req.TraceID = newUUIDv4()
	}
	var data map[string]any
	traceID, err := c.postSigned(ctx, "/operator/v1/wallet/transaction-status", req, req.TraceID, &data)
	if err != nil {
		return nil, traceID, err
	}
	return data, traceID, nil
}

// ── 5. Seamless Wallet Webhook Dispatcher & Thread-Safe InMemoryWallet ──────

type WalletResponseData struct {
	Username  string `json:"username,omitempty"`
	Currency  string `json:"currency,omitempty"`
	Balance   string `json:"balance"`
	Timestamp int64  `json:"timestamp"`
}

type WalletResponse struct {
	TraceID string              `json:"traceId,omitempty"`
	Status  string              `json:"status"`
	Message string              `json:"message,omitempty"`
	Data    *WalletResponseData `json:"data,omitempty"`
}

type WalletAdjustmentHandler interface {
	OnAdjustment(ctx context.Context, req WalletAdjustmentRequest) WalletResponse
}

type WalletHandler interface {
	OnBalance(ctx context.Context, req WalletBalanceRequest) WalletResponse
	OnBet(ctx context.Context, req WalletBetRequest) WalletResponse
	OnBetResult(ctx context.Context, req WalletBetResultRequest) WalletResponse
	OnRollback(ctx context.Context, req WalletRollbackRequest) WalletResponse
}

type AccountInit struct {
	Currency string
	Balance  string
	Exponent int
	Tokens   []string
	Disabled bool
}

type walletAcct struct {
	currency string
	exponent int
	units    *big.Int
	tokens   map[string]bool
	disabled bool
}

type txRecord struct {
	kind  string
	fp    string
	empty bool
}

type betState string

const (
	betStateDeducted   betState = "DEDUCTED"
	betStateSettled    betState = "SETTLED"
	betStateRolledBack betState = "ROLLED_BACK"
)

type betRecord struct {
	txID     string
	username string
	currency string
	stake    *big.Int
	state    betState
}

type InMemoryWallet struct {
	mu           sync.Mutex
	accounts     map[string]*walletAcct
	transactions map[string]txRecord
	deductedBets map[string]*betRecord
}

func NewInMemoryWallet(initial map[string]AccountInit) (*InMemoryWallet, error) {
	w := &InMemoryWallet{
		accounts:     make(map[string]*walletAcct),
		transactions: make(map[string]txRecord),
		deductedBets: make(map[string]*betRecord),
	}
	for u, info := range initial {
		uVal, err := DecimalToLedgerUnits(info.Balance, info.Exponent, false)
		if err != nil {
			return nil, err
		}
		toks := make(map[string]bool)
		for _, t := range info.Tokens {
			toks[t] = true
		}
		w.accounts[u] = &walletAcct{
			currency: strings.ToUpper(strings.TrimSpace(info.Currency)),
			exponent: info.Exponent,
			units:    uVal,
			tokens:   toks,
			disabled: info.Disabled,
		}
	}
	return w, nil
}

func (w *InMemoryWallet) SetDisabled(username string, disabled bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if a, ok := w.accounts[username]; ok {
		a.disabled = disabled
	}
}

func (w *InMemoryWallet) okResp(traceID, username string, a *walletAcct) WalletResponse {
	bal, _ := LedgerUnitsToDecimal(a.units, a.exponent)
	return WalletResponse{
		TraceID: traceID,
		Status:  SC_OK,
		Data: &WalletResponseData{
			Username:  username,
			Currency:  a.currency,
			Balance:   bal,
			Timestamp: time.Now().UnixMilli(),
		},
	}
}

func (w *InMemoryWallet) OnBalance(_ context.Context, req WalletBalanceRequest) WalletResponse {
	w.mu.Lock()
	defer w.mu.Unlock()
	username := strings.TrimSpace(req.Username)
	currency := strings.ToUpper(strings.TrimSpace(req.Currency))
	if username == "" || currency == "" {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "username and currency are required"}
	}
	a, ok := w.accounts[username]
	if !ok {
		return WalletResponse{TraceID: req.TraceID, Status: SC_USER_NOT_EXISTS, Message: "user not exists"}
	}
	if a.currency != currency {
		return WalletResponse{TraceID: req.TraceID, Status: SC_WRONG_CURRENCY, Message: "wrong currency"}
	}
	if a.disabled {
		return WalletResponse{TraceID: req.TraceID, Status: SC_USER_DISABLED, Message: "user disabled"}
	}
	if len(a.tokens) > 0 && !a.tokens[req.Token] {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_TOKEN, Message: "invalid token"}
	}
	return w.okResp(req.TraceID, username, a)
}

func (w *InMemoryWallet) OnBet(_ context.Context, req WalletBetRequest) WalletResponse {
	w.mu.Lock()
	defer w.mu.Unlock()
	txID := strings.TrimSpace(req.TransactionID)
	betID := strings.TrimSpace(req.BetID)
	username := strings.TrimSpace(req.Username)
	currency := strings.ToUpper(strings.TrimSpace(req.Currency))
	if txID == "" || betID == "" || username == "" || currency == "" || strings.TrimSpace(req.Amount) == "" {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "missing required bet fields"}
	}
	a, ok := w.accounts[username]
	if !ok {
		return WalletResponse{TraceID: req.TraceID, Status: SC_USER_NOT_EXISTS}
	}
	if a.currency != currency {
		return WalletResponse{TraceID: req.TraceID, Status: SC_WRONG_CURRENCY}
	}
	fp := BetFingerprint(req)
	if prior, exists := w.transactions[txID]; exists {
		if prior.kind != "BET" || prior.fp != fp {
			return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_DUPLICATED, Message: "conflicting bet"}
		}
		return w.okResp(req.TraceID, username, a)
	}
	if _, dupBet := w.deductedBets[betID]; dupBet {
		return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_DUPLICATED, Message: "duplicate betId"}
	}
	if a.disabled {
		return WalletResponse{TraceID: req.TraceID, Status: SC_USER_DISABLED}
	}
	if len(a.tokens) > 0 && !a.tokens[req.Token] {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_TOKEN}
	}
	stake, err := DecimalToLedgerUnits(req.Amount, a.exponent, false)
	if err != nil || stake.Sign() <= 0 {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "invalid bet amount"}
	}
	if a.units.Cmp(stake) < 0 {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INSUFFICIENT_FUNDS, Message: "insufficient funds"}
	}
	a.units.Sub(a.units, stake)
	w.transactions[txID] = txRecord{kind: "BET", fp: fp}
	w.deductedBets[betID] = &betRecord{
		txID:     txID,
		username: username,
		currency: a.currency,
		stake:    new(big.Int).Set(stake),
		state:    betStateDeducted,
	}
	return w.okResp(req.TraceID, username, a)
}

func (w *InMemoryWallet) OnBetResult(_ context.Context, req WalletBetResultRequest) WalletResponse {
	w.mu.Lock()
	defer w.mu.Unlock()
	txID := strings.TrimSpace(req.TransactionID)
	betID := strings.TrimSpace(req.BetID)
	username := strings.TrimSpace(req.Username)
	currency := strings.ToUpper(strings.TrimSpace(req.Currency))
	if txID == "" || betID == "" || username == "" || currency == "" || strings.TrimSpace(req.WinAmount) == "" || strings.TrimSpace(req.BetAmount) == "" {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "missing required bet_result fields"}
	}
	a, ok := w.accounts[username]
	if !ok {
		return WalletResponse{TraceID: req.TraceID, Status: SC_USER_NOT_EXISTS}
	}
	if a.currency != currency {
		return WalletResponse{TraceID: req.TraceID, Status: SC_WRONG_CURRENCY}
	}
	fp := BetResultFingerprint(req)
	if prior, exists := w.transactions[txID]; exists {
		if prior.kind != "SETTLE" || prior.fp != fp {
			return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_DUPLICATED, Message: "conflicting bet_result"}
		}
		return w.okResp(req.TraceID, username, a)
	}
	orig, existed := w.deductedBets[betID]
	if !existed {
		return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_NOT_EXISTS}
	}
	betAmt, errBet := DecimalToLedgerUnits(req.BetAmount, a.exponent, false)
	winAmt, errWin := DecimalToLedgerUnits(req.WinAmount, a.exponent, false)
	if errBet != nil || errWin != nil || orig.username != username || orig.currency != a.currency || orig.stake.Cmp(betAmt) != 0 {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "bet_result mismatch"}
	}
	if orig.state != betStateDeducted {
		return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_DUPLICATED, Message: "betId already finalized"}
	}
	a.units.Add(a.units, winAmt)
	orig.state = betStateSettled
	w.transactions[txID] = txRecord{kind: "SETTLE", fp: fp}
	return w.okResp(req.TraceID, username, a)
}

func (w *InMemoryWallet) OnRollback(_ context.Context, req WalletRollbackRequest) WalletResponse {
	w.mu.Lock()
	defer w.mu.Unlock()
	txID := strings.TrimSpace(req.TransactionID)
	betID := strings.TrimSpace(req.BetID)
	username := strings.TrimSpace(req.Username)
	currency := strings.ToUpper(strings.TrimSpace(req.Currency))
	if txID == "" || betID == "" || username == "" || currency == "" || strings.TrimSpace(req.Amount) == "" {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "missing required rollback fields"}
	}
	a, ok := w.accounts[username]
	if !ok {
		return WalletResponse{TraceID: req.TraceID, Status: SC_USER_NOT_EXISTS}
	}
	if a.currency != currency {
		return WalletResponse{TraceID: req.TraceID, Status: SC_WRONG_CURRENCY}
	}
	fp := RollbackFingerprint(req)
	if prior, exists := w.transactions[txID]; exists {
		if prior.kind != "ROLLBACK" || prior.fp != fp {
			return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_DUPLICATED, Message: "conflicting rollback"}
		}
		if prior.empty {
			return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_NOT_EXISTS, Message: "never deducted"}
		}
		return w.okResp(req.TraceID, username, a)
	}
	refund, err := DecimalToLedgerUnits(req.Amount, a.exponent, false)
	if err != nil || refund.Sign() <= 0 {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "invalid rollback amount"}
	}
	orig, existed := w.deductedBets[betID]
	if !existed {
		w.transactions[txID] = txRecord{kind: "ROLLBACK", fp: fp, empty: true}
		return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_NOT_EXISTS, Message: "never deducted"}
	}
	if orig.username != username || orig.currency != a.currency || orig.stake.Cmp(refund) != 0 {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "rollback mismatch"}
	}
	if orig.state != betStateDeducted {
		return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_DUPLICATED, Message: "betId already finalized"}
	}
	a.units.Add(a.units, refund)
	orig.state = betStateRolledBack
	w.transactions[txID] = txRecord{kind: "ROLLBACK", fp: fp}
	return w.okResp(req.TraceID, username, a)
}

func (w *InMemoryWallet) OnAdjustment(_ context.Context, req WalletAdjustmentRequest) WalletResponse {
	w.mu.Lock()
	defer w.mu.Unlock()
	txID := strings.TrimSpace(req.TransactionID)
	betID := strings.TrimSpace(req.BetID)
	username := strings.TrimSpace(req.Username)
	currency := strings.ToUpper(strings.TrimSpace(req.Currency))
	direction := strings.ToUpper(strings.TrimSpace(req.Direction))
	reasonCode := strings.TrimSpace(req.ReasonCode)
	if txID == "" || betID == "" || username == "" || currency == "" || reasonCode == "" || strings.TrimSpace(req.Amount) == "" || (direction != "CREDIT" && direction != "DEBIT") {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "missing or invalid adjustment fields"}
	}
	a, ok := w.accounts[username]
	if !ok {
		return WalletResponse{TraceID: req.TraceID, Status: SC_USER_NOT_EXISTS}
	}
	if a.currency != currency {
		return WalletResponse{TraceID: req.TraceID, Status: SC_WRONG_CURRENCY}
	}
	fp := AdjustmentFingerprint(req)
	if prior, exists := w.transactions[txID]; exists {
		if prior.kind != "ADJUSTMENT" || prior.fp != fp {
			return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_DUPLICATED, Message: "conflicting adjustment"}
		}
		return w.okResp(req.TraceID, username, a)
	}
	orig, existed := w.deductedBets[betID]
	if !existed {
		return WalletResponse{TraceID: req.TraceID, Status: SC_TRANSACTION_NOT_EXISTS}
	}
	if orig.username != username || orig.currency != a.currency {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "adjustment mismatch"}
	}
	adjUnits, err := DecimalToLedgerUnits(req.Amount, a.exponent, false)
	if err != nil || adjUnits.Sign() <= 0 {
		return WalletResponse{TraceID: req.TraceID, Status: SC_INVALID_REQUEST, Message: "invalid adjustment amount"}
	}
	if direction == "DEBIT" {
		if a.units.Cmp(adjUnits) < 0 {
			return WalletResponse{TraceID: req.TraceID, Status: SC_INSUFFICIENT_FUNDS, Message: "insufficient funds"}
		}
		a.units.Sub(a.units, adjUnits)
	} else {
		a.units.Add(a.units, adjUnits)
	}
	w.transactions[txID] = txRecord{kind: "ADJUSTMENT", fp: fp}
	return w.okResp(req.TraceID, username, a)
}

type WebhookDispatcher struct {
	apiKey     string
	hmacSecret string
	wallet     WalletHandler
}

func NewWebhookDispatcher(apiKey, hmacSecret string, wallet WalletHandler) (*WebhookDispatcher, error) {
	if strings.TrimSpace(apiKey) == "" || hmacSecret == "" || wallet == nil {
		return nil, errors.New("apiKey, hmacSecret, and wallet handler are required")
	}
	return &WebhookDispatcher{
		apiKey:     strings.TrimSpace(apiKey),
		hmacSecret: hmacSecret,
		wallet:     wallet,
	}, nil
}

func extractTraceHint(rawBody []byte) string {
	head := rawBody
	if len(head) > 1024 {
		head = head[:1024]
	}
	if m := traceHintRe.FindSubmatch(head); len(m) == 2 {
		return string(m[1])
	}
	return ""
}

func (d *WebhookDispatcher) HandleRaw(ctx context.Context, routePath, apiKeyHeader, sigHeader string, rawBody []byte) WalletResponse {
	if len(rawBody) > MaxWebhookBodyBytes {
		return WalletResponse{Status: SC_INVALID_REQUEST, Message: "request body exceeds 1 MiB limit"}
	}

	// Verify X-API-Key & X-Signature over raw bytes BEFORE JSON unmarshaling!
	if st := VerifyWebhookHeaders(apiKeyHeader, sigHeader, rawBody, d.apiKey, d.hmacSecret); st != SC_OK {
		return WalletResponse{TraceID: extractTraceHint(rawBody), Status: st, Message: "auth/signature check failed"}
	}

	if !isJSONObjectBytes(rawBody) {
		return WalletResponse{Status: SC_INVALID_REQUEST, Message: "request body must be a JSON object"}
	}

	var traceProbe struct {
		TraceID string `json:"traceId"`
	}
	_ = json.Unmarshal(rawBody, &traceProbe)
	traceID := strings.TrimSpace(traceProbe.TraceID)
	if len(traceID) > 128 {
		traceID = traceID[:128]
	}

	clean := strings.TrimRight(strings.SplitN(routePath, "?", 2)[0], "/")
	switch {
	case strings.HasSuffix(clean, "/wallet/balance"):
		var req WalletBalanceRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			return WalletResponse{TraceID: traceID, Status: SC_INVALID_REQUEST, Message: "invalid JSON"}
		}
		return d.wallet.OnBalance(ctx, req)
	case strings.HasSuffix(clean, "/wallet/bet"):
		var req WalletBetRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			return WalletResponse{TraceID: traceID, Status: SC_INVALID_REQUEST, Message: "invalid JSON"}
		}
		return d.wallet.OnBet(ctx, req)
	case strings.HasSuffix(clean, "/wallet/bet_result"):
		var req WalletBetResultRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			return WalletResponse{TraceID: traceID, Status: SC_INVALID_REQUEST, Message: "invalid JSON"}
		}
		return d.wallet.OnBetResult(ctx, req)
	case strings.HasSuffix(clean, "/wallet/rollback"):
		var req WalletRollbackRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			return WalletResponse{TraceID: traceID, Status: SC_INVALID_REQUEST, Message: "invalid JSON"}
		}
		return d.wallet.OnRollback(ctx, req)
	case strings.HasSuffix(clean, "/wallet/adjustment"):
		adjHandler, ok := d.wallet.(WalletAdjustmentHandler)
		if !ok {
			return WalletResponse{TraceID: traceID, Status: SC_INVALID_REQUEST, Message: "OnAdjustment not implemented"}
		}
		var req WalletAdjustmentRequest
		if err := json.Unmarshal(rawBody, &req); err != nil {
			return WalletResponse{TraceID: traceID, Status: SC_INVALID_REQUEST, Message: "invalid JSON"}
		}
		return adjHandler.OnAdjustment(ctx, req)
	default:
		return WalletResponse{TraceID: traceID, Status: SC_INVALID_REQUEST, Message: "unknown wallet route"}
	}
}

func (d *WebhookDispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxWebhookBodyBytes+1))
	if err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"SC_INVALID_REQUEST","message":"failed to read body"}`))
		return
	}
	resp := d.HandleRaw(r.Context(), r.URL.Path, r.Header.Get("X-API-Key"), r.Header.Get("X-Signature"), raw)
	out, _ := marshalNoEscapeHTML(resp)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

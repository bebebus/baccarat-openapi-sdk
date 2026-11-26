// SPDX-License-Identifier: MIT
#pragma once

#include "baccarat/json.hpp"

#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

namespace baccarat {

constexpr const char* SANDBOX_BASE_URL = "https://api.lt.cniia.cloud";
constexpr int64_t MAX_DETAIL_WINDOW_MS = 604800000LL;
constexpr int MAX_PAGE_SIZE = 20000;
constexpr size_t MAX_WEBHOOK_BODY_BYTES = 1048576;

enum class Environment { Sandbox, Production };

namespace StatusCode {
constexpr const char* SC_OK = "SC_OK";
constexpr const char* SC_INVALID_REQUEST = "SC_INVALID_REQUEST";
constexpr const char* SC_AUTHENTICATION_FAILED = "SC_AUTHENTICATION_FAILED";
constexpr const char* SC_INVALID_SIGNATURE = "SC_INVALID_SIGNATURE";
constexpr const char* SC_INVALID_TOKEN = "SC_INVALID_TOKEN";
constexpr const char* SC_INVALID_GAME = "SC_INVALID_GAME";
constexpr const char* SC_USER_NOT_EXISTS = "SC_USER_NOT_EXISTS";
constexpr const char* SC_USER_DISABLED = "SC_USER_DISABLED";
constexpr const char* SC_WRONG_CURRENCY = "SC_WRONG_CURRENCY";
constexpr const char* SC_CURRENCY_NOT_SUPPORTED = "SC_CURRENCY_NOT_SUPPORTED";
constexpr const char* SC_INSUFFICIENT_FUNDS = "SC_INSUFFICIENT_FUNDS";
constexpr const char* SC_TRANSACTION_DUPLICATED = "SC_TRANSACTION_DUPLICATED";
constexpr const char* SC_TRANSACTION_NOT_EXISTS = "SC_TRANSACTION_NOT_EXISTS";
constexpr const char* SC_TRANSACTION_STILL_PROCESSING = "SC_TRANSACTION_STILL_PROCESSING";
constexpr const char* SC_OPERATOR_TIMEOUT = "SC_OPERATOR_TIMEOUT";
constexpr const char* SC_UNDER_MAINTENANCE = "SC_UNDER_MAINTENANCE";
constexpr const char* SC_GAME_DISABLED = "SC_GAME_DISABLED";
constexpr const char* SC_RATE_LIMITED = "SC_RATE_LIMITED";
} // namespace StatusCode

bool is_retryable_status(const std::string& status);

class SdkError : public std::runtime_error {
public:
    std::string code;
    SdkError(std::string c, const std::string& msg) : std::runtime_error(msg), code(std::move(c)) {}
};

class ApiError : public SdkError {
public:
    std::string trace_id;
    std::string status;
    std::map<std::string, std::string> validation;
    int http_status;
    ApiError(
        std::string st,
        const std::string& msg,
        std::string tid = "",
        int http = 200,
        std::map<std::string, std::string> val = {}
    )
        : SdkError(st, msg.empty() ? ("B2B API error: " + st) : msg),
          trace_id(std::move(tid)),
          status(std::move(st)),
          validation(std::move(val)),
          http_status(http) {}

    bool is_retryable() const { return is_retryable_status(status); }
};

class TransportError : public SdkError {
public:
    explicit TransportError(const std::string& msg)
        : SdkError(StatusCode::SC_OPERATOR_TIMEOUT, msg) {}
    TransportError(std::string c, const std::string& msg)
        : SdkError(std::move(c), msg) {}
};

// 1. Raw-byte HMAC-SHA256 signing & timing-safe verification
std::string sign_body(const std::string& raw_body, const std::string& hmac_secret);
bool verify_signature(const std::string& raw_body, const std::string& signature_header, const std::string& hmac_secret);
std::string verify_webhook_headers(
    const std::string& api_key_header,
    const std::string& signature_header,
    const std::string& raw_body,
    const std::string& expected_api_key,
    const std::string& hmac_secret
);

// 2. Arbitrary-precision base-10 Decimal <-> Ledger units string math
std::string decimal_to_ledger_units(const std::string& raw, int display_exponent, bool allow_negative = false);
std::string ledger_units_to_decimal(const std::string& units, int display_exponent);

// 3. Canonical retry-safe idempotency fingerprints
std::string encode_tuple_fingerprint(const std::string& domain, const std::vector<std::string>& fields);
std::string bet_fingerprint(const Json& payload);
std::string bet_result_fingerprint(const Json& payload);
std::string rollback_fingerprint(const Json& payload);
std::string adjustment_fingerprint(const Json& payload);

// 4. Config & S2S Client
struct Config {
    std::string api_key;
    std::string hmac_secret;
    Environment environment = Environment::Production;
    std::string base_url;
    long timeout_ms = 8000;
    bool send_timestamp = false;

    std::string resolved_base_url() const;
};

class Client {
public:
    explicit Client(const Config& cfg);

    Json post_signed(const std::string& route_path, Json payload) const;
    Json ping(Json params = Json::object()) const;
    Json create_game_url(Json params) const;
    Json list_tables(Json params = Json::object()) const;
    Json terminate_sessions(Json params = Json::object()) const;
    Json update_player_status(Json params) const;
    Json update_player_limits(Json params) const;
    Json list_transactions(Json params) const;
    std::vector<Json> list_all_transactions(
        int64_t from_time,
        int64_t to_time,
        int page_size = 2000,
        Json filters = Json::object(),
        int rate_limit_max_retries = 3,
        int rate_limit_backoff_ms = 1000
    ) const;
    Json get_transaction_detail(Json params) const;
    Json list_unsettled_transactions(Json params = Json::object()) const;
    Json get_wallet_transaction_status(Json params) const;

private:
    std::string api_key_;
    std::string hmac_secret_;
    std::string base_url_;
    long timeout_ms_;
    bool send_timestamp_;
};

// 5. Seamless Wallet Pluggable WalletHandler, WebhookDispatcher & InMemoryWallet
Json wallet_ok(
    const std::string& trace_id,
    const std::string& username,
    const std::string& currency,
    const std::string& balance,
    int64_t timestamp_ms = 0
);
Json wallet_error(
    const std::string& trace_id,
    const std::string& status,
    const std::string& message = ""
);

class WalletHandler {
public:
    virtual ~WalletHandler() = default;
    virtual Json on_balance(const Json& req) = 0;
    virtual Json on_bet(const Json& req) = 0;
    virtual Json on_bet_result(const Json& req) = 0;
    virtual Json on_rollback(const Json& req) = 0;
    virtual Json on_adjustment(const Json& req);
};

class InMemoryWallet : public WalletHandler {
public:
    void add_account(
        const std::string& username,
        const std::string& currency,
        const std::string& balance,
        int exponent = 2,
        const std::vector<std::string>& tokens = {}
    );
    void set_disabled(const std::string& username, bool disabled);

    Json on_balance(const Json& req) override;
    Json on_bet(const Json& req) override;
    Json on_bet_result(const Json& req) override;
    Json on_rollback(const Json& req) override;
    Json on_adjustment(const Json& req) override;

private:
    struct Account {
        std::string currency;
        int exponent = 2;
        std::string units = "0";
        std::set<std::string> tokens;
        bool disabled = false;
    };
    struct TxRec {
        std::string type;
        std::string fp;
        bool empty = false;
    };
    struct BetRec {
        std::string tx_id;
        std::string username;
        std::string currency;
        std::string stake;
        std::string state = "DEDUCTED";
    };

    std::mutex mu_;
    std::map<std::string, Account> accounts_;
    std::map<std::string, TxRec> transactions_;
    std::map<std::string, BetRec> deducted_bets_;

    Json ok_envelope(const std::string& trace_id, const std::string& username, const Account& acct) const;
    static Json err_envelope(const std::string& trace_id, const std::string& status, const std::string& msg);
};

class WebhookDispatcher {
public:
    WebhookDispatcher(const Config& cfg, WalletHandler& wallet);
    WebhookDispatcher(std::string api_key, std::string hmac_secret, WalletHandler& wallet);
    Json handle(
        const std::string& route_path,
        const std::string& api_key_header,
        const std::string& signature_header,
        const std::string& raw_body
    );

private:
    std::string api_key_;
    std::string hmac_secret_;
    WalletHandler& wallet_;
};

} // namespace baccarat

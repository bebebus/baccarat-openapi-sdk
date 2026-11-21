// SPDX-License-Identifier: MIT
#include "baccarat/sdk.hpp"

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>

namespace baccarat {

namespace {

std::string trim(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    size_t e = s.size();
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string to_upper(std::string s) {
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
}

std::string to_hex_lower(const unsigned char* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out(len * 2, '0');
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = digits[(data[i] >> 4) & 0x0F];
        out[i * 2 + 1] = digits[data[i] & 0x0F];
    }
    return out;
}

bool hex_to_bytes32(const std::string& hex, unsigned char out[32]) {
    if (hex.size() != 64) return false;
    for (size_t i = 0; i < 32; ++i) {
        auto nibble = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nibble(hex[i * 2]);
        int lo = nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return true;
}

bool ct_string_eq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string strip_leading_zeros(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && s[i] == '0') ++i;
    return i == s.size() ? "0" : s.substr(i);
}

std::string strip_trailing_zeros(const std::string& s) {
    size_t e = s.size();
    while (e > 0 && s[e - 1] == '0') --e;
    return s.substr(0, e);
}

int compare_unsigned(const std::string& a, const std::string& b) {
    std::string na = strip_leading_zeros(a);
    std::string nb = strip_leading_zeros(b);
    if (na.size() != nb.size()) return na.size() < nb.size() ? -1 : 1;
    if (na == nb) return 0;
    return na < nb ? -1 : 1;
}

std::string add_unsigned(const std::string& a, const std::string& b) {
    int i = static_cast<int>(a.size()) - 1;
    int j = static_cast<int>(b.size()) - 1;
    int carry = 0;
    std::string rev;
    while (i >= 0 || j >= 0 || carry > 0) {
        int da = i >= 0 ? (a[i--] - '0') : 0;
        int db = j >= 0 ? (b[j--] - '0') : 0;
        int sum = da + db + carry;
        rev.push_back(static_cast<char>('0' + (sum % 10)));
        carry = sum / 10;
    }
    std::reverse(rev.begin(), rev.end());
    return strip_leading_zeros(rev);
}

std::string sub_unsigned(const std::string& a, const std::string& b) {
    int i = static_cast<int>(a.size()) - 1;
    int j = static_cast<int>(b.size()) - 1;
    int borrow = 0;
    std::string rev;
    while (i >= 0) {
        int da = (a[i--] - '0') - borrow;
        int db = j >= 0 ? (b[j--] - '0') : 0;
        if (da < db) {
            da += 10;
            borrow = 1;
        } else {
            borrow = 0;
        }
        rev.push_back(static_cast<char>('0' + (da - db)));
    }
    std::reverse(rev.begin(), rev.end());
    return strip_leading_zeros(rev);
}

std::string uuid_v4() {
    unsigned char b[16];
    if (RAND_bytes(b, 16) != 1) {
        for (int i = 0; i < 16; ++i) b[i] = static_cast<unsigned char>(i * 17 + 3);
    }
    b[6] = (b[6] & 0x0F) | 0x40;
    b[8] = (b[8] & 0x3F) | 0x80;
    char out[37];
    std::snprintf(
        out, sizeof(out),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    );
    return std::string(out);
}

size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

} // namespace

bool is_retryable_status(const std::string& status) {
    std::string s = trim(status);
    return s == StatusCode::SC_TRANSACTION_STILL_PROCESSING || s == StatusCode::SC_OPERATOR_TIMEOUT;
}

std::string sign_body(const std::string& raw_body, const std::string& hmac_secret) {
    if (hmac_secret.empty()) {
        throw SdkError("INVALID_CONFIG", "hmac_secret must be non-empty");
    }
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    // CRITICAL: Pass raw UTF-8 bytes of hmac_secret directly — NEVER Base64-decode!
    HMAC(
        EVP_sha256(),
        hmac_secret.data(),
        static_cast<int>(hmac_secret.size()),
        reinterpret_cast<const unsigned char*>(raw_body.data()),
        raw_body.size(),
        md,
        &md_len
    );
    return to_hex_lower(md, md_len);
}

bool verify_signature(const std::string& raw_body, const std::string& signature_header, const std::string& hmac_secret) {
    if (hmac_secret.empty()) return false;
    std::string trimmed = trim(signature_header);
    unsigned char actual[32];
    unsigned char expected[32];
    if (!hex_to_bytes32(trimmed, actual)) return false;
    if (!hex_to_bytes32(sign_body(raw_body, hmac_secret), expected)) return false;
    return CRYPTO_memcmp(actual, expected, 32) == 0;
}

std::string verify_webhook_headers(
    const std::string& api_key_header,
    const std::string& signature_header,
    const std::string& raw_body,
    const std::string& expected_api_key,
    const std::string& hmac_secret
) {
    std::string exp_key = trim(expected_api_key);
    std::string act_key = trim(api_key_header);
    if (exp_key.empty() || act_key.empty() || !ct_string_eq(act_key, exp_key)) {
        return StatusCode::SC_AUTHENTICATION_FAILED;
    }
    if (!verify_signature(raw_body, signature_header, hmac_secret)) {
        return StatusCode::SC_INVALID_SIGNATURE;
    }
    return StatusCode::SC_OK;
}

std::string decimal_to_ledger_units(const std::string& raw, int display_exponent, bool allow_negative) {
    if (display_exponent < 0 || display_exponent > 18) {
        throw SdkError("INVALID_DISPLAY_EXPONENT", "display_exponent out of range 0..18");
    }
    std::string s = trim(raw);
    if (s.empty()) throw SdkError("INVALID_DECIMAL_AMOUNT", "empty decimal amount");
    size_t idx = 0;
    bool neg = false;
    if (s[idx] == '-') {
        neg = true;
        ++idx;
    }
    size_t whole_start = idx;
    while (idx < s.size() && std::isdigit(static_cast<unsigned char>(s[idx]))) ++idx;
    if (idx == whole_start) throw SdkError("INVALID_DECIMAL_AMOUNT", "missing digits before dot");
    std::string whole = s.substr(whole_start, idx - whole_start);
    std::string frac;
    if (idx < s.size()) {
        if (s[idx] != '.') throw SdkError("INVALID_DECIMAL_AMOUNT", "malformed decimal character");
        ++idx;
        size_t frac_start = idx;
        while (idx < s.size() && std::isdigit(static_cast<unsigned char>(s[idx]))) ++idx;
        if (idx == frac_start || idx != s.size()) throw SdkError("INVALID_DECIMAL_AMOUNT", "malformed fractional digits");
        frac = s.substr(frac_start);
    }
    size_t scale = static_cast<size_t>(display_exponent + 3);
    std::string trimmed_frac = strip_trailing_zeros(frac);
    if (trimmed_frac.size() > scale) {
        throw SdkError("DECIMAL_PRECISION_EXCEEDED", "decimal precision exceeded");
    }
    trimmed_frac.append(scale - trimmed_frac.size(), '0');
    std::string combined = strip_leading_zeros(whole + trimmed_frac);
    if (combined == "0") return "0";
    if (neg) {
        if (!allow_negative) throw SdkError("NEGATIVE_DECIMAL_FORBIDDEN", "negative decimal forbidden");
        return "-" + combined;
    }
    return combined;
}

std::string ledger_units_to_decimal(const std::string& units, int display_exponent) {
    if (display_exponent < 0 || display_exponent > 18) {
        throw SdkError("INVALID_DISPLAY_EXPONENT", "display_exponent out of range 0..18");
    }
    std::string u = trim(units);
    bool neg = false;
    size_t idx = 0;
    if (!u.empty() && u[0] == '-') {
        neg = true;
        idx = 1;
    }
    if (idx >= u.size()) throw SdkError("INVALID_DECIMAL_AMOUNT", "empty units");
    for (size_t i = idx; i < u.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(u[i]))) throw SdkError("INVALID_DECIMAL_AMOUNT", "non-digit units");
    }
    std::string abs_digits = strip_leading_zeros(u.substr(idx));
    if (abs_digits == "0") neg = false;
    size_t scale = static_cast<size_t>(display_exponent + 3);
    if (abs_digits.size() <= scale) {
        abs_digits = std::string(scale + 1 - abs_digits.size(), '0') + abs_digits;
    }
    std::string whole = strip_leading_zeros(abs_digits.substr(0, abs_digits.size() - scale));
    std::string frac_all = abs_digits.substr(abs_digits.size() - scale);
    std::string sign = neg ? "-" : "";
    if (display_exponent == 0) {
        std::string sub = strip_trailing_zeros(frac_all);
        return sub.empty() ? (sign + whole) : (sign + whole + "." + sub);
    }
    std::string shown = frac_all.substr(0, static_cast<size_t>(display_exponent));
    std::string sub = strip_trailing_zeros(frac_all.substr(static_cast<size_t>(display_exponent)));
    return sign + whole + "." + shown + sub;
}

std::string encode_tuple_fingerprint(const std::string& domain, const std::vector<std::string>& fields) {
    std::string canonical = "v1|" + domain;
    for (const auto& f : fields) {
        canonical += "|" + std::to_string(f.size()) + ":" + f;
    }
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size(), hash);
    return to_hex_lower(hash, SHA256_DIGEST_LENGTH);
}

std::string bet_fingerprint(const Json& p) {
    return encode_tuple_fingerprint("wallet/bet", {
        p.at("transactionId").to_scalar_string(),
        p.at("username").to_scalar_string(),
        p.at("betId").to_scalar_string(),
        p.at("externalTransactionId").to_scalar_string(),
        p.at("roundId").to_scalar_string(),
        p.at("currency").to_scalar_string(),
        p.at("gameCode").to_scalar_string(),
        p.at("amount").to_scalar_string(),
    });
}

std::string bet_result_fingerprint(const Json& p) {
    return encode_tuple_fingerprint("wallet/bet_result", {
        p.at("transactionId").to_scalar_string(),
        p.at("username").to_scalar_string(),
        p.at("betId").to_scalar_string(),
        p.at("externalTransactionId").to_scalar_string(),
        p.at("roundId").to_scalar_string(),
        p.at("currency").to_scalar_string(),
        p.at("gameCode").to_scalar_string(),
        p.at("betAmount").to_scalar_string(),
        p.at("winAmount").to_scalar_string(),
        p.at("effectiveTurnover").to_scalar_string(),
        p.at("winLoss").to_scalar_string(),
        p.at("jackpotAmount").to_scalar_string(),
        p.at("resultType").to_scalar_string(),
        p.at("isFreespin").to_scalar_string(),
        p.at("isEndRound").to_scalar_string(),
        p.at("betTime").to_scalar_string(),
    });
}

std::string rollback_fingerprint(const Json& p) {
    return encode_tuple_fingerprint("wallet/rollback", {
        p.at("transactionId").to_scalar_string(),
        p.at("username").to_scalar_string(),
        p.at("betId").to_scalar_string(),
        p.at("externalTransactionId").to_scalar_string(),
        p.at("roundId").to_scalar_string(),
        p.at("currency").to_scalar_string(),
        p.at("gameCode").to_scalar_string(),
        p.at("amount").to_scalar_string(),
    });
}

std::string Config::resolved_base_url() const {
    if (trim(api_key).empty()) throw SdkError("INVALID_CONFIG", "api_key is required");
    if (hmac_secret.empty()) throw SdkError("INVALID_CONFIG", "hmac_secret is required");
    std::string u = trim(base_url);
    if (u.empty()) {
        if (environment == Environment::Sandbox) u = SANDBOX_BASE_URL;
        else throw SdkError("INVALID_CONFIG", "base_url is required in Production environment");
    }
    if (u.rfind("http://", 0) != 0 && u.rfind("https://", 0) != 0) {
        throw SdkError("INVALID_CONFIG", "base_url must start with http:// or https://");
    }
    while (!u.empty() && u.back() == '/') u.pop_back();
    return u;
}

Client::Client(const Config& cfg)
    : api_key_(trim(cfg.api_key)),
      hmac_secret_(cfg.hmac_secret),
      base_url_(cfg.resolved_base_url()),
      timeout_ms_(cfg.timeout_ms > 0 ? cfg.timeout_ms : 8000) {}

Json Client::post_signed(const std::string& route_path, Json payload) const {
    if (!payload.is_object()) payload = Json::object();
    std::string trace_id = trim(payload.at("traceId").as_string());
    if (trace_id.empty()) trace_id = uuid_v4();
    payload.set("traceId", Json(trace_id));

    std::string raw_body = payload.dump();
    std::string sig = sign_body(raw_body, hmac_secret_);
    std::string url = base_url_ + route_path;

    CURL* curl = curl_easy_init();
    if (!curl) throw SdkError(StatusCode::SC_OPERATOR_TIMEOUT, "curl_easy_init failed");

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, ("X-API-Key: " + api_key_).c_str());
    headers = curl_slist_append(headers, ("X-Signature: " + sig).c_str());

    std::string resp_body;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, raw_body.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(raw_body.size()));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms_);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_body);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) {
        throw SdkError(StatusCode::SC_OPERATOR_TIMEOUT, std::string("curl error: ") + curl_easy_strerror(rc));
    }

    Json parsed;
    try {
        parsed = Json::parse(resp_body);
    } catch (...) {
        std::string st = (http_code >= 500 || http_code == 408 || http_code == 429)
            ? StatusCode::SC_OPERATOR_TIMEOUT
            : StatusCode::SC_INVALID_REQUEST;
        throw ApiError(st, "Non-JSON response", trace_id, static_cast<int>(http_code));
    }
    std::string st = parsed.at("status").as_string();
    std::string eff_trace = parsed.at("traceId").as_string().empty() ? trace_id : parsed.at("traceId").as_string();
    if (http_code != 200 || st != StatusCode::SC_OK) {
        throw ApiError(
            st.empty() ? StatusCode::SC_INVALID_REQUEST : st,
            parsed.at("message").as_string(),
            eff_trace,
            static_cast<int>(http_code)
        );
    }
    Json out = Json::object();
    out.set("traceId", Json(eff_trace));
    out.set("status", Json(StatusCode::SC_OK));
    out.set("data", parsed.at("data"));
    return out;
}

Json Client::create_game_url(Json params) const { return post_signed("/operator/v1/game/url", std::move(params)); }
Json Client::list_tables(Json params) const { return post_signed("/operator/v1/game/tables", std::move(params)); }
Json Client::terminate_sessions(Json params) const { return post_signed("/operator/v1/game/terminate", std::move(params)); }

Json Client::list_transactions(Json params) const {
    int64_t from = params.at("fromTime").as_int(-1);
    int64_t to = params.at("toTime").as_int(-1);
    if (from < 0 || to < from) throw SdkError("INVALID_ARGUMENT", "invalid [fromTime, toTime]");
    return post_signed("/operator/v1/transaction/list", std::move(params));
}

std::vector<Json> Client::list_all_transactions(int64_t from_time, int64_t to_time, int page_size) const {
    std::vector<Json> all;
    int page_no = 1;
    while (true) {
        Json p = Json::object();
        p.set("fromTime", Json(from_time));
        p.set("toTime", Json(to_time));
        p.set("pageNo", Json(page_no));
        p.set("pageSize", Json(page_size));
        Json res = list_transactions(std::move(p));
        const Json& data = res.at("data");
        const auto& batch = data.at("transactions").as_array();
        for (const auto& row : batch) all.push_back(row);
        int64_t total = data.at("total").as_int(static_cast<int64_t>(all.size()));
        if (static_cast<int64_t>(all.size()) >= total || batch.empty()) break;
        ++page_no;
    }
    return all;
}

Json Client::get_transaction_detail(Json params) const {
    std::string bet_id = trim(params.at("betId").as_string());
    int64_t from = params.at("fromTime").as_int(-1);
    int64_t to = params.at("toTime").as_int(-1);
    int64_t span = to - from;
    if (bet_id.empty() || from < 0 || span < 0 || span > MAX_DETAIL_WINDOW_MS) {
        throw SdkError("INVALID_ARGUMENT", "detail window must satisfy 0 <= toTime - fromTime <= 604800000");
    }
    return post_signed("/operator/v1/transaction/detail", std::move(params));
}

void InMemoryWallet::add_account(
    const std::string& username,
    const std::string& currency,
    const std::string& balance,
    int exponent,
    const std::vector<std::string>& tokens
) {
    std::lock_guard<std::mutex> lk(mu_);
    Account a;
    a.currency = to_upper(trim(currency));
    a.exponent = exponent;
    a.units = decimal_to_ledger_units(balance, exponent, false);
    for (const auto& t : tokens) a.tokens.insert(t);
    accounts_[username] = std::move(a);
}

void InMemoryWallet::set_disabled(const std::string& username, bool disabled) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = accounts_.find(username);
    if (it != accounts_.end()) it->second.disabled = disabled;
}

Json InMemoryWallet::ok_envelope(const std::string& trace_id, const std::string& username, const Account& acct) const {
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    Json data = Json::object();
    data.set("username", Json(username));
    data.set("currency", Json(acct.currency));
    data.set("balance", Json(ledger_units_to_decimal(acct.units, acct.exponent)));
    data.set("timestamp", Json(static_cast<int64_t>(now_ms)));

    Json r = Json::object();
    r.set("traceId", Json(trace_id));
    r.set("status", Json(StatusCode::SC_OK));
    r.set("data", std::move(data));
    return r;
}

Json InMemoryWallet::err_envelope(const std::string& trace_id, const std::string& status, const std::string& msg) {
    Json r = Json::object();
    r.set("traceId", Json(trace_id));
    r.set("status", Json(status));
    r.set("message", Json(msg));
    return r;
}

Json InMemoryWallet::on_balance(const Json& req) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string tid = req.at("traceId").as_string();
    std::string u = req.at("username").as_string();
    auto it = accounts_.find(u);
    if (it == accounts_.end()) return err_envelope(tid, StatusCode::SC_USER_NOT_EXISTS, "User missing");
    if (it->second.currency != to_upper(trim(req.at("currency").as_string()))) {
        return err_envelope(tid, StatusCode::SC_WRONG_CURRENCY, "Wrong currency");
    }
    if (it->second.disabled) return err_envelope(tid, StatusCode::SC_USER_DISABLED, "Disabled");
    if (!it->second.tokens.empty() && it->second.tokens.count(req.at("token").as_string()) == 0) {
        return err_envelope(tid, StatusCode::SC_INVALID_TOKEN, "Invalid token");
    }
    return ok_envelope(tid, u, it->second);
}

Json InMemoryWallet::on_bet(const Json& req) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string tid = req.at("traceId").as_string();
    std::string u = req.at("username").as_string();
    auto it = accounts_.find(u);
    if (it == accounts_.end()) return err_envelope(tid, StatusCode::SC_USER_NOT_EXISTS, "User missing");
    if (it->second.currency != to_upper(trim(req.at("currency").as_string()))) {
        return err_envelope(tid, StatusCode::SC_WRONG_CURRENCY, "Wrong currency");
    }
    std::string tx_id = req.at("transactionId").as_string();
    std::string fp = bet_fingerprint(req);
    auto tx_it = transactions_.find(tx_id);
    if (tx_it != transactions_.end()) {
        if (tx_it->second.fp != fp) return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "Conflict");
        return ok_envelope(tid, u, it->second);
    }
    if (it->second.disabled) return err_envelope(tid, StatusCode::SC_USER_DISABLED, "Disabled");
    if (!it->second.tokens.empty() && it->second.tokens.count(req.at("token").as_string()) == 0) {
        return err_envelope(tid, StatusCode::SC_INVALID_TOKEN, "Invalid token");
    }
    std::string stake = decimal_to_ledger_units(req.at("amount").as_string(), it->second.exponent, false);
    if (compare_unsigned(it->second.units, stake) < 0) {
        return err_envelope(tid, StatusCode::SC_INSUFFICIENT_FUNDS, "Insufficient funds");
    }
    it->second.units = sub_unsigned(it->second.units, stake);
    transactions_[tx_id] = TxRec{fp, false};
    deducted_bets_[req.at("betId").as_string()] = stake;
    return ok_envelope(tid, u, it->second);
}

Json InMemoryWallet::on_bet_result(const Json& req) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string tid = req.at("traceId").as_string();
    std::string u = req.at("username").as_string();
    auto it = accounts_.find(u);
    if (it == accounts_.end()) return err_envelope(tid, StatusCode::SC_USER_NOT_EXISTS, "User missing");
    if (it->second.currency != to_upper(trim(req.at("currency").as_string()))) {
        return err_envelope(tid, StatusCode::SC_WRONG_CURRENCY, "Wrong currency");
    }
    std::string tx_id = req.at("transactionId").as_string();
    std::string fp = bet_result_fingerprint(req);
    auto tx_it = transactions_.find(tx_id);
    if (tx_it != transactions_.end()) {
        if (tx_it->second.fp != fp) return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "Conflict");
        return ok_envelope(tid, u, it->second);
    }
    if (deducted_bets_.count(req.at("betId").as_string()) == 0) {
        return err_envelope(tid, StatusCode::SC_TRANSACTION_NOT_EXISTS, "Original betId missing");
    }
    std::string win = decimal_to_ledger_units(req.at("winAmount").as_string(), it->second.exponent, false);
    it->second.units = add_unsigned(it->second.units, win);
    transactions_[tx_id] = TxRec{fp, false};
    return ok_envelope(tid, u, it->second);
}

Json InMemoryWallet::on_rollback(const Json& req) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string tid = req.at("traceId").as_string();
    std::string u = req.at("username").as_string();
    auto it = accounts_.find(u);
    if (it == accounts_.end()) return err_envelope(tid, StatusCode::SC_USER_NOT_EXISTS, "User missing");
    if (it->second.currency != to_upper(trim(req.at("currency").as_string()))) {
        return err_envelope(tid, StatusCode::SC_WRONG_CURRENCY, "Wrong currency");
    }
    std::string tx_id = req.at("transactionId").as_string();
    std::string fp = rollback_fingerprint(req);
    auto tx_it = transactions_.find(tx_id);
    if (tx_it != transactions_.end()) {
        if (tx_it->second.fp != fp) return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "Conflict");
        if (tx_it->second.empty) return err_envelope(tid, StatusCode::SC_TRANSACTION_NOT_EXISTS, "Never deducted");
        return ok_envelope(tid, u, it->second);
    }
    if (deducted_bets_.count(req.at("betId").as_string()) == 0) {
        transactions_[tx_id] = TxRec{fp, true};
        return err_envelope(tid, StatusCode::SC_TRANSACTION_NOT_EXISTS, "Never deducted");
    }
    std::string refund = decimal_to_ledger_units(req.at("amount").as_string(), it->second.exponent, false);
    it->second.units = add_unsigned(it->second.units, refund);
    transactions_[tx_id] = TxRec{fp, false};
    return ok_envelope(tid, u, it->second);
}

WebhookDispatcher::WebhookDispatcher(const Config& cfg, InMemoryWallet& wallet)
    : api_key_(trim(cfg.api_key)), hmac_secret_(cfg.hmac_secret), wallet_(wallet) {}

Json WebhookDispatcher::handle(
    const std::string& route_path,
    const std::string& api_key_header,
    const std::string& signature_header,
    const std::string& raw_body
) {
    Json parsed;
    bool valid_obj = false;
    std::string trace_id;
    try {
        parsed = Json::parse(raw_body);
        if (parsed.is_object()) {
            valid_obj = true;
            trace_id = trim(parsed.at("traceId").as_string()).substr(0, 128);
        }
    } catch (...) {}

    std::string auth = verify_webhook_headers(api_key_header, signature_header, raw_body, api_key_, hmac_secret_);
    if (auth != StatusCode::SC_OK) {
        Json r = Json::object();
        r.set("traceId", Json(trace_id));
        r.set("status", Json(auth));
        r.set("message", Json("Auth/signature failed"));
        return r;
    }
    if (!valid_obj) {
        Json r = Json::object();
        r.set("traceId", Json(trace_id));
        r.set("status", Json(StatusCode::SC_INVALID_REQUEST));
        r.set("message", Json("Invalid JSON object"));
        return r;
    }

    std::string clean = route_path.substr(0, route_path.find('?'));
    while (!clean.empty() && clean.back() == '/') clean.pop_back();
    auto ends_with = [](const std::string& s, const std::string& suf) {
        return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
    };
    if (ends_with(clean, "/wallet/balance")) return wallet_.on_balance(parsed);
    if (ends_with(clean, "/wallet/bet")) return wallet_.on_bet(parsed);
    if (ends_with(clean, "/wallet/bet_result")) return wallet_.on_bet_result(parsed);
    if (ends_with(clean, "/wallet/rollback")) return wallet_.on_rollback(parsed);

    Json r = Json::object();
    r.set("traceId", Json(trace_id));
    r.set("status", Json(StatusCode::SC_INVALID_REQUEST));
    r.set("message", Json("Unknown route"));
    return r;
}

} // namespace baccarat

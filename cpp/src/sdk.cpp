// SPDX-License-Identifier: MIT
#include "baccarat/sdk.hpp"

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <limits>
#include <sstream>
#include <thread>

namespace baccarat {

namespace {

constexpr size_t MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024;
std::once_flag g_curl_init_once;

void ensure_curl_global_init() {
    std::call_once(g_curl_init_once, []() {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    });
}

struct CurlGuard {
    CURL* curl = nullptr;
    struct curl_slist* headers = nullptr;
    ~CurlGuard() {
        if (headers) curl_slist_free_all(headers);
        if (curl) curl_easy_cleanup(curl);
    }
};

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

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
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
    static std::atomic<uint64_t> fallback_seq{1};
    unsigned char b[16];
    if (RAND_bytes(b, 16) != 1) {
        std::ostringstream oss;
        oss << std::chrono::steady_clock::now().time_since_epoch().count() << ":"
            << std::chrono::system_clock::now().time_since_epoch().count() << ":"
            << std::this_thread::get_id() << ":"
            << fallback_seq.fetch_add(1, std::memory_order_relaxed);
        std::string seed = oss.str();
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(seed.data()), seed.size(), digest);
        std::copy(digest, digest + 16, b);
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

struct CurlWriteState {
    std::string body;
    bool overflow = false;
};

size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) noexcept {
    if (!ptr || !userdata) return 0;
    auto* state = static_cast<CurlWriteState*>(userdata);
    if (size != 0 && nmemb > (std::numeric_limits<size_t>::max)() / size) {
        state->overflow = true;
        return 0;
    }
    size_t total = size * nmemb;
    if (total == 0) return 0;
    try {
        if (total > MAX_HTTP_RESPONSE_BYTES || state->body.size() > MAX_HTTP_RESPONSE_BYTES - total) {
            state->overflow = true;
            return 0; // abort transfer cleanly in libcurl
        }
        state->body.append(ptr, total);
        return total;
    } catch (...) {
        return 0;
    }
}

std::string fallback_status_for_http(long http_status) {
    if (http_status == 429) return StatusCode::SC_RATE_LIMITED;
    if (http_status >= 500 || http_status == 408) return StatusCode::SC_OPERATOR_TIMEOUT;
    return StatusCode::SC_INVALID_REQUEST;
}

std::string truncate_utf8(const std::string& s, size_t max_chars) {
    size_t i = 0;
    size_t chars = 0;
    while (i < s.size() && chars < max_chars) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t step = 1;
        if ((c & 0x80u) == 0u) step = 1;
        else if ((c & 0xE0u) == 0xC0u) step = 2;
        else if ((c & 0xF0u) == 0xE0u) step = 3;
        else if ((c & 0xF8u) == 0xF0u) step = 4;
        if (i + step > s.size()) break;
        i += step;
        ++chars;
    }
    return s.substr(0, i);
}

std::string extract_trace_hint(const std::string& raw_body) {
    std::string head = raw_body.substr(0, (std::min<size_t>)(raw_body.size(), 1024));
    size_t key_pos = head.find("\"traceId\"");
    if (key_pos == std::string::npos) return "";
    size_t colon = head.find(':', key_pos + 9);
    if (colon == std::string::npos) return "";
    size_t q1 = head.find('"', colon + 1);
    if (q1 == std::string::npos) return "";
    size_t q2 = q1 + 1;
    while (q2 < head.size() && head[q2] != '"' && (q2 - q1 - 1) < 128) {
        unsigned char c = static_cast<unsigned char>(head[q2]);
        if (!(std::isalnum(c) || c == '_' || c == '-' || c == '.' || c == ':')) return "";
        ++q2;
    }
    if (q2 >= head.size() || head[q2] != '"') return "";
    return head.substr(q1 + 1, q2 - q1 - 1);
}

Json make_err_json(const std::string& trace_id, const std::string& status, const std::string& msg) {
    Json r = Json::object();
    r.set("traceId", Json(trace_id));
    r.set("status", Json(status));
    r.set("message", Json(msg));
    return r;
}

} // namespace

bool is_retryable_status(const std::string& status) {
    std::string s = trim(status);
    return s == StatusCode::SC_TRANSACTION_STILL_PROCESSING
        || s == StatusCode::SC_OPERATOR_TIMEOUT
        || s == StatusCode::SC_RATE_LIMITED;
}

std::string sign_body(const std::string& raw_body, const std::string& hmac_secret) {
    if (hmac_secret.empty()) {
        throw SdkError("INVALID_CONFIG", "hmac_secret must be non-empty");
    }
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    // CRITICAL: Pass raw UTF-8 bytes of hmac_secret directly — NEVER Base64-decode!
    if (!HMAC(
            EVP_sha256(),
            hmac_secret.data(),
            static_cast<int>(hmac_secret.size()),
            reinterpret_cast<const unsigned char*>(raw_body.data()),
            raw_body.size(),
            md,
            &md_len
        )) {
        throw SdkError("CRYPTO_ERROR", "OpenSSL HMAC calculation failed");
    }
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

std::string adjustment_fingerprint(const Json& p) {
    return encode_tuple_fingerprint("wallet/adjustment", {
        p.at("transactionId").to_scalar_string(),
        p.at("username").to_scalar_string(),
        p.at("betId").to_scalar_string(),
        p.at("externalTransactionId").to_scalar_string(),
        p.at("roundId").to_scalar_string(),
        p.at("currency").to_scalar_string(),
        p.at("gameCode").to_scalar_string(),
        p.at("direction").to_scalar_string(),
        p.at("amount").to_scalar_string(),
        p.at("reasonCode").to_scalar_string(),
    });
}

std::string Config::resolved_base_url() const {
    if (trim(api_key).empty()) throw SdkError("INVALID_CONFIG", "api_key is required");
    if (hmac_secret.empty()) throw SdkError("INVALID_CONFIG", "hmac_secret is required");
    if (timeout_ms <= 0) throw SdkError("INVALID_CONFIG", "timeout_ms must be positive");
    std::string u = trim(base_url);
    if (u.empty()) {
        if (environment == Environment::Sandbox) u = SANDBOX_BASE_URL;
        else throw SdkError("INVALID_CONFIG", "base_url is required in Production environment");
    }
    std::string low = to_lower(u);
    if (low.rfind("http://", 0) != 0 && low.rfind("https://", 0) != 0) {
        throw SdkError("INVALID_CONFIG", "base_url must start with http:// or https://");
    }
    while (!u.empty() && u.back() == '/') u.pop_back();
    return u;
}

Client::Client(const Config& cfg)
    : api_key_(trim(cfg.api_key)),
      hmac_secret_(cfg.hmac_secret),
      base_url_(cfg.resolved_base_url()),
      timeout_ms_(cfg.timeout_ms),
      send_timestamp_(cfg.send_timestamp) {
    ensure_curl_global_init();
}

Json Client::post_signed(const std::string& route_path, Json payload) const {
    if (!payload.is_object()) payload = Json::object();
    std::string trace_id = trim(payload.at("traceId").as_string());
    if (trace_id.empty()) trace_id = uuid_v4();
    payload.set("traceId", Json(trace_id));

    std::string raw_body = payload.dump();
    std::string sig = sign_body(raw_body, hmac_secret_);
    std::string url = base_url_ + route_path;

    ensure_curl_global_init();
    CurlGuard guard;
    guard.curl = curl_easy_init();
    if (!guard.curl) throw SdkError(StatusCode::SC_OPERATOR_TIMEOUT, "curl_easy_init failed");

    std::string hdr_key = "X-API-Key: " + api_key_;
    std::string hdr_sig = "X-Signature: " + sig;
    std::string hdr_ts;
    auto append_header = [&](const char* hdr) {
        struct curl_slist* next = curl_slist_append(guard.headers, hdr);
        if (!next) {
            throw SdkError(StatusCode::SC_OPERATOR_TIMEOUT, "curl_slist_append failed");
        }
        guard.headers = next;
    };
    append_header("Content-Type: application/json");
    append_header("Accept: application/json");
    append_header(hdr_key.c_str());
    append_header(hdr_sig.c_str());
    if (send_timestamp_) {
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        hdr_ts = "X-Timestamp: " + std::to_string(now_ms);
        append_header(hdr_ts.c_str());
    }

    CurlWriteState write_state;
    curl_easy_setopt(guard.curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(guard.curl, CURLOPT_POST, 1L);
    curl_easy_setopt(guard.curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(guard.curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(guard.curl, CURLOPT_HTTPHEADER, guard.headers);
    curl_easy_setopt(guard.curl, CURLOPT_POSTFIELDS, raw_body.data());
    curl_easy_setopt(guard.curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(raw_body.size()));
    curl_easy_setopt(guard.curl, CURLOPT_TIMEOUT_MS, timeout_ms_);
    curl_easy_setopt(guard.curl, CURLOPT_CONNECTTIMEOUT_MS, (std::min<long>)(timeout_ms_, 5000L));
    curl_easy_setopt(guard.curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(guard.curl, CURLOPT_WRITEDATA, &write_state);

    CURLcode rc = curl_easy_perform(guard.curl);
    long http_code = 0;
    curl_easy_getinfo(guard.curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (write_state.overflow) {
        throw SdkError(StatusCode::SC_INVALID_REQUEST, "Gateway response exceeded 16 MiB limit");
    }
    if (rc != CURLE_OK) {
        throw SdkError(StatusCode::SC_OPERATOR_TIMEOUT, std::string("curl error: ") + curl_easy_strerror(rc));
    }

    Json parsed;
    try {
        parsed = Json::parse(write_state.body);
    } catch (...) {
        throw ApiError(fallback_status_for_http(http_code), "Non-JSON response", trace_id, static_cast<int>(http_code));
    }
    if (!parsed.is_object()) {
        throw ApiError(fallback_status_for_http(http_code), "Malformed envelope object", trace_id, static_cast<int>(http_code));
    }
    std::string st = trim(parsed.at("status").as_string());
    std::string eff_trace = parsed.at("traceId").as_string().empty() ? trace_id : parsed.at("traceId").as_string();
    if (http_code != 200 || st != StatusCode::SC_OK) {
        std::map<std::string, std::string> val_map;
        const Json& val_obj = parsed.at("validation");
        if (val_obj.is_object()) {
            for (const auto& kv : val_obj.as_object()) {
                val_map[kv.first] = kv.second.to_scalar_string();
            }
        }
        throw ApiError(
            st.empty() ? fallback_status_for_http(http_code) : st,
            parsed.at("message").as_string(),
            eff_trace,
            static_cast<int>(http_code),
            std::move(val_map)
        );
    }
    Json out = Json::object();
    out.set("traceId", Json(eff_trace));
    out.set("status", Json(StatusCode::SC_OK));
    out.set("data", parsed.at("data"));
    return out;
}

Json Client::ping(Json params) const { return post_signed("/operator/v1/ping", std::move(params)); }
Json Client::create_game_url(Json params) const { return post_signed("/operator/v1/game/url", std::move(params)); }
Json Client::list_tables(Json params) const { return post_signed("/operator/v1/game/tables", std::move(params)); }
Json Client::terminate_sessions(Json params) const { return post_signed("/operator/v1/game/terminate", std::move(params)); }
Json Client::update_player_status(Json params) const { return post_signed("/operator/v1/player/status", std::move(params)); }
Json Client::update_player_limits(Json params) const { return post_signed("/operator/v1/player/limits", std::move(params)); }

Json Client::list_transactions(Json params) const {
    if (!params.at("fromTime").is_int() || !params.at("toTime").is_int()) {
        throw SdkError("INVALID_ARGUMENT", "fromTime and toTime must be integers");
    }
    int64_t from = params.at("fromTime").as_int(-1);
    int64_t to = params.at("toTime").as_int(-1);
    if (from < 0 || to < from) throw SdkError("INVALID_ARGUMENT", "invalid [fromTime, toTime]");
    return post_signed("/operator/v1/transaction/list", std::move(params));
}

std::vector<Json> Client::list_all_transactions(
    int64_t from_time,
    int64_t to_time,
    int page_size,
    Json filters,
    int rate_limit_max_retries,
    int rate_limit_backoff_ms
) const {
    if (page_size < 1 || page_size > MAX_PAGE_SIZE) {
        throw SdkError("INVALID_ARGUMENT", "page_size out of range 1..20000");
    }
    int max_retries = (std::max)(0, rate_limit_max_retries);
    int backoff_ms = (std::max)(0, rate_limit_backoff_ms);
    std::vector<Json> all;
    int page_no = 1;
    while (true) {
        Json p = filters.is_object() ? filters : Json::object();
        p.erase("traceId");
        p.set("fromTime", Json(from_time));
        p.set("toTime", Json(to_time));
        p.set("pageNo", Json(page_no));
        p.set("pageSize", Json(page_size));
        Json res;
        int attempt = 0;
        while (true) {
            try {
                res = list_transactions(p);
                break;
            } catch (const ApiError& e) {
                if (e.status == StatusCode::SC_RATE_LIMITED && attempt < max_retries) {
                    ++attempt;
                    int wait_ms = backoff_ms * attempt;
                    if (wait_ms > 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(wait_ms));
                    }
                    continue;
                }
                throw;
            }
        }
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
    if (bet_id.empty()) {
        throw SdkError("INVALID_ARGUMENT", "betId is required");
    }
    if (params.contains("fromTime") || params.contains("toTime")) {
        if (!params.at("fromTime").is_int() || !params.at("toTime").is_int()) {
            throw SdkError("INVALID_ARGUMENT", "fromTime and toTime must both be integers when specified");
        }
        int64_t from = params.at("fromTime").as_int(-1);
        int64_t to = params.at("toTime").as_int(-1);
        if (from < 0 || to < from || (to - from) > MAX_DETAIL_WINDOW_MS) {
            throw SdkError("INVALID_ARGUMENT", "detail window must satisfy 0 <= toTime - fromTime <= 604800000");
        }
    }
    return post_signed("/operator/v1/transaction/detail", std::move(params));
}

Json Client::list_unsettled_transactions(Json params) const {
    if (params.contains("fromTime") || params.contains("toTime")) {
        if (!params.at("fromTime").is_int() || !params.at("toTime").is_int()) {
            throw SdkError("INVALID_ARGUMENT", "fromTime and toTime must both be integers when specified");
        }
        int64_t from = params.at("fromTime").as_int(-1);
        int64_t to = params.at("toTime").as_int(-1);
        if (from < 0 || to < from || (to - from) > MAX_DETAIL_WINDOW_MS) {
            throw SdkError("INVALID_ARGUMENT", "unsettled window must satisfy 0 <= toTime - fromTime <= 604800000");
        }
    }
    return post_signed("/operator/v1/transaction/unsettled", std::move(params));
}

Json Client::get_wallet_transaction_status(Json params) const {
    std::string tx_id = trim(params.at("transactionId").as_string());
    std::string bet_id = trim(params.at("betId").as_string());
    std::string username = trim(params.at("username").as_string());
    if (tx_id.empty() && bet_id.empty() && username.empty()) {
        throw SdkError("INVALID_ARGUMENT", "At least one of transactionId, betId, or username is required");
    }
    bool user_only = (!username.empty() && tx_id.empty() && bet_id.empty());
    bool has_window = (params.contains("fromTime") || params.contains("toTime"));
    if (user_only || has_window) {
        if (!params.at("fromTime").is_int() || !params.at("toTime").is_int()) {
            throw SdkError("INVALID_ARGUMENT", "fromTime and toTime must both be integers when querying by username alone or specifying a window");
        }
        int64_t from = params.at("fromTime").as_int(-1);
        int64_t to = params.at("toTime").as_int(-1);
        if (from < 0 || to < from || (user_only && (to - from) > 86400000LL)) {
            throw SdkError(
                "INVALID_ARGUMENT",
                user_only
                    ? "Username query window must satisfy 0 <= toTime - fromTime <= 86400000"
                    : "Invalid [fromTime, toTime] window"
            );
        }
    }
    return post_signed("/operator/v1/wallet/transaction-status", std::move(params));
}

namespace {
bool is_valid_non_negative_decimal(const std::string& s) {
    if (s.empty()) return false;
    bool seen_dot = false;
    for (size_t i = 0; i < s.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        if (c == '.') {
            if (seen_dot || i == 0 || i + 1 == s.size()) return false;
            seen_dot = true;
        } else if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}
} // namespace

Json wallet_ok(
    const std::string& trace_id,
    const std::string& username,
    const std::string& currency,
    const std::string& balance,
    int64_t timestamp_ms
) {
    if (!is_valid_non_negative_decimal(balance)) {
        throw SdkError(
            "INVALID_ARGUMENT",
            "wallet_ok balance must be a non-empty non-negative decimal string matching ^\\d+(?:\\.\\d+)?$"
        );
    }
    int64_t ts = timestamp_ms;
    if (ts <= 0) {
        ts = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count());
    }
    Json data = Json::object();
    data.set("username", Json(username));
    data.set("currency", Json(currency));
    data.set("balance", Json(balance));
    data.set("timestamp", Json(ts));

    Json r = Json::object();
    r.set("traceId", Json(trace_id));
    r.set("status", Json(StatusCode::SC_OK));
    r.set("data", std::move(data));
    return r;
}

Json wallet_error(
    const std::string& trace_id,
    const std::string& status,
    const std::string& message
) {
    std::string st = trim(status);
    if (st.empty() || st == StatusCode::SC_OK) {
        throw SdkError(
            "INVALID_ARGUMENT",
            "wallet_error status must be a non-empty error status code (cannot be SC_OK)"
        );
    }
    Json r = Json::object();
    r.set("traceId", Json(trace_id));
    r.set("status", Json(st));
    if (!message.empty()) {
        r.set("message", Json(message));
    }
    return r;
}

Json WalletHandler::on_adjustment(const Json& req) {
    return make_err_json(req.at("traceId").as_string(), StatusCode::SC_INVALID_REQUEST, "on_adjustment not implemented");
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
    return wallet_ok(trace_id, username, acct.currency, ledger_units_to_decimal(acct.units, acct.exponent));
}

Json InMemoryWallet::err_envelope(const std::string& trace_id, const std::string& status, const std::string& msg) {
    return make_err_json(trace_id, status, msg);
}

Json InMemoryWallet::on_balance(const Json& req) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string tid = req.at("traceId").as_string();
    std::string u = trim(req.at("username").as_string());
    std::string cur = to_upper(trim(req.at("currency").as_string()));
    if (u.empty() || cur.empty()) return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "username and currency required");
    auto it = accounts_.find(u);
    if (it == accounts_.end()) return err_envelope(tid, StatusCode::SC_USER_NOT_EXISTS, "User missing");
    if (it->second.currency != cur) return err_envelope(tid, StatusCode::SC_WRONG_CURRENCY, "Wrong currency");
    if (it->second.disabled) return err_envelope(tid, StatusCode::SC_USER_DISABLED, "Disabled");
    if (!it->second.tokens.empty() && it->second.tokens.count(req.at("token").as_string()) == 0) {
        return err_envelope(tid, StatusCode::SC_INVALID_TOKEN, "Invalid token");
    }
    return ok_envelope(tid, u, it->second);
}

Json InMemoryWallet::on_bet(const Json& req) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string tid = req.at("traceId").as_string();
    std::string tx_id = trim(req.at("transactionId").as_string());
    std::string bet_id = trim(req.at("betId").as_string());
    std::string u = trim(req.at("username").as_string());
    std::string cur = to_upper(trim(req.at("currency").as_string()));
    std::string amt_str = req.at("amount").as_string();
    if (tx_id.empty() || bet_id.empty() || u.empty() || cur.empty() || amt_str.empty()) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "Missing required bet fields");
    }
    auto it = accounts_.find(u);
    if (it == accounts_.end()) return err_envelope(tid, StatusCode::SC_USER_NOT_EXISTS, "User missing");
    if (it->second.currency != cur) return err_envelope(tid, StatusCode::SC_WRONG_CURRENCY, "Wrong currency");

    std::string fp = bet_fingerprint(req);
    auto tx_it = transactions_.find(tx_id);
    if (tx_it != transactions_.end()) {
        if (tx_it->second.type != "BET" || tx_it->second.fp != fp) {
            return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "Conflict");
        }
        return ok_envelope(tid, u, it->second);
    }
    if (deducted_bets_.count(bet_id) > 0) {
        return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "Duplicate betId");
    }
    if (it->second.disabled) return err_envelope(tid, StatusCode::SC_USER_DISABLED, "Disabled");
    if (!it->second.tokens.empty() && it->second.tokens.count(req.at("token").as_string()) == 0) {
        return err_envelope(tid, StatusCode::SC_INVALID_TOKEN, "Invalid token");
    }
    std::string stake = decimal_to_ledger_units(amt_str, it->second.exponent, false);
    if (compare_unsigned(stake, "0") <= 0) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "Bet amount must be positive");
    }
    if (compare_unsigned(it->second.units, stake) < 0) {
        return err_envelope(tid, StatusCode::SC_INSUFFICIENT_FUNDS, "Insufficient funds");
    }
    it->second.units = sub_unsigned(it->second.units, stake);
    transactions_[tx_id] = TxRec{"BET", fp, false};
    deducted_bets_[bet_id] = BetRec{tx_id, u, it->second.currency, stake, "DEDUCTED"};
    return ok_envelope(tid, u, it->second);
}

Json InMemoryWallet::on_bet_result(const Json& req) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string tid = req.at("traceId").as_string();
    std::string tx_id = trim(req.at("transactionId").as_string());
    std::string bet_id = trim(req.at("betId").as_string());
    std::string u = trim(req.at("username").as_string());
    std::string cur = to_upper(trim(req.at("currency").as_string()));
    std::string win_str = req.at("winAmount").as_string();
    std::string bet_amt_str = req.at("betAmount").as_string();
    if (tx_id.empty() || bet_id.empty() || u.empty() || cur.empty() || win_str.empty() || bet_amt_str.empty()) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "Missing required bet_result fields");
    }
    auto it = accounts_.find(u);
    if (it == accounts_.end()) return err_envelope(tid, StatusCode::SC_USER_NOT_EXISTS, "User missing");
    if (it->second.currency != cur) return err_envelope(tid, StatusCode::SC_WRONG_CURRENCY, "Wrong currency");

    std::string fp = bet_result_fingerprint(req);
    auto tx_it = transactions_.find(tx_id);
    if (tx_it != transactions_.end()) {
        if (tx_it->second.type != "SETTLE" || tx_it->second.fp != fp) {
            return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "Conflict");
        }
        return ok_envelope(tid, u, it->second);
    }
    auto bet_it = deducted_bets_.find(bet_id);
    if (bet_it == deducted_bets_.end()) {
        return err_envelope(tid, StatusCode::SC_TRANSACTION_NOT_EXISTS, "Original betId missing");
    }
    std::string bet_units = decimal_to_ledger_units(bet_amt_str, it->second.exponent, false);
    std::string win = decimal_to_ledger_units(win_str, it->second.exponent, false);
    if (bet_it->second.username != u || bet_it->second.currency != it->second.currency || bet_it->second.stake != bet_units) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "bet_result mismatch");
    }
    if (bet_it->second.state != "DEDUCTED") {
        return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "betId already finalized");
    }
    it->second.units = add_unsigned(it->second.units, win);
    bet_it->second.state = "SETTLED";
    transactions_[tx_id] = TxRec{"SETTLE", fp, false};
    return ok_envelope(tid, u, it->second);
}

Json InMemoryWallet::on_rollback(const Json& req) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string tid = req.at("traceId").as_string();
    std::string tx_id = trim(req.at("transactionId").as_string());
    std::string bet_id = trim(req.at("betId").as_string());
    std::string u = trim(req.at("username").as_string());
    std::string cur = to_upper(trim(req.at("currency").as_string()));
    std::string amt_str = req.at("amount").as_string();
    if (tx_id.empty() || bet_id.empty() || u.empty() || cur.empty() || amt_str.empty()) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "Missing required rollback fields");
    }
    auto it = accounts_.find(u);
    if (it == accounts_.end()) return err_envelope(tid, StatusCode::SC_USER_NOT_EXISTS, "User missing");
    if (it->second.currency != cur) return err_envelope(tid, StatusCode::SC_WRONG_CURRENCY, "Wrong currency");

    std::string fp = rollback_fingerprint(req);
    auto tx_it = transactions_.find(tx_id);
    if (tx_it != transactions_.end()) {
        if (tx_it->second.type != "ROLLBACK" || tx_it->second.fp != fp) {
            return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "Conflict");
        }
        if (tx_it->second.empty) return err_envelope(tid, StatusCode::SC_TRANSACTION_NOT_EXISTS, "Never deducted");
        return ok_envelope(tid, u, it->second);
    }
    std::string refund = decimal_to_ledger_units(amt_str, it->second.exponent, false);
    if (compare_unsigned(refund, "0") <= 0) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "Rollback amount must be positive");
    }
    auto bet_it = deducted_bets_.find(bet_id);
    if (bet_it == deducted_bets_.end()) {
        transactions_[tx_id] = TxRec{"ROLLBACK", fp, true};
        return err_envelope(tid, StatusCode::SC_TRANSACTION_NOT_EXISTS, "Never deducted");
    }
    if (bet_it->second.username != u || bet_it->second.currency != it->second.currency || bet_it->second.stake != refund) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "Rollback mismatch");
    }
    if (bet_it->second.state != "DEDUCTED") {
        return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "betId already finalized");
    }
    it->second.units = add_unsigned(it->second.units, refund);
    bet_it->second.state = "ROLLED_BACK";
    transactions_[tx_id] = TxRec{"ROLLBACK", fp, false};
    return ok_envelope(tid, u, it->second);
}

Json InMemoryWallet::on_adjustment(const Json& req) {
    std::lock_guard<std::mutex> lk(mu_);
    std::string tid = req.at("traceId").as_string();
    std::string tx_id = trim(req.at("transactionId").as_string());
    std::string bet_id = trim(req.at("betId").as_string());
    std::string u = trim(req.at("username").as_string());
    std::string cur = to_upper(trim(req.at("currency").as_string()));
    std::string dir = to_upper(trim(req.at("direction").as_string()));
    std::string reason = trim(req.at("reasonCode").as_string());
    std::string amt_str = req.at("amount").as_string();
    if (tx_id.empty() || bet_id.empty() || u.empty() || cur.empty() || reason.empty() || amt_str.empty() || (dir != "CREDIT" && dir != "DEBIT")) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "Missing or invalid adjustment fields");
    }
    auto it = accounts_.find(u);
    if (it == accounts_.end()) return err_envelope(tid, StatusCode::SC_USER_NOT_EXISTS, "User missing");
    if (it->second.currency != cur) return err_envelope(tid, StatusCode::SC_WRONG_CURRENCY, "Wrong currency");

    std::string fp = adjustment_fingerprint(req);
    auto tx_it = transactions_.find(tx_id);
    if (tx_it != transactions_.end()) {
        if (tx_it->second.type != "ADJUSTMENT" || tx_it->second.fp != fp) {
            return err_envelope(tid, StatusCode::SC_TRANSACTION_DUPLICATED, "Conflict");
        }
        return ok_envelope(tid, u, it->second);
    }
    auto bet_it = deducted_bets_.find(bet_id);
    if (bet_it == deducted_bets_.end()) {
        return err_envelope(tid, StatusCode::SC_TRANSACTION_NOT_EXISTS, "Original betId missing");
    }
    if (bet_it->second.username != u || bet_it->second.currency != it->second.currency) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "Adjustment mismatch");
    }
    std::string adj_units = decimal_to_ledger_units(amt_str, it->second.exponent, false);
    if (compare_unsigned(adj_units, "0") <= 0) {
        return err_envelope(tid, StatusCode::SC_INVALID_REQUEST, "Adjustment amount must be positive");
    }
    if (dir == "DEBIT") {
        if (compare_unsigned(it->second.units, adj_units) < 0) {
            return err_envelope(tid, StatusCode::SC_INSUFFICIENT_FUNDS, "Insufficient funds");
        }
        it->second.units = sub_unsigned(it->second.units, adj_units);
    } else {
        it->second.units = add_unsigned(it->second.units, adj_units);
    }
    transactions_[tx_id] = TxRec{"ADJUSTMENT", fp, false};
    return ok_envelope(tid, u, it->second);
}

WebhookDispatcher::WebhookDispatcher(const Config& cfg, WalletHandler& wallet)
    : WebhookDispatcher(cfg.api_key, cfg.hmac_secret, wallet) {}

WebhookDispatcher::WebhookDispatcher(std::string api_key, std::string hmac_secret, WalletHandler& wallet)
    : api_key_(trim(api_key)), hmac_secret_(std::move(hmac_secret)), wallet_(wallet) {
    if (api_key_.empty()) throw SdkError("INVALID_CONFIG", "api_key is required");
    if (hmac_secret_.empty()) throw SdkError("INVALID_CONFIG", "hmac_secret is required");
}

Json WebhookDispatcher::handle(
    const std::string& route_path,
    const std::string& api_key_header,
    const std::string& signature_header,
    const std::string& raw_body
) {
    if (raw_body.size() > MAX_WEBHOOK_BODY_BYTES) {
        return make_err_json("", StatusCode::SC_INVALID_REQUEST, "Request body exceeds 1 MiB limit");
    }

    // Verify X-API-Key & X-Signature over raw bytes BEFORE JSON parsing!
    std::string auth = verify_webhook_headers(api_key_header, signature_header, raw_body, api_key_, hmac_secret_);
    if (auth != StatusCode::SC_OK) {
        return make_err_json(extract_trace_hint(raw_body), auth, "Auth/signature failed");
    }

    Json parsed;
    try {
        parsed = Json::parse(raw_body);
    } catch (...) {
        return make_err_json("", StatusCode::SC_INVALID_REQUEST, "Invalid JSON object");
    }
    if (!parsed.is_object()) {
        return make_err_json("", StatusCode::SC_INVALID_REQUEST, "Invalid JSON object");
    }
    std::string trace_id = truncate_utf8(trim(parsed.at("traceId").as_string()), 128);

    std::string clean = route_path.substr(0, route_path.find('?'));
    while (!clean.empty() && clean.back() == '/') clean.pop_back();
    auto ends_with = [](const std::string& s, const std::string& suf) {
        return s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
    };
    try {
        if (ends_with(clean, "/wallet/balance")) return wallet_.on_balance(parsed);
        if (ends_with(clean, "/wallet/bet")) return wallet_.on_bet(parsed);
        if (ends_with(clean, "/wallet/bet_result")) return wallet_.on_bet_result(parsed);
        if (ends_with(clean, "/wallet/rollback")) return wallet_.on_rollback(parsed);
        if (ends_with(clean, "/wallet/adjustment")) return wallet_.on_adjustment(parsed);
        return make_err_json(trace_id, StatusCode::SC_INVALID_REQUEST, "Unknown route");
    } catch (const SdkError& e) {
        std::string st = (e.code.rfind("SC_", 0) == 0) ? e.code : StatusCode::SC_INVALID_REQUEST;
        return make_err_json(trace_id, st, e.what());
    } catch (const std::exception&) {
        return make_err_json(trace_id, StatusCode::SC_OPERATOR_TIMEOUT, "Temporary wallet handler error");
    } catch (...) {
        return make_err_json(trace_id, StatusCode::SC_OPERATOR_TIMEOUT, "Temporary wallet handler error");
    }
}

} // namespace baccarat

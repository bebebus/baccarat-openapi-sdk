// SPDX-License-Identifier: MIT
#include "baccarat/sdk.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <thread>

using namespace baccarat;

namespace {

void require_true(bool cond, const std::string& label) {
    if (!cond) {
        std::cerr << "FAIL: " << label << "\n";
        std::exit(1);
    }
}

void require_eq(const std::string& actual, const std::string& expected, const std::string& label) {
    if (actual != expected) {
        std::cerr << "FAIL [" << label << "]: expected <" << expected << "> got <" << actual << ">\n";
        std::exit(1);
    }
}

std::string read_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    require_true(static_cast<bool>(ifs), "open " + path);
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

std::string to_lower_ascii(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // namespace

int main() {
    std::signal(SIGPIPE, SIG_IGN);
    Json doc = Json::parse(read_file("../test-vectors.json"));

    // 1. HMAC & header verification vectors
    for (const auto& v : doc.at("hmacVectors").as_array()) {
        std::string name = v.at("name").as_string();
        std::string raw = v.at("rawBody").as_string();
        std::string sec = v.at("secret").as_string();
        std::string sig = v.at("signature").as_string();
        require_true(static_cast<int64_t>(raw.size()) == v.at("utf8ByteLength").as_int(), name + ":len");
        require_eq(sign_body(raw, sec), sig, name + ":sign");
        require_true(verify_signature(raw, sig, sec), name + ":verify");
        if (v.contains("wrongBase64DecodedSignature")) {
            require_true(!verify_signature(raw, v.at("wrongBase64DecodedSignature").as_string(), sec), name + ":wrongB64");
        }
    }
    for (const auto& h : doc.at("headerVerificationVectors").as_array()) {
        std::string got = verify_webhook_headers(
            h.at("apiKeyHeader").as_string(),
            h.at("signatureHeader").as_string(),
            h.at("rawBody").as_string(),
            h.at("expectedApiKey").as_string(),
            h.at("hmacSecret").as_string()
        );
        require_eq(got, h.at("expectedStatus").as_string(), h.at("name").as_string());
    }

    // 2. Idempotency vectors
    const Json& idem = doc.at("idempotencyVectors");
    const Json& bet = idem.at("bet");
    require_eq(bet_fingerprint(bet.at("initial")), bet.at("expectedFingerprint").as_string(), "bet:init");
    require_eq(bet_fingerprint(bet.at("retrySameBusiness")), bet.at("expectedFingerprint").as_string(), "bet:retry");
    require_eq(bet_fingerprint(bet.at("conflictDifferentAmount")), bet.at("conflictFingerprint").as_string(), "bet:conflict");

    const Json& stl = idem.at("betResult");
    require_eq(bet_result_fingerprint(stl.at("initial")), stl.at("expectedFingerprint").as_string(), "stl:init");
    require_eq(bet_result_fingerprint(stl.at("retrySameBusiness")), stl.at("expectedFingerprint").as_string(), "stl:retry");
    require_eq(bet_result_fingerprint(stl.at("conflictDifferentWinAmount")), stl.at("conflictFingerprint").as_string(), "stl:conflict");

    const Json& rb = idem.at("rollback");
    require_eq(rollback_fingerprint(rb.at("initial")), rb.at("expectedFingerprint").as_string(), "rb:init");
    require_eq(rollback_fingerprint(rb.at("retrySameBusiness")), rb.at("expectedFingerprint").as_string(), "rb:retry");
    require_eq(rollback_fingerprint(rb.at("conflictDifferentAmount")), rb.at("conflictFingerprint").as_string(), "rb:conflict");

    const Json& adj = idem.at("adjustment");
    require_eq(adjustment_fingerprint(adj.at("initial")), adj.at("expectedFingerprint").as_string(), "adj:init");
    require_eq(adjustment_fingerprint(adj.at("retrySameBusiness")), adj.at("expectedFingerprint").as_string(), "adj:retry");
    require_eq(adjustment_fingerprint(adj.at("conflictDifferentDirection")), adj.at("conflictFingerprint").as_string(), "adj:conflict");

    // 3. Money & status vectors
    for (const auto& m : doc.at("moneyVectors").at("valid").as_array()) {
        int exp = static_cast<int>(m.at("displayExponent").as_int());
        std::string u = decimal_to_ledger_units(m.at("raw").as_string(), exp, m.at("allowNegative").as_bool());
        require_eq(u, m.at("expectedUnits").as_string(), m.at("name").as_string() + ":units");
        require_eq(ledger_units_to_decimal(u, exp), m.at("expectedFormatted").as_string(), m.at("name").as_string() + ":fmt");
    }
    for (const auto& inv : doc.at("moneyVectors").at("invalid").as_array()) {
        bool threw = false;
        try {
            decimal_to_ledger_units(inv.at("raw").as_string(), static_cast<int>(inv.at("displayExponent").as_int()), inv.at("allowNegative").as_bool());
        } catch (const SdkError&) {
            threw = true;
        }
        require_true(threw, "money:invalid:" + inv.at("name").as_string());
    }
    for (const auto& sc : doc.at("statusCodes").as_array()) {
        require_true(is_retryable_status(sc.at("code").as_string()) == sc.at("retryable").as_bool(), "sc:" + sc.at("code").as_string());
    }

    // 4. POSIX loopback HTTP server + libcurl S2S Client round-trip
    const std::string api_key = "ak_0123456789abcdef0123456789abcdef";
    const std::string secret = "dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s";

    int srv_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    require_true(srv_fd >= 0, "socket");
    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    require_true(::bind(srv_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0, "bind");
    socklen_t len = sizeof(addr);
    require_true(::getsockname(srv_fd, reinterpret_cast<sockaddr*>(&addr), &len) == 0, "getsockname");
    int port = ntohs(addr.sin_port);
    require_true(::listen(srv_fd, 16) == 0, "listen");

    std::atomic<bool> stop_srv{false};
    std::atomic<int> rl_p1_calls{0};
    std::string last_ts_hdr;
    std::vector<std::string> list_traces;
    std::mutex hdr_mu;
    std::thread server_thread([&]() {
        while (!stop_srv.load()) {
            int cfd = ::accept(srv_fd, nullptr, nullptr);
            if (cfd < 0) break;
            std::string req;
            char buf[4096];
            size_t header_end = std::string::npos;
            size_t content_len = 0;
            while (true) {
                ssize_t n = ::read(cfd, buf, sizeof(buf));
                if (n <= 0) break;
                req.append(buf, static_cast<size_t>(n));
                if (header_end == std::string::npos) {
                    header_end = req.find("\r\n\r\n");
                    if (header_end != std::string::npos) {
                        std::istringstream hs(req.substr(0, header_end));
                        std::string line;
                        while (std::getline(hs, line)) {
                            std::string low = to_lower_ascii(line);
                            if (low.rfind("content-length:", 0) == 0) {
                                content_len = static_cast<size_t>(std::stoul(line.substr(15)));
                            }
                        }
                    }
                }
                if (header_end != std::string::npos && req.size() >= header_end + 4 + content_len) break;
            }
            if (header_end == std::string::npos) {
                ::close(cfd);
                continue;
            }
            std::string head = req.substr(0, header_end);
            std::string raw_body = req.substr(header_end + 4, content_len);
            std::istringstream hs(head);
            std::string req_line;
            std::getline(hs, req_line);
            std::istringstream rl(req_line);
            std::string method, path;
            rl >> method >> path;

            std::string x_key, x_sig;
            std::string line;
            while (std::getline(hs, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                auto colon = line.find(':');
                if (colon != std::string::npos) {
                    std::string k = to_lower_ascii(line.substr(0, colon));
                    std::string v = line.substr(colon + 1);
                    if (k == "x-api-key") x_key = v;
                    if (k == "x-signature") x_sig = v;
                    if (k == "x-timestamp") {
                        std::lock_guard<std::mutex> lk(hdr_mu);
                        last_ts_hdr = v;
                    }
                }
            }

            if (path == "/operator/v1/ping") {
                Json ping_body = Json::parse(raw_body);
                std::string ptid = ping_body.at("traceId").as_string();
                if (ptid == "m1_json_429") {
                    std::string body_429 = "{\"statusCode\":429,\"message\":\"Too Many Requests\"}";
                    std::string http_429 = "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                        + std::to_string(body_429.size()) + "\r\n\r\n" + body_429;
                    (void)::write(cfd, http_429.data(), http_429.size());
                    ::close(cfd);
                    continue;
                }
                if (ptid == "m1_json_503") {
                    std::string body_503 = "{\"error\":\"unavailable\"}";
                    std::string http_503 = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                        + std::to_string(body_503.size()) + "\r\n\r\n" + body_503;
                    (void)::write(cfd, http_503.data(), http_503.size());
                    ::close(cfd);
                    continue;
                }
                if (ptid == "m2_overflow") {
                    const size_t total_len = 16 * 1024 * 1024 + 65536;
                    std::string hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                        + std::to_string(total_len) + "\r\n\r\n";
                    if (::write(cfd, hdr.data(), hdr.size()) > 0) {
                        std::string chunk(65536, 'a');
                        size_t sent = 0;
                        while (sent < total_len) {
                            ssize_t w = ::write(cfd, chunk.data(), (std::min)(chunk.size(), total_len - sent));
                            if (w <= 0) break;
                            sent += static_cast<size_t>(w);
                        }
                    }
                    ::close(cfd);
                    continue;
                }
                std::string raw_429 = "Too Many Requests";
                std::string http_429 = "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: "
                    + std::to_string(raw_429.size()) + "\r\n\r\n" + raw_429;
                (void)::write(cfd, http_429.data(), http_429.size());
                ::close(cfd);
                continue;
            }

            std::string st = verify_webhook_headers(x_key, x_sig, raw_body, api_key, secret);
            Json body = Json::parse(raw_body);
            Json resp = Json::object();
            resp.set("traceId", body.at("traceId"));
            std::string status_line = "200 OK";
            if (st != StatusCode::SC_OK) {
                resp.set("status", Json(st));
                resp.set("message", Json("bad auth"));
            } else {
                resp.set("status", Json("SC_OK"));
                if (path == "/operator/v1/game/tables") {
                    Json t = Json::object();
                    t.set("tableId", Json("T-A2"));
                    t.set("currency", Json("USD"));
                    Json data = Json::object();
                    data.set("tables", Json(Json::Array{t}));
                    data.set("pageNo", Json(1));
                    data.set("pageSize", Json(50));
                    data.set("total", Json(1));
                    resp.set("data", data);
                } else if (path == "/operator/v1/game/url") {
                    if (body.at("currency").as_string() != "USD") {
                        resp.set("status", Json("SC_WRONG_CURRENCY"));
                        resp.set("message", Json("USD required"));
                    } else {
                        std::string tok = "b2bt_" + std::string(48, 'f');
                        Json data = Json::object();
                        data.set("gameUrl", Json("https://play.lt.cniia.cloud/?token=" + tok));
                        data.set("token", Json(tok));
                        resp.set("data", data);
                    }
                } else if (path == "/operator/v1/game/terminate") {
                    Json data = Json::object();
                    data.set("username", body.at("username"));
                    data.set("terminatedSessions", Json(1));
                    data.set("revokedLaunchTokens", Json(0));
                    resp.set("data", data);
                } else if (path == "/operator/v1/player/status") {
                    if (body.at("username").as_string() == "locked_user") {
                        status_line = "403 Forbidden";
                        resp.set("status", Json("SC_USER_DISABLED"));
                        resp.set("message", Json("PLATFORM_RISK_LOCKED"));
                    } else if (body.at("username").as_string() == "capped_user" && body.at("bettingEnabled").as_bool(false) && !body.at("resetPnlWindow").as_bool(false)) {
                        status_line = "409 Conflict";
                        resp.set("status", Json("SC_INVALID_REQUEST"));
                        resp.set("message", Json("PNL_CAP_BREACHED_RESET_REQUIRED"));
                    } else {
                        Json data = Json::object();
                        data.set("username", body.at("username"));
                        data.set("status", Json("ACTIVE"));
                        data.set("bettingEnabled", Json(true));
                        data.set("rgRestricted", Json(false));
                        data.set("revokedSessions", Json(0));
                        data.set("revokedLaunchTokens", Json(0));
                        resp.set("data", data);
                    }
                } else if (path == "/operator/v1/wallet/transaction-status") {
                    Json row = Json::object();
                    row.set("transactionId", Json("bet_cpp_1"));
                    row.set("username", body.at("username"));
                    row.set("status", Json("COMPLETED"));
                    Json data = Json::object();
                    data.set("transactions", Json(Json::Array{row}));
                    resp.set("data", data);
                } else if (path == "/operator/v1/transaction/list") {
                    if (body.at("username").as_string() == "rl_user") {
                        std::lock_guard<std::mutex> lk(hdr_mu);
                        list_traces.push_back(body.at("traceId").as_string());
                    }
                    int64_t pno = body.at("pageNo").as_int(1);
                    if (pno == 1 && body.at("username").as_string() == "rl_user" && rl_p1_calls.fetch_add(1) == 0) {
                        resp.set("status", Json("SC_RATE_LIMITED"));
                        resp.set("message", Json("slow down"));
                    } else {
                        Json r1 = Json::object(); r1.set("betId", Json("b2btkt1"));
                        Json r2 = Json::object(); r2.set("betId", Json("b2btkt2"));
                        Json r3 = Json::object(); r3.set("betId", Json("b2btkt3"));
                        Json data = Json::object();
                        data.set("transactions", Json(pno == 1 ? Json::Array{r1, r2} : Json::Array{r3}));
                        data.set("pageNo", Json(pno));
                        data.set("pageSize", Json(2));
                        data.set("total", Json(3));
                        resp.set("data", data);
                    }
                } else {
                    Json rr = Json::object();
                    rr.set("outcome", Json("BANKER"));
                    rr.set("playerPoints", Json(3));
                    rr.set("bankerPoints", Json(8));
                    Json data = Json::object();
                    data.set("betId", body.at("betId"));
                    data.set("status", Json(1));
                    data.set("roundResult", rr);
                    resp.set("data", data);
                }
            }
            std::string out_json = resp.dump();
            std::string http_resp = "HTTP/1.1 " + status_line + "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
                + std::to_string(out_json.size()) + "\r\n\r\n" + out_json;
            (void)::write(cfd, http_resp.data(), http_resp.size());
            ::close(cfd);
        }
    });

    Config cfg{api_key, secret, Environment::Production, "http://127.0.0.1:" + std::to_string(port), 5000};
    Client client(cfg);

    Json tbl_req = Json::object();
    tbl_req.set("currency", Json("USD"));
    Json tbl_res = client.list_tables(tbl_req);
    require_eq(tbl_res.at("data").at("tables").as_array()[0].at("tableId").as_string(), "T-A2", "s2s:tables");

    Json url_req = Json::object();
    url_req.set("username", Json("player_9527"));
    url_req.set("tableId", Json("T-A2"));
    url_req.set("platform", Json("H5"));
    url_req.set("currency", Json("USD"));
    url_req.set("lobbyUrl", Json("https://merchant.example.com/lobby"));
    url_req.set("ipAddress", Json("203.0.113.42"));
    Json url_res = client.create_game_url(url_req);
    require_true(url_res.at("data").at("token").as_string().rfind("b2bt_", 0) == 0, "s2s:url");

    url_req.set("currency", Json("JPY"));
    bool caught_api = false;
    try {
        client.create_game_url(url_req);
    } catch (const ApiError& e) {
        caught_api = (e.status == "SC_WRONG_CURRENCY" && !e.is_retryable());
    }
    require_true(caught_api, "s2s:wrongCurrency");

    auto all_tx = client.list_all_transactions(1000, 2000, 2);
    require_true(all_tx.size() == 3, "s2s:txAll");

    Json det_req = Json::object();
    det_req.set("betId", Json("b2btkt1"));
    det_req.set("fromTime", Json(static_cast<int64_t>(1000)));
    det_req.set("toTime", Json(static_cast<int64_t>(2000)));
    Json det_res = client.get_transaction_detail(det_req);
    require_eq(det_res.at("data").at("roundResult").at("outcome").as_string(), "BANKER", "s2s:detail");

    Json ps_ok_req = Json::object();
    ps_ok_req.set("username", Json("capped_user"));
    ps_ok_req.set("action", Json("SET"));
    ps_ok_req.set("bettingEnabled", Json(true));
    ps_ok_req.set("resetPnlWindow", Json(true));
    Json ps_ok_res = client.update_player_status(ps_ok_req);
    require_true(ps_ok_res.at("data").at("bettingEnabled").as_bool(false), "s2s:playerStatusReset");

    bool caught_403 = false;
    try {
        Json ps_lock = Json::object();
        ps_lock.set("username", Json("locked_user"));
        ps_lock.set("action", Json("SET"));
        ps_lock.set("status", Json("ACTIVE"));
        client.update_player_status(ps_lock);
    } catch (const ApiError& e) {
        caught_403 = (e.http_status == 403 && e.status == "SC_USER_DISABLED" && std::string(e.what()) == "PLATFORM_RISK_LOCKED" && !e.is_retryable());
    }
    require_true(caught_403, "s2s:playerStatus403");

    bool caught_409 = false;
    try {
        Json ps_cap = Json::object();
        ps_cap.set("username", Json("capped_user"));
        ps_cap.set("action", Json("SET"));
        ps_cap.set("bettingEnabled", Json(true));
        client.update_player_status(ps_cap);
    } catch (const ApiError& e) {
        caught_409 = (e.http_status == 409 && e.status == "SC_INVALID_REQUEST" && std::string(e.what()) == "PNL_CAP_BREACHED_RESET_REQUIRED" && !e.is_retryable());
    }
    require_true(caught_409, "s2s:playerStatus409");

    Json wts_req = Json::object();
    wts_req.set("username", Json("player_9527"));
    wts_req.set("fromTime", Json(static_cast<int64_t>(0)));
    wts_req.set("toTime", Json(static_cast<int64_t>(86400000)));
    Json wts_res = client.get_wallet_transaction_status(wts_req);
    require_eq(wts_res.at("data").at("transactions").as_array()[0].at("username").as_string(), "player_9527", "s2s:walletStatusByUser");

    auto expect_invalid_arg = [&](auto fn, const std::string& label) {
        bool threw = false;
        try {
            fn();
        } catch (const SdkError& e) {
            threw = (e.code == "INVALID_ARGUMENT");
        }
        require_true(threw, label);
    };
    expect_invalid_arg([&] { client.get_wallet_transaction_status(Json::object()); }, "s2s:wtsEmpty");
    expect_invalid_arg([&] {
        Json p = Json::object(); p.set("username", Json("player_9527"));
        client.get_wallet_transaction_status(p);
    }, "s2s:wtsUserNoWindow");
    expect_invalid_arg([&] {
        Json p = Json::object(); p.set("username", Json("player_9527")); p.set("fromTime", Json(static_cast<int64_t>(0))); p.set("toTime", Json(static_cast<int64_t>(86400001)));
        client.get_wallet_transaction_status(p);
    }, "s2s:wtsUserOver24h");
    expect_invalid_arg([&] {
        Json p = Json::object(); p.set("transactionId", Json("bet_1")); p.set("fromTime", Json(static_cast<int64_t>(1000)));
        client.get_wallet_transaction_status(p);
    }, "s2s:wtsPartialWindow");
    expect_invalid_arg([&] {
        Json p = Json::object(); p.set("betId", Json("b2btkt1")); p.set("fromTime", Json(static_cast<int64_t>(2000))); p.set("toTime", Json(static_cast<int64_t>(1000)));
        client.get_wallet_transaction_status(p);
    }, "s2s:wtsInvertedWindow");
    expect_invalid_arg([&] {
        Json p = Json::object(); p.set("transactionId", Json("bet_1")); p.set("fromTime", Json(nullptr));
        client.get_wallet_transaction_status(p);
    }, "s2s:wtsNullFrom");
    expect_invalid_arg([&] {
        Json p = Json::object(); p.set("fromTime", Json(nullptr));
        client.list_unsettled_transactions(p);
    }, "s2s:unsettledNullFrom");

    // Regressions: send_timestamp X-Timestamp, non-JSON & JSON missing-status 429/503 (M1),
    // 16 MiB overflow non-retryable (m2), list_all_transactions backoff + filters + traceId stripping (m1)
    Config ts_cfg{api_key, secret, Environment::Production, "http://127.0.0.1:" + std::to_string(port), 5000, true};
    Client ts_client(ts_cfg);
    bool caught_429 = false;
    try {
        ts_client.ping();
    } catch (const ApiError& e) {
        caught_429 = (e.http_status == 429 && e.status == StatusCode::SC_RATE_LIMITED && e.is_retryable());
    }
    require_true(caught_429, "s2s:nonJson429");
    {
        std::lock_guard<std::mutex> lk(hdr_mu);
        require_true(last_ts_hdr.size() >= 13, "s2s:xTimestamp");
    }

    // M1: JSON 429 & 503 with missing status field
    bool caught_m1_429 = false;
    try {
        Json p = Json::object(); p.set("traceId", Json("m1_json_429"));
        ts_client.ping(p);
    } catch (const ApiError& e) {
        caught_m1_429 = (e.http_status == 429 && e.status == StatusCode::SC_RATE_LIMITED && e.is_retryable());
    }
    require_true(caught_m1_429, "s2s:m1Json429");

    bool caught_m1_503 = false;
    try {
        Json p = Json::object(); p.set("traceId", Json("m1_json_503"));
        ts_client.ping(p);
    } catch (const ApiError& e) {
        caught_m1_503 = (e.http_status == 503 && e.status == StatusCode::SC_OPERATOR_TIMEOUT && e.is_retryable());
    }
    require_true(caught_m1_503, "s2s:m1Json503");

    // m2 & P2-4: >16 MiB response throws non-retryable ApiError(SC_INVALID_REQUEST, http_status, trace_id)
    bool caught_m2_overflow = false;
    try {
        Json p = Json::object(); p.set("traceId", Json("m2_overflow"));
        ts_client.ping(p);
    } catch (const ApiError& e) {
        caught_m2_overflow = (e.status == StatusCode::SC_INVALID_REQUEST
            && e.code == StatusCode::SC_INVALID_REQUEST
            && e.trace_id == "m2_overflow"
            && e.http_status == 200
            && !e.is_retryable());
    }
    require_true(caught_m2_overflow, "s2s:m2OverflowNonRetryable");

    // m1: caller-supplied traceId in filters is stripped so every page & retry gets a fresh unique UUID
    Json rl_filters = Json::object();
    rl_filters.set("username", Json("rl_user"));
    rl_filters.set("traceId", Json("caller-fixed-trace"));
    auto retried_tx = ts_client.list_all_transactions(1000, 2000, 2, rl_filters, 3, 0);
    require_true(retried_tx.size() == 3 && rl_p1_calls.load() == 2, "s2s:listAllRateLimitRetry");
    {
        std::lock_guard<std::mutex> lk(hdr_mu);
        require_true(list_traces.size() == 3, "s2s:m1TraceCount");
        std::set<std::string> uniq(list_traces.begin(), list_traces.end());
        require_true(uniq.size() == 3, "s2s:m1UniqueTraces");
        require_true(uniq.count("caller-fixed-trace") == 0, "s2s:m1StrippedCallerTrace");
    }

    stop_srv.store(true);
    ::shutdown(srv_fd, SHUT_RDWR);
    ::close(srv_fd);
    server_thread.join();

    // 5. WebhookDispatcher & InMemoryWallet lifecycle
    std::string tok = "b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819";
    InMemoryWallet wallet;
    wallet.add_account("player_9527", "USD", "1000.00", 2, {tok});
    Config sb_cfg{api_key, secret, Environment::Sandbox, "", 5000};
    WebhookDispatcher disp(sb_cfg, wallet);

    auto send_wb = [&](const std::string& route, const Json& payload) -> Json {
        std::string raw = payload.dump();
        return disp.handle(route, api_key, sign_body(raw, secret), raw);
    };

    Json bal_req = Json::object();
    bal_req.set("traceId", Json("t1"));
    bal_req.set("username", Json("player_9527"));
    bal_req.set("currency", Json("USD"));
    bal_req.set("token", Json(tok));
    require_eq(send_wb("/wallet/balance", bal_req).at("data").at("balance").as_string(), "1000.00", "wb:bal");
    require_eq(send_wb("/wallet/bet", bet.at("initial")).at("data").at("balance").as_string(), "900.00", "wb:bet");
    require_eq(send_wb("/wallet/bet", bet.at("retrySameBusiness")).at("data").at("balance").as_string(), "900.00", "wb:betReplay");
    require_eq(send_wb("/wallet/bet", bet.at("conflictDifferentAmount")).at("status").as_string(), "SC_TRANSACTION_DUPLICATED", "wb:betConflict");

    wallet.set_disabled("player_9527", true);
    require_eq(send_wb("/wallet/bet_result", stl.at("initial")).at("data").at("balance").as_string(), "1100.00", "wb:settle");
    require_eq(send_wb("/wallet/adjustment", adj.at("initial")).at("data").at("balance").as_string(), "1120.00", "wb:adjCredit");
    require_eq(send_wb("/wallet/adjustment", adj.at("retrySameBusiness")).at("data").at("balance").as_string(), "1120.00", "wb:adjReplay");
    require_eq(send_wb("/wallet/adjustment", adj.at("conflictDifferentDirection")).at("status").as_string(), "SC_TRANSACTION_DUPLICATED", "wb:adjConflict");
    Json debit_adj = adj.at("initial");
    debit_adj.set("transactionId", Json("adj_debit_cpp"));
    debit_adj.set("direction", Json("DEBIT"));
    require_eq(send_wb("/wallet/adjustment", debit_adj).at("data").at("balance").as_string(), "1100.00", "wb:adjDebit");

    Json unknown_rb = rb.at("initial");
    unknown_rb.set("transactionId", Json("rb_b2btkt000000000000000000000000"));
    unknown_rb.set("betId", Json("b2btkt000000000000000000000000"));
    unknown_rb.set("externalTransactionId", Json("b2btkt000000000000000000000000"));
    require_eq(send_wb("/wallet/rollback", unknown_rb).at("status").as_string(), "SC_TRANSACTION_NOT_EXISTS", "wb:emptyRb");

    // 6. CR-01..CR-10 adversarial regressions:
    // Pre-auth deep nesting rejected without stack overflow; signed >64 depth rejected; surrogate validation; rollback after settle rejected
    require_eq(disp.handle("/wallet/bet", "bad", "bad", std::string(50000, '[')).at("status").as_string(), "SC_AUTHENTICATION_FAILED", "wb:preAuthDeep");
    std::string deep_signed = "{\"a\":" + std::string(80, '[') + std::string(80, ']') + "}";
    require_eq(disp.handle("/wallet/bet", api_key, sign_body(deep_signed, secret), deep_signed).at("status").as_string(), "SC_INVALID_REQUEST", "wb:maxDepth64");
    require_eq(send_wb("/wallet/rollback", rb.at("initial")).at("status").as_string(), "SC_TRANSACTION_DUPLICATED", "wb:rbAfterSettle");

    wallet.set_disabled("player_9527", false);
    Json bad_bet = bet.at("initial");
    bad_bet.set("transactionId", Json("bet_bad_cpp"));
    bad_bet.set("betId", Json("b2btkt_bad_cpp"));
    bad_bet.set("amount", Json("invalid_decimal"));
    require_eq(send_wb("/wallet/bet", bad_bet).at("status").as_string(), "SC_INVALID_REQUEST", "wb:badDecimalCaught");

    bool bad_surr = false;
    try { Json::parse("{\"x\":\"\\uD83D\\u0041\"}"); } catch (const std::exception&) { bad_surr = true; }
    require_true(bad_surr, "json:badSurrogatePair");
    require_eq(Json::parse("{\"x\":\"\\uD83C\\uDFB2\"}").at("x").as_string(), "\xF0\x9F\x8E\xB2", "json:goodSurrogatePair");

    WebhookDispatcher cred_disp(api_key, secret, wallet);
    std::string bal_raw = bal_req.dump();
    require_eq(cred_disp.handle("/wallet/balance", api_key, sign_body(bal_raw, secret), bal_raw).at("status").as_string(), "SC_OK", "wb:credCtor");

    // m9: duplicate JSON object keys follow last-key-wins
    Json dup = Json::parse(R"({"k":"first","k":"second","nested":{"x":1,"x":2}})");
    require_eq(dup.at("k").as_string(), "second", "json:m9DupKeyLastWins");
    require_true(dup.at("nested").at("x").as_int() == 2, "json:m9NestedDupKeyLastWins");

    // m10: UTF-8 multi-byte traceId > 128 bytes/chars truncates cleanly on character boundary
    std::string utf8_trace;
    for (int i = 0; i < 140; ++i) utf8_trace += "\xE4\xB8\xAD"; // '中' (3 UTF-8 bytes)
    Json utf8_req = Json::object();
    utf8_req.set("traceId", Json(utf8_trace));
    std::string utf8_raw = utf8_req.dump();
    Json utf8_res = cred_disp.handle("/wallet/unknown", api_key, sign_body(utf8_raw, secret), utf8_raw);
    std::string expected_trunc;
    for (int i = 0; i < 128; ++i) expected_trunc += "\xE4\xB8\xAD";
    require_eq(utf8_res.at("status").as_string(), StatusCode::SC_INVALID_REQUEST, "wb:m10Utf8Status");
    require_eq(utf8_res.at("traceId").as_string(), expected_trunc, "wb:m10Utf8Truncated128Chars");

    // 7. v1.5.11 regressions: deadlock, S2S ApiError/TransportError/overflow & allowlist SdkError safety, wallet_ok/wallet_error guards, strict JSON ws trace hint, locale-independent JSON float, strict UTF-8
    class DeadlockWallet final : public WalletHandler {
    public:
        Json on_balance(const Json&) override { throw SdkError(StatusCode::SC_INSUFFICIENT_FUNDS, "explicit sdk err"); }
        Json on_bet(const Json& req) override {
            std::string amt = req.at("amount").as_string();
            (void)decimal_to_ledger_units(amt, 2, false);
            return wallet_ok(req.at("traceId").as_string(), "p1", "USD", "100.00");
        }
        Json on_bet_result(const Json& req) override {
            std::string mode = req.at("mode").as_string();
            if (mode == "bad_balance") {
                return wallet_ok(req.at("traceId").as_string(), "p1", "USD", "-1.00");
            }
            if (mode == "nan_balance") {
                return wallet_ok(req.at("traceId").as_string(), "p1", "USD", "NaN");
            }
            if (mode == "s2s_api_err") {
                throw ApiError(StatusCode::SC_INVALID_REQUEST, "upstream S2S failure secret detail", "t_upstream_s2s", 400);
            }
            if (mode == "s2s_overflow_err") {
                throw ApiError(StatusCode::SC_INVALID_REQUEST, "Gateway response exceeded 16 MiB limit", "t_upstream_overflow", 200);
            }
            if (mode == "s2s_transport_err") {
                throw TransportError("curl failed: 10.0.1.5:8443 proxy refused");
            }
            if (mode == "sdk_sc_ok") {
                throw SdkError(StatusCode::SC_OK, "bogus SC_OK error");
            }
            if (mode == "sdk_sc_custom") {
                throw SdkError("SC_CUSTOM", "bogus custom error");
            }
            if (mode == "sdk_sc_prefix") {
                throw SdkError("SC_", "bogus prefix error");
            }
            throw std::runtime_error("ERROR: deadlock detected (40P01) on table wallets");
        }
        Json on_rollback(const Json& req) override { return wallet_ok(req.at("traceId").as_string(), "p1", "USD", "100.00"); }
    };
    DeadlockWallet dl_wallet;
    WebhookDispatcher dl_disp(api_key, secret, dl_wallet);
    std::string dl_raw = R"({"traceId":"t_cpp_dl","transactionId":"stl_1"})";
    Json dl_res = dl_disp.handle("/wallet/bet_result", api_key, sign_body(dl_raw, secret), dl_raw);
    require_eq(dl_res.at("traceId").as_string(), "t_cpp_dl", "wb:deadlockTraceId");
    require_eq(dl_res.at("status").as_string(), StatusCode::SC_OPERATOR_TIMEOUT, "wb:deadlockTimeoutStatus");
    require_eq(dl_res.at("message").as_string(), "Temporary wallet handler error", "wb:deadlockSanitizedMsg");
    require_true(dl_res.at("message").as_string().find("40P01") == std::string::npos, "wb:deadlockNoLeak");

    for (const std::string& mode : std::vector<std::string>{"bad_balance", "nan_balance", "s2s_api_err", "s2s_overflow_err", "s2s_transport_err", "sdk_sc_ok", "sdk_sc_custom", "sdk_sc_prefix"}) {
        std::string bb_raw = R"({"traceId":"t_cpp_)" + mode + R"(","mode":")" + mode + R"("})";
        Json bb_res = dl_disp.handle("/wallet/bet_result", api_key, sign_body(bb_raw, secret), bb_raw);
        require_eq(bb_res.at("traceId").as_string(), "t_cpp_" + mode, "wb:internalSdkErrTrace:" + mode);
        require_eq(bb_res.at("status").as_string(), StatusCode::SC_OPERATOR_TIMEOUT, "wb:internalSdkErrStatus:" + mode);
        require_eq(bb_res.at("message").as_string(), "Temporary wallet handler error", "wb:internalSdkErrMsg:" + mode);
        require_true(bb_res.at("message").as_string().find("wallet_ok") == std::string::npos, "wb:internalSdkErrNoLeak:" + mode);
        require_true(bb_res.at("message").as_string().find("upstream") == std::string::npos, "wb:internalSdkErrNoS2sLeak:" + mode);
        require_true(bb_res.at("message").as_string().find("10.0.1.5") == std::string::npos, "wb:internalSdkErrNoTransportLeak:" + mode);
        require_true(bb_res.at("message").as_string().find("16 MiB") == std::string::npos, "wb:internalSdkErrNoOverflowLeak:" + mode);
        require_true(bb_res.at("message").as_string().find("bogus") == std::string::npos, "wb:internalSdkErrNoBogusLeak:" + mode);
    }

    for (const std::string& bad_amt : std::vector<std::string>{"not_a_number", "1.123456", "-5.00"}) {
        std::string bd_raw = R"({"traceId":"t_cpp_bad_dec","amount":")" + bad_amt + R"("})";
        Json bd_res = dl_disp.handle("/wallet/bet", api_key, sign_body(bd_raw, secret), bd_raw);
        require_eq(bd_res.at("status").as_string(), StatusCode::SC_INVALID_REQUEST, "wb:incomingDecInvalidReq:" + bad_amt);
    }

    Json sdk_err_res = dl_disp.handle("/wallet/balance", api_key, sign_body(dl_raw, secret), dl_raw);
    require_eq(sdk_err_res.at("status").as_string(), StatusCode::SC_INSUFFICIENT_FUNDS, "wb:sdkErrPreserved");

    // Strict JSON whitespace in extract_trace_hint on auth failure
    Json bad_hint_res = dl_disp.handle("/wallet/bet", "bad_key", "bad_sig", R"({"traceId": 123, "username": "alice"})");
    require_eq(bad_hint_res.at("status").as_string(), StatusCode::SC_AUTHENTICATION_FAILED, "wb:badHintStatus");
    require_eq(bad_hint_res.at("traceId").as_string(), "", "wb:badHintNumericTraceIdEmpty");
    Json fake_key_res = dl_disp.handle("/wallet/bet", "bad_key", "bad_sig", R"({"a": "traceId", "b": "evil"})");
    require_eq(fake_key_res.at("status").as_string(), StatusCode::SC_AUTHENTICATION_FAILED, "wb:fakeKeyStatus");
    require_eq(fake_key_res.at("traceId").as_string(), "", "wb:fakeKeyValueTraceIdEmpty");
    Json real_after_fake = dl_disp.handle("/wallet/bet", "bad_key", "bad_sig", R"({"a": "traceId", "traceId": "t_real_1"})");
    require_eq(real_after_fake.at("traceId").as_string(), "t_real_1", "wb:realAfterFakeTraceId");

    Json ok_env = wallet_ok("t_ok", "player_1", "JPY", "0");
    require_eq(ok_env.at("status").as_string(), StatusCode::SC_OK, "wallet_ok:status");
    require_eq(ok_env.at("data").at("balance").as_string(), "0", "wallet_ok:balance");
    require_true(ok_env.at("data").at("timestamp").as_int() > 0, "wallet_ok:timestamp");
    Json err_env = wallet_error("t_err", StatusCode::SC_USER_DISABLED, "disabled");
    require_eq(err_env.at("status").as_string(), StatusCode::SC_USER_DISABLED, "wallet_error:status");
    require_eq(err_env.at("message").as_string(), "disabled", "wallet_error:message");

    for (const std::string& bad_bal : std::vector<std::string>{"", "   ", "-1.00", "abc", "10.", ".5", "10.00 "}) {
        bool threw = false;
        try {
            (void)wallet_ok("t_bad", "player_1", "USD", bad_bal);
        } catch (const SdkError& e) {
            threw = (e.code == "INVALID_ARGUMENT");
        }
        require_true(threw, "wallet_ok:rejectBadBalance:" + bad_bal);
    }
    for (const std::string& bad_st : std::vector<std::string>{"", "   ", StatusCode::SC_OK, " SC_OK ", "sc_ok", "Sc_Ok", " sc_ok ", "SC_", "SC_TIMEOUT", "SC_CUSTOM", "INSUFFICIENT_FUNDS"}) {
        bool threw = false;
        try {
            (void)wallet_error("t_bad", bad_st, "oops");
        } catch (const SdkError& e) {
            threw = (e.code == "INVALID_ARGUMENT");
        }
        require_true(threw, "wallet_error:rejectBadStatus:" + bad_st);
    }

    std::string dbl_json = Json(12.34).dump();
    require_true(dbl_json.find('.') != std::string::npos && dbl_json.find(',') == std::string::npos, "json:classicLocaleDump");
    Json parsed_dbl = Json::parse(R"({"v":12.34})");
    require_true(parsed_dbl.at("v").type() == Json::Type::Double, "json:classicLocaleParse");

    // v1.5.11 P3-2: strict UTF-8 validation in WebhookDispatcher
    std::string bad_utf8 = std::string("{\"traceId\":\"t1") + "\xff" + "\",\"username\":\"alice\"}";
    Json bad_utf8_res = dl_disp.handle("/wallet/balance", api_key, sign_body(bad_utf8, secret), bad_utf8);
    require_eq(bad_utf8_res.at("status").as_string(), StatusCode::SC_INVALID_REQUEST, "wb:p32InvalidUtf8Status");
    require_eq(bad_utf8_res.at("traceId").as_string(), "", "wb:p32InvalidUtf8TraceEmpty");

    std::cout << "C++17 SDK: ALL TESTS PASSED\n";
    return 0;
}

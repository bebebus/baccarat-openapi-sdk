// SPDX-License-Identifier: MIT
#include "baccarat/sdk.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
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
                }
            }

            std::string st = verify_webhook_headers(x_key, x_sig, raw_body, api_key, secret);
            Json body = Json::parse(raw_body);
            Json resp = Json::object();
            resp.set("traceId", body.at("traceId"));
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
                } else if (path == "/operator/v1/transaction/list") {
                    int64_t pno = body.at("pageNo").as_int(1);
                    Json r1 = Json::object(); r1.set("betId", Json("b2btkt1"));
                    Json r2 = Json::object(); r2.set("betId", Json("b2btkt2"));
                    Json r3 = Json::object(); r3.set("betId", Json("b2btkt3"));
                    Json data = Json::object();
                    data.set("transactions", Json(pno == 1 ? Json::Array{r1, r2} : Json::Array{r3}));
                    data.set("pageNo", Json(pno));
                    data.set("pageSize", Json(2));
                    data.set("total", Json(3));
                    resp.set("data", data);
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
            std::string http_resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: "
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

    std::cout << "C++17 SDK: ALL TESTS PASSED\n";
    return 0;
}

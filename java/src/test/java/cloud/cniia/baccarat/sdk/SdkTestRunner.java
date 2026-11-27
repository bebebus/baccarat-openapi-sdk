// SPDX-License-Identifier: MIT
package cloud.cniia.baccarat.sdk;

import com.sun.net.httpserver.HttpServer;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class SdkTestRunner {
    private static void check(boolean cond, String msg) {
        if (!cond) throw new AssertionError("FAIL: " + msg);
    }

    private static void checkEq(Object actual, Object expected, String msg) {
        if (!Objects.equals(actual, expected)) {
            throw new AssertionError("FAIL [" + msg + "]: expected <" + expected + "> but got <" + actual + ">");
        }
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        String rawJson = Files.readString(Path.of("../test-vectors.json"), StandardCharsets.UTF_8);
        Map<String, Object> doc = JsonCodec.parseObject(rawJson);

        // 1. HMAC & header vectors
        for (Object item : (List<Object>) doc.get("hmacVectors")) {
            Map<String, Object> v = (Map<String, Object>) item;
            String name = (String) v.get("name");
            String body = (String) v.get("rawBody");
            String secret = (String) v.get("secret");
            String sig = (String) v.get("signature");
            checkEq(body.getBytes(StandardCharsets.UTF_8).length, ((Number) v.get("utf8ByteLength")).intValue(), name + ":len");
            checkEq(BaccaratSdk.signBody(body, secret), sig, name + ":sign");
            check(BaccaratSdk.verifySignature(body.getBytes(StandardCharsets.UTF_8), sig, secret), name + ":verify");
            if (v.containsKey("wrongBase64DecodedSignature")) {
                check(!BaccaratSdk.verifySignature(
                        body.getBytes(StandardCharsets.UTF_8),
                        (String) v.get("wrongBase64DecodedSignature"),
                        secret
                ), name + ":wrongB64");
            }
        }

        for (Object item : (List<Object>) doc.get("headerVerificationVectors")) {
            Map<String, Object> h = (Map<String, Object>) item;
            String actual = BaccaratSdk.verifyWebhookHeaders(
                    (String) h.get("apiKeyHeader"),
                    (String) h.get("signatureHeader"),
                    ((String) h.get("rawBody")).getBytes(StandardCharsets.UTF_8),
                    (String) h.get("expectedApiKey"),
                    (String) h.get("hmacSecret")
            );
            checkEq(actual, h.get("expectedStatus"), (String) h.get("name"));
        }

        // 2. Idempotency vectors
        Map<String, Object> idem = (Map<String, Object>) doc.get("idempotencyVectors");
        Map<String, Object> bet = (Map<String, Object>) idem.get("bet");
        checkEq(BaccaratSdk.betFingerprint((Map<String, Object>) bet.get("initial")), bet.get("expectedFingerprint"), "bet:init");
        checkEq(BaccaratSdk.betFingerprint((Map<String, Object>) bet.get("retrySameBusiness")), bet.get("expectedFingerprint"), "bet:retry");
        checkEq(BaccaratSdk.betFingerprint((Map<String, Object>) bet.get("conflictDifferentAmount")), bet.get("conflictFingerprint"), "bet:conflict");

        Map<String, Object> stl = (Map<String, Object>) idem.get("betResult");
        checkEq(BaccaratSdk.betResultFingerprint((Map<String, Object>) stl.get("initial")), stl.get("expectedFingerprint"), "stl:init");
        checkEq(BaccaratSdk.betResultFingerprint((Map<String, Object>) stl.get("retrySameBusiness")), stl.get("expectedFingerprint"), "stl:retry");
        checkEq(BaccaratSdk.betResultFingerprint((Map<String, Object>) stl.get("conflictDifferentWinAmount")), stl.get("conflictFingerprint"), "stl:conflict");

        Map<String, Object> rb = (Map<String, Object>) idem.get("rollback");
        checkEq(BaccaratSdk.rollbackFingerprint((Map<String, Object>) rb.get("initial")), rb.get("expectedFingerprint"), "rb:init");
        checkEq(BaccaratSdk.rollbackFingerprint((Map<String, Object>) rb.get("retrySameBusiness")), rb.get("expectedFingerprint"), "rb:retry");
        checkEq(BaccaratSdk.rollbackFingerprint((Map<String, Object>) rb.get("conflictDifferentAmount")), rb.get("conflictFingerprint"), "rb:conflict");

        Map<String, Object> adj = (Map<String, Object>) idem.get("adjustment");
        checkEq(BaccaratSdk.adjustmentFingerprint((Map<String, Object>) adj.get("initial")), adj.get("expectedFingerprint"), "adj:init");
        checkEq(BaccaratSdk.adjustmentFingerprint((Map<String, Object>) adj.get("retrySameBusiness")), adj.get("expectedFingerprint"), "adj:retry");
        checkEq(BaccaratSdk.adjustmentFingerprint((Map<String, Object>) adj.get("conflictDifferentDirection")), adj.get("conflictFingerprint"), "adj:conflict");

        // 3. Money & status vectors
        Map<String, Object> money = (Map<String, Object>) doc.get("moneyVectors");
        for (Object item : (List<Object>) money.get("valid")) {
            Map<String, Object> m = (Map<String, Object>) item;
            int exp = ((Number) m.get("displayExponent")).intValue();
            BigInteger units = BaccaratSdk.decimalToLedgerUnits((String) m.get("raw"), exp, (Boolean) m.get("allowNegative"));
            checkEq(units.toString(), m.get("expectedUnits"), m.get("name") + ":units");
            checkEq(BaccaratSdk.ledgerUnitsToDecimal(units, exp), m.get("expectedFormatted"), m.get("name") + ":fmt");
        }
        for (Object item : (List<Object>) money.get("invalid")) {
            Map<String, Object> inv = (Map<String, Object>) item;
            boolean threw = false;
            try {
                BaccaratSdk.decimalToLedgerUnits((String) inv.get("raw"), ((Number) inv.get("displayExponent")).intValue(), (Boolean) inv.get("allowNegative"));
            } catch (BaccaratSdk.SdkException e) {
                threw = true;
            }
            check(threw, "money:invalid:" + inv.get("name"));
        }
        for (Object item : (List<Object>) doc.get("statusCodes")) {
            Map<String, Object> sc = (Map<String, Object>) item;
            checkEq(BaccaratSdk.StatusCode.isRetryable((String) sc.get("code")), sc.get("retryable"), "sc:" + sc.get("code"));
        }

        // 4. Loopback HTTP Server S2S Client + WebhookDispatcher
        String apiKey = "ak_0123456789abcdef0123456789abcdef";
        String secret = "dGVzdF9zZWNyZXRfNDBfY2hhcnNfYmFzZTY0dXJsX2s";

        HttpServer srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        srv.createContext("/operator/v1/", ex -> {
            byte[] reqBytes = ex.getRequestBody().readAllBytes();
            String st = BaccaratSdk.verifyWebhookHeaders(
                    ex.getRequestHeaders().getFirst("X-API-Key"),
                    ex.getRequestHeaders().getFirst("X-Signature"),
                    reqBytes, apiKey, secret
            );
            Map<String, Object> body = JsonCodec.parseObject(new String(reqBytes, StandardCharsets.UTF_8));
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("traceId", body.get("traceId"));
            if (!BaccaratSdk.StatusCode.SC_OK.equals(st)) {
                resp.put("status", st);
                resp.put("message", "auth failed");
            } else {
                String path = ex.getRequestURI().getPath();
                resp.put("status", "SC_OK");
                if ("/operator/v1/game/tables".equals(path)) {
                    resp.put("data", Map.of("tables", List.of(Map.of("tableId", "T-A2", "currency", "USD")), "pageNo", 1, "pageSize", 50, "total", 1));
                } else if ("/operator/v1/game/url".equals(path)) {
                    if (!"USD".equals(body.get("currency"))) {
                        resp.put("status", "SC_WRONG_CURRENCY");
                        resp.put("message", "USD required");
                    } else {
                        String tok = "b2bt_" + "e".repeat(48);
                        resp.put("data", Map.of("gameUrl", "https://play.lt.cniia.cloud/?token=" + tok, "token", tok));
                    }
                } else if ("/operator/v1/game/terminate".equals(path)) {
                    resp.put("data", Map.of("username", body.get("username"), "terminatedSessions", 1, "revokedLaunchTokens", 0));
                } else if ("/operator/v1/player/status".equals(path)) {
                    if ("locked_user".equals(body.get("username"))) {
                        resp.put("status", "SC_USER_DISABLED");
                        resp.put("message", "PLATFORM_RISK_LOCKED");
                        byte[] out = JsonCodec.stringify(resp).getBytes(StandardCharsets.UTF_8);
                        ex.getResponseHeaders().set("Content-Type", "application/json");
                        ex.sendResponseHeaders(403, out.length);
                        ex.getResponseBody().write(out);
                        ex.close();
                        return;
                    }
                    if ("capped_user".equals(body.get("username")) && Boolean.TRUE.equals(body.get("bettingEnabled")) && !Boolean.TRUE.equals(body.get("resetPnlWindow"))) {
                        resp.put("status", "SC_INVALID_REQUEST");
                        resp.put("message", "PNL_CAP_BREACHED_RESET_REQUIRED");
                        byte[] out = JsonCodec.stringify(resp).getBytes(StandardCharsets.UTF_8);
                        ex.getResponseHeaders().set("Content-Type", "application/json");
                        ex.sendResponseHeaders(409, out.length);
                        ex.getResponseBody().write(out);
                        ex.close();
                        return;
                    }
                    resp.put("data", Map.of("username", body.get("username"), "status", "ACTIVE", "bettingEnabled", true, "rgRestricted", false, "revokedSessions", 0, "revokedLaunchTokens", 0));
                } else if ("/operator/v1/wallet/transaction-status".equals(path)) {
                    resp.put("data", Map.of("transactions", List.of(Map.of("transactionId", "bet_java_1", "username", String.valueOf(body.get("username")), "status", "COMPLETED"))));
                } else if ("/operator/v1/transaction/list".equals(path)) {
                    int pNo = ((Number) body.get("pageNo")).intValue();
                    List<Map<String, Object>> rows = pNo == 1 ? List.of(Map.of("betId", "b2btkt1"), Map.of("betId", "b2btkt2")) : List.of(Map.of("betId", "b2btkt3"));
                    resp.put("data", Map.of("transactions", rows, "pageNo", pNo, "pageSize", 2, "total", 3));
                } else {
                    resp.put("data", Map.of("betId", body.get("betId"), "status", 1, "roundResult", Map.of("outcome", "PLAYER", "playerPoints", 8, "bankerPoints", 5)));
                }
            }
            byte[] out = JsonCodec.stringify(resp).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        srv.start();
        try {
            int port = srv.getAddress().getPort();
            BaccaratSdk.Config cfg = new BaccaratSdk.Config(apiKey, secret, BaccaratSdk.Environment.PRODUCTION, "http://127.0.0.1:" + port, 5000);
            BaccaratSdk.Client client = new BaccaratSdk.Client(cfg);

            Map<String, Object> tablesData = (Map<String, Object>) client.listTables(Map.of("currency", "USD")).get("data");
            checkEq(((List<Map<String, Object>>) tablesData.get("tables")).get(0).get("tableId"), "T-A2", "s2s:tables");

            Map<String, Object> urlData = (Map<String, Object>) client.createGameUrl(Map.of(
                    "username", "player_9527", "tableId", "T-A2", "platform", "H5",
                    "currency", "USD", "lobbyUrl", "https://merchant.example.com/lobby", "ipAddress", "203.0.113.42"
            )).get("data");
            check(((String) urlData.get("token")).startsWith("b2bt_"), "s2s:url");

            boolean caughtApi = false;
            try {
                client.createGameUrl(Map.of(
                        "username", "player_9527", "tableId", "T-A2", "platform", "H5",
                        "currency", "JPY", "lobbyUrl", "https://merchant.example.com/lobby", "ipAddress", "203.0.113.42"
                ));
            } catch (BaccaratSdk.ApiException ex) {
                caughtApi = "SC_WRONG_CURRENCY".equals(ex.status) && !ex.isRetryable();
            }
            check(caughtApi, "s2s:wrongCurrency");

            checkEq(client.listAllTransactions(1000L, 2000L, 2).size(), 3, "s2s:txAll");
            Map<String, Object> detData = (Map<String, Object>) client.getTransactionDetail(Map.of("betId", "b2btkt1", "fromTime", 1000L, "toTime", 2000L)).get("data");
            checkEq(((Map<String, Object>) detData.get("roundResult")).get("outcome"), "PLAYER", "s2s:detail");

            Map<String, Object> psData = (Map<String, Object>) client.updatePlayerStatus(Map.of("username", "capped_user", "action", "SET", "bettingEnabled", true, "resetPnlWindow", true)).get("data");
            checkEq(psData.get("bettingEnabled"), Boolean.TRUE, "s2s:playerStatusReset");
            boolean caught403 = false;
            try {
                client.updatePlayerStatus(Map.of("username", "locked_user", "action", "SET", "status", "ACTIVE"));
            } catch (BaccaratSdk.ApiException ex) {
                caught403 = ex.httpStatus == 403 && "SC_USER_DISABLED".equals(ex.status) && "PLATFORM_RISK_LOCKED".equals(ex.getMessage()) && !ex.isRetryable();
            }
            check(caught403, "s2s:playerStatus403");
            boolean caught409 = false;
            try {
                client.updatePlayerStatus(Map.of("username", "capped_user", "action", "SET", "bettingEnabled", true));
            } catch (BaccaratSdk.ApiException ex) {
                caught409 = ex.httpStatus == 409 && "SC_INVALID_REQUEST".equals(ex.status) && "PNL_CAP_BREACHED_RESET_REQUIRED".equals(ex.getMessage()) && !ex.isRetryable();
            }
            check(caught409, "s2s:playerStatus409");
            Map<String, Object> wtsData = (Map<String, Object>) client.getWalletTransactionStatus(Map.of("username", "player_9527", "fromTime", 0L, "toTime", 86_400_000L)).get("data");
            checkEq(((List<Map<String, Object>>) wtsData.get("transactions")).get(0).get("username"), "player_9527", "s2s:walletStatusByUser");

            java.util.function.BiConsumer<Runnable, String> expectInvalidArg = (fn, label) -> {
                boolean threw = false;
                try { fn.run(); } catch (BaccaratSdk.SdkException ex) { threw = "INVALID_ARGUMENT".equals(ex.code); }
                check(threw, label);
            };
            expectInvalidArg.accept(() -> client.getWalletTransactionStatus(Map.of()), "s2s:wtsEmpty");
            expectInvalidArg.accept(() -> client.getWalletTransactionStatus(Map.of("username", "player_9527")), "s2s:wtsUserNoWindow");
            expectInvalidArg.accept(() -> client.getWalletTransactionStatus(Map.of("username", "player_9527", "fromTime", 0L, "toTime", 86_400_001L)), "s2s:wtsUserOver24h");
            expectInvalidArg.accept(() -> client.getWalletTransactionStatus(Map.of("transactionId", "bet_1", "fromTime", 1000L)), "s2s:wtsPartialWindow");
            expectInvalidArg.accept(() -> client.getWalletTransactionStatus(Map.of("betId", "b2btkt1", "fromTime", 2000L, "toTime", 1000L)), "s2s:wtsInvertedWindow");
            Map<String, Object> nullFromWts = new LinkedHashMap<>();
            nullFromWts.put("transactionId", "bet_1");
            nullFromWts.put("fromTime", null);
            expectInvalidArg.accept(() -> client.getWalletTransactionStatus(nullFromWts), "s2s:wtsNullFrom");
            Map<String, Object> nullFromDet = new LinkedHashMap<>();
            nullFromDet.put("betId", "b2btkt1");
            nullFromDet.put("fromTime", null);
            expectInvalidArg.accept(() -> client.getTransactionDetail(nullFromDet), "s2s:detailNullFrom");
            expectInvalidArg.accept(() -> client.listTransactions(Map.of("fromTime", BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE), "toTime", 2000L)), "s2s:bigIntOverflow");
        } finally {
            srv.stop(0);
        }

        // Webhook lifecycle
        String tok = "b2bt_9f81c204d7e641b8a5309c17e248f6b109d3a4c5e6f70819";
        BaccaratSdk.InMemoryWallet wallet = new BaccaratSdk.InMemoryWallet();
        wallet.addAccount("player_9527", "USD", "1000.00", 2, List.of(tok));
        BaccaratSdk.Config sbCfg = new BaccaratSdk.Config(apiKey, secret, BaccaratSdk.Environment.SANDBOX, null, 5000);
        BaccaratSdk.WebhookDispatcher disp = new BaccaratSdk.WebhookDispatcher(sbCfg, wallet);

        var send = new java.util.function.BiFunction<String, Map<String, Object>, Map<String, Object>>() {
            @Override
            public Map<String, Object> apply(String route, Map<String, Object> payload) {
                byte[] raw = JsonCodec.stringify(payload).getBytes(StandardCharsets.UTF_8);
                return disp.handle(route, apiKey, BaccaratSdk.signBody(raw, secret), raw);
            }
        };

        checkEq(((Map<String, Object>) send.apply("/wallet/balance", Map.of("traceId", "t1", "username", "player_9527", "currency", "USD", "token", tok)).get("data")).get("balance"), "1000.00", "wb:bal");
        checkEq(((Map<String, Object>) send.apply("/wallet/bet", (Map<String, Object>) bet.get("initial")).get("data")).get("balance"), "900.00", "wb:bet");
        checkEq(((Map<String, Object>) send.apply("/wallet/bet", (Map<String, Object>) bet.get("retrySameBusiness")).get("data")).get("balance"), "900.00", "wb:betReplay");
        checkEq(send.apply("/wallet/bet", (Map<String, Object>) bet.get("conflictDifferentAmount")).get("status"), "SC_TRANSACTION_DUPLICATED", "wb:betConflict");

        wallet.setDisabled("player_9527", true);
        checkEq(((Map<String, Object>) send.apply("/wallet/bet_result", (Map<String, Object>) stl.get("initial")).get("data")).get("balance"), "1100.00", "wb:settle");
        checkEq(((Map<String, Object>) send.apply("/wallet/adjustment", (Map<String, Object>) adj.get("initial")).get("data")).get("balance"), "1120.00", "wb:adjCredit");
        checkEq(((Map<String, Object>) send.apply("/wallet/adjustment", (Map<String, Object>) adj.get("retrySameBusiness")).get("data")).get("balance"), "1120.00", "wb:adjReplay");
        checkEq(send.apply("/wallet/adjustment", (Map<String, Object>) adj.get("conflictDifferentDirection")).get("status"), "SC_TRANSACTION_DUPLICATED", "wb:adjConflict");
        Map<String, Object> debitAdj = new LinkedHashMap<>((Map<String, Object>) adj.get("initial"));
        debitAdj.put("transactionId", "adj_debit_java");
        debitAdj.put("direction", "DEBIT");
        checkEq(((Map<String, Object>) send.apply("/wallet/adjustment", debitAdj).get("data")).get("balance"), "1100.00", "wb:adjDebit");

        Map<String, Object> unknownRb = new LinkedHashMap<>((Map<String, Object>) rb.get("initial"));
        unknownRb.put("transactionId", "rb_b2btkt000000000000000000000000");
        unknownRb.put("betId", "b2btkt000000000000000000000000");
        unknownRb.put("externalTransactionId", "b2btkt000000000000000000000000");
        checkEq(send.apply("/wallet/rollback", unknownRb).get("status"), "SC_TRANSACTION_NOT_EXISTS", "wb:emptyRb");

        // CR-01..CR-10 adversarial regressions:
        // 1. Pre-auth 20,000-deep nested array does NOT throw StackOverflowError; signed 100-deep array returns SC_INVALID_REQUEST!
        byte[] deepBytes = "[".repeat(20_000).getBytes(StandardCharsets.UTF_8);
        checkEq(disp.handle("/wallet/bet", "bad", "bad", deepBytes).get("status"), "SC_AUTHENTICATION_FAILED", "wb:preAuthDeepNoSOE");
        byte[] signedDeep = ("{\"a\":" + "[".repeat(80) + "]".repeat(80) + "}").getBytes(StandardCharsets.UTF_8);
        checkEq(disp.handle("/wallet/bet", apiKey, BaccaratSdk.signBody(signedDeep, secret), signedDeep).get("status"), "SC_INVALID_REQUEST", "wb:maxDepth64");
        // 2. Rollback after settle rejected; malformed decimal caught cleanly as SC_INVALID_REQUEST
        checkEq(send.apply("/wallet/rollback", (Map<String, Object>) rb.get("initial")).get("status"), "SC_TRANSACTION_DUPLICATED", "wb:rbAfterSettle");
        wallet.setDisabled("player_9527", false);
        Map<String, Object> badBet = new LinkedHashMap<>((Map<String, Object>) bet.get("initial"));
        badBet.put("transactionId", "bet_bad_java");
        badBet.put("betId", "b2btkt_bad_java");
        badBet.put("amount", "bad_decimal");
        checkEq(send.apply("/wallet/bet", badBet).get("status"), "SC_INVALID_REQUEST", "wb:badDecimalCaught");
        // 3. Surrogate pair parses cleanly while lone surrogate or malformed hex escape fails
        checkEq(JsonCodec.parseObject("{\"emoji\":\"\\uD83D\\uDFB2\"}").get("emoji"), "\uD83D\uDFB2", "json:surrogatePair");
        boolean badEscThrew = false;
        try { JsonCodec.parseObject("{\"bad\":\"\\u+123\"}"); } catch (IllegalArgumentException e) { badEscThrew = true; }
        check(badEscThrew, "json:badHexSign");
        boolean loneSurrThrew = false;
        try { JsonCodec.parseObject("{\"bad\":\"\\uD800\"}"); } catch (IllegalArgumentException e) { loneSurrThrew = true; }
        check(loneSurrThrew, "json:loneSurrogate");

        // 4. Regressions: JsonCodec array serialization & ASCII digits (m7), WebhookDispatcher(apiKey, secret, wallet),
        //    sendTimestamp X-Timestamp, non-JSON & JSON missing-status 429/503 (M1), 16 MiB cap (M4),
        //    listAllTransactions rate-limit retry + filters + traceId stripping (m1)
        checkEq(JsonCodec.stringify(new String[]{"50.00", "100.00"}), "[\"50.00\",\"100.00\"]", "json:stringArray");
        checkEq(JsonCodec.stringify(new int[]{1, 2, 3}), "[1,2,3]", "json:intArray");
        boolean nonAsciiDigitThrew = false;
        try { JsonCodec.parseObject("{\"n\":1\u0660}"); } catch (IllegalArgumentException e) { nonAsciiDigitThrew = true; }
        check(nonAsciiDigitThrew, "json:m7NonAsciiDigitRejected");

        BaccaratSdk.WebhookDispatcher credDisp = new BaccaratSdk.WebhookDispatcher(apiKey, secret, wallet);
        byte[] credRaw = JsonCodec.stringify(Map.of("traceId", "t_cred", "username", "player_9527", "currency", "USD", "token", tok)).getBytes(StandardCharsets.UTF_8);
        checkEq(credDisp.handle("/wallet/balance", apiKey, BaccaratSdk.signBody(credRaw, secret), credRaw).get("status"), "SC_OK", "wb:credCtor");

        java.util.concurrent.atomic.AtomicInteger p1Count = new java.util.concurrent.atomic.AtomicInteger(0);
        java.util.concurrent.atomic.AtomicReference<String> lastTs = new java.util.concurrent.atomic.AtomicReference<>("");
        java.util.List<String> listTraces = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        HttpServer rlSrv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        rlSrv.createContext("/operator/v1/", ex -> {
            lastTs.set(ex.getRequestHeaders().getFirst("X-Timestamp"));
            byte[] reqBytes = ex.getRequestBody().readAllBytes();
            Map<String, Object> body = JsonCodec.parseObject(new String(reqBytes, StandardCharsets.UTF_8));
            String path = ex.getRequestURI().getPath();
            if ("/operator/v1/ping".equals(path)) {
                String tid = String.valueOf(body.get("traceId"));
                if ("m1_json_429".equals(tid)) {
                    byte[] out = "{\"statusCode\":429,\"message\":\"Too Many Requests\"}".getBytes(StandardCharsets.UTF_8);
                    ex.getResponseHeaders().set("Content-Type", "application/json");
                    ex.sendResponseHeaders(429, out.length);
                    ex.getResponseBody().write(out);
                    ex.close();
                    return;
                }
                if ("m1_json_503".equals(tid)) {
                    byte[] out = "{\"error\":\"unavailable\"}".getBytes(StandardCharsets.UTF_8);
                    ex.getResponseHeaders().set("Content-Type", "application/json");
                    ex.sendResponseHeaders(503, out.length);
                    ex.getResponseBody().write(out);
                    ex.close();
                    return;
                }
                if ("p2_num_429".equals(tid)) {
                    byte[] out = "{\"status\":429,\"message\":\"proxy rate limited\"}".getBytes(StandardCharsets.UTF_8);
                    ex.getResponseHeaders().set("Content-Type", "application/json");
                    ex.sendResponseHeaders(429, out.length);
                    ex.getResponseBody().write(out);
                    ex.close();
                    return;
                }
                if ("p2_num_503".equals(tid)) {
                    byte[] out = "{\"status\":503,\"traceId\":12345}".getBytes(StandardCharsets.UTF_8);
                    ex.getResponseHeaders().set("Content-Type", "application/json");
                    ex.sendResponseHeaders(503, out.length);
                    ex.getResponseBody().write(out);
                    ex.close();
                    return;
                }
                if ("m4_exact".equals(tid)) {
                    String prefix = "{\"traceId\":\"m4_exact\",\"status\":\"SC_OK\",\"data\":{\"pad\":\"";
                    String suffix = "\"}}";
                    int exactBytes = 16 * 1024 * 1024;
                    int padLen = exactBytes - prefix.length() - suffix.length();
                    ex.getResponseHeaders().set("Content-Type", "application/json");
                    ex.sendResponseHeaders(200, exactBytes);
                    byte[] chunk = new byte[65536];
                    java.util.Arrays.fill(chunk, (byte) 'a');
                    try (var os = ex.getResponseBody()) {
                        os.write(prefix.getBytes(StandardCharsets.UTF_8));
                        int remaining = padLen;
                        while (remaining > 0) {
                            int n = Math.min(remaining, chunk.length);
                            os.write(chunk, 0, n);
                            remaining -= n;
                        }
                        os.write(suffix.getBytes(StandardCharsets.UTF_8));
                    }
                    ex.close();
                    return;
                }
                if ("m4_overflow".equals(tid)) {
                    ex.getResponseHeaders().set("Content-Type", "application/json");
                    ex.sendResponseHeaders(200, 0);
                    byte[] chunk = new byte[65536];
                    java.util.Arrays.fill(chunk, (byte) 'a');
                    try (var os = ex.getResponseBody()) {
                        for (int i = 0; i < 260; i++) {
                            os.write(chunk);
                        }
                    } catch (Exception ignored) {
                    }
                    ex.close();
                    return;
                }
                byte[] out = "Too Many Requests".getBytes(StandardCharsets.UTF_8);
                ex.sendResponseHeaders(429, out.length);
                ex.getResponseBody().write(out);
                ex.close();
                return;
            }
            listTraces.add(String.valueOf(body.get("traceId")));
            int pNo = ((Number) body.get("pageNo")).intValue();
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("traceId", body.get("traceId"));
            if (pNo == 1 && p1Count.getAndIncrement() == 0) {
                resp.put("status", "SC_RATE_LIMITED");
                resp.put("message", "slow down");
            } else {
                resp.put("status", "SC_OK");
                List<Map<String, Object>> rows = pNo == 1 ? List.of(Map.of("betId", "b1"), Map.of("betId", "b2")) : List.of(Map.of("betId", "b3"));
                resp.put("data", Map.of("transactions", rows, "pageNo", pNo, "pageSize", 2, "total", 3));
            }
            byte[] out = JsonCodec.stringify(resp).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        rlSrv.start();
        try {
            BaccaratSdk.Config tsCfg = new BaccaratSdk.Config(apiKey, secret, BaccaratSdk.Environment.PRODUCTION, "http://127.0.0.1:" + rlSrv.getAddress().getPort(), 5000, true);
            BaccaratSdk.Client tsClient = new BaccaratSdk.Client(tsCfg);
            boolean caught429 = false;
            try {
                tsClient.ping(Map.of());
            } catch (BaccaratSdk.ApiException ex) {
                caught429 = ex.httpStatus == 429 && "SC_RATE_LIMITED".equals(ex.status) && ex.isRetryable();
            }
            check(caught429, "s2s:nonJson429");
            check(lastTs.get() != null && lastTs.get().matches("^\\d{13}$"), "s2s:xTimestamp");

            // M1: JSON 429 & 503 with missing status field
            boolean caughtM1429 = false;
            try {
                tsClient.ping(Map.of("traceId", "m1_json_429"));
            } catch (BaccaratSdk.ApiException ex) {
                caughtM1429 = ex.httpStatus == 429 && "SC_RATE_LIMITED".equals(ex.status) && ex.isRetryable();
            }
            check(caughtM1429, "s2s:m1Json429");

            boolean caughtM1503 = false;
            try {
                tsClient.ping(Map.of("traceId", "m1_json_503"));
            } catch (BaccaratSdk.ApiException ex) {
                caughtM1503 = ex.httpStatus == 503 && "SC_OPERATOR_TIMEOUT".equals(ex.status) && ex.isRetryable();
            }
            check(caughtM1503, "s2s:m1Json503");

            // P2-5: Numeric JSON "status" (e.g. {"status": 429} / {"status": 503}) falls back to retryable SC_*
            boolean caughtNum429 = false;
            try {
                tsClient.ping(Map.of("traceId", "p2_num_429"));
            } catch (BaccaratSdk.ApiException ex) {
                caughtNum429 = ex.httpStatus == 429 && "SC_RATE_LIMITED".equals(ex.status) && ex.isRetryable();
            }
            check(caughtNum429, "s2s:p2NumericStatus429");

            boolean caughtNum503 = false;
            try {
                tsClient.ping(Map.of("traceId", "p2_num_503"));
            } catch (BaccaratSdk.ApiException ex) {
                caughtNum503 = ex.httpStatus == 503 && "SC_OPERATOR_TIMEOUT".equals(ex.status)
                        && "p2_num_503".equals(ex.traceId) && ex.isRetryable();
            }
            check(caughtNum503, "s2s:p2NumericStatus503");

            // M4: exact 16 MiB response body succeeds; >16 MiB response body rejected with non-retryable SC_INVALID_REQUEST
            Map<String, Object> exactResp = tsClient.ping(Map.of("traceId", "m4_exact"));
            checkEq(exactResp.get("status"), "SC_OK", "s2s:m4Exact16MiB");

            boolean caughtM4Overflow = false;
            try {
                tsClient.ping(Map.of("traceId", "m4_overflow"));
            } catch (BaccaratSdk.ApiException ex) {
                caughtM4Overflow = BaccaratSdk.StatusCode.SC_INVALID_REQUEST.equals(ex.status)
                        && ex.httpStatus == 200
                        && "m4_overflow".equals(ex.traceId)
                        && !ex.isRetryable();
            }
            check(caughtM4Overflow, "s2s:m4Overflow16MiB");

            // Regression: BoundedBodySubscriber HTTP/2 synchronous-cancel race
            // (Subscription.cancel() synchronously invokes onError(IOException("Stream 1 cancelled")) or throws)
            {
                BaccaratSdk.Client.BoundedBodySubscriber raceSub =
                        new BaccaratSdk.Client.BoundedBodySubscriber(16, 200, "h2_sync_cancel_race");
                java.util.concurrent.atomic.AtomicBoolean cancelCalled = new java.util.concurrent.atomic.AtomicBoolean(false);
                java.util.concurrent.atomic.AtomicBoolean overflowVisibleInCancel = new java.util.concurrent.atomic.AtomicBoolean(false);
                java.util.concurrent.atomic.AtomicBoolean bodyDoneInCancel = new java.util.concurrent.atomic.AtomicBoolean(false);
                raceSub.onSubscribe(new java.util.concurrent.Flow.Subscription() {
                    @Override public void request(long n) {}
                    @Override public void cancel() {
                        cancelCalled.set(true);
                        overflowVisibleInCancel.set(raceSub.overflowError != null);
                        bodyDoneInCancel.set(raceSub.getBody().toCompletableFuture().isCompletedExceptionally());
                        raceSub.onError(new java.io.IOException("Stream 1 cancelled"));
                    }
                });
                raceSub.onNext(List.of(java.nio.ByteBuffer.wrap(new byte[10])));
                raceSub.onNext(List.of(java.nio.ByteBuffer.wrap(new byte[10])));
                check(cancelCalled.get(), "s2s:h2RaceCancelCalled");
                check(overflowVisibleInCancel.get(), "s2s:h2RaceOverflowSetBeforeCancel");
                check(bodyDoneInCancel.get(), "s2s:h2RaceBodyCompletedBeforeCancel");
                check(raceSub.overflowError != null
                        && BaccaratSdk.StatusCode.SC_INVALID_REQUEST.equals(raceSub.overflowError.status)
                        && raceSub.overflowError.httpStatus == 200
                        && "h2_sync_cancel_race".equals(raceSub.overflowError.traceId)
                        && !raceSub.overflowError.isRetryable(), "s2s:h2RaceOverflowError");
                boolean bodyThrewApi = false;
                try {
                    raceSub.getBody().toCompletableFuture().get();
                } catch (java.util.concurrent.ExecutionException ee) {
                    if (ee.getCause() instanceof BaccaratSdk.ApiException apiEx) {
                        bodyThrewApi = apiEx == raceSub.overflowError
                                && BaccaratSdk.StatusCode.SC_INVALID_REQUEST.equals(apiEx.status)
                                && apiEx.httpStatus == 200
                                && "h2_sync_cancel_race".equals(apiEx.traceId)
                                && !apiEx.isRetryable();
                    }
                }
                check(bodyThrewApi, "s2s:h2RaceBodyFutureIsApiException");
            }
            {
                BaccaratSdk.Client.BoundedBodySubscriber throwSub =
                        new BaccaratSdk.Client.BoundedBodySubscriber(16, 200, "h2_cancel_throw_race");
                throwSub.onSubscribe(new java.util.concurrent.Flow.Subscription() {
                    @Override public void request(long n) {}
                    @Override public void cancel() {
                        throw new IllegalStateException("Stream 1 cancelled synchronously");
                    }
                });
                throwSub.onNext(List.of(java.nio.ByteBuffer.wrap(new byte[32])));
                check(throwSub.overflowError != null
                        && BaccaratSdk.StatusCode.SC_INVALID_REQUEST.equals(throwSub.overflowError.status)
                        && throwSub.overflowError.httpStatus == 200
                        && "h2_cancel_throw_race".equals(throwSub.overflowError.traceId)
                        && !throwSub.overflowError.isRetryable(), "s2s:h2CancelThrowOverflowError");
                boolean bodyThrewApi = false;
                try {
                    throwSub.getBody().toCompletableFuture().get();
                } catch (java.util.concurrent.ExecutionException ee) {
                    bodyThrewApi = ee.getCause() == throwSub.overflowError;
                }
                check(bodyThrewApi, "s2s:h2CancelThrowBodyFutureIsApiException");
            }

            // Body-read timeout regression: headers arrive immediately, body stalls mid-stream -> must fail within timeoutMs
            java.util.concurrent.CountDownLatch releaseStall = new java.util.concurrent.CountDownLatch(1);
            try (java.net.ServerSocket stallSrv = new java.net.ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))) {
                Thread stallThread = new Thread(() -> {
                    try (java.net.Socket sock = stallSrv.accept()) {
                        var in = sock.getInputStream();
                        byte[] buf = new byte[1024];
                        StringBuilder reqBuf = new StringBuilder();
                        sock.setSoTimeout(200);
                        try {
                            int n;
                            while ((n = in.read(buf)) > 0) {
                                reqBuf.append(new String(buf, 0, n, StandardCharsets.ISO_8859_1));
                                String s = reqBuf.toString();
                                int hdrEnd = s.indexOf("\r\n\r\n");
                                if (hdrEnd >= 0 && s.indexOf('}', hdrEnd + 4) >= 0) {
                                    break;
                                }
                            }
                        } catch (java.net.SocketTimeoutException ignored) {
                        }
                        var out = sock.getOutputStream();
                        out.write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"a\":".getBytes(StandardCharsets.UTF_8));
                        out.flush();
                        releaseStall.await(10, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (Exception ignored) {
                    }
                });
                stallThread.setDaemon(true);
                stallThread.start();
                try {
                    BaccaratSdk.Config stallCfg = new BaccaratSdk.Config(
                            apiKey, secret, BaccaratSdk.Environment.PRODUCTION,
                            "http://127.0.0.1:" + stallSrv.getLocalPort(), 400
                    );
                    BaccaratSdk.Client stallClient = new BaccaratSdk.Client(stallCfg);
                    long t0 = System.nanoTime();
                    boolean caughtBodyTimeout = false;
                    try {
                        stallClient.ping(Map.of("traceId", "body_stall_timeout"));
                    } catch (BaccaratSdk.TransportException ex) {
                        caughtBodyTimeout = BaccaratSdk.StatusCode.SC_OPERATOR_TIMEOUT.equals(ex.code)
                                && BaccaratSdk.StatusCode.isRetryable(ex.code);
                    }
                    long elapsedMs = (System.nanoTime() - t0) / 1_000_000L;
                    check(caughtBodyTimeout, "s2s:bodyReadTimeoutStatus");
                    check(elapsedMs < 1500L, "s2s:bodyReadTimeoutElapsed<" + elapsedMs + "ms");
                } finally {
                    releaseStall.countDown();
                    stallThread.join(1000);
                }
            }

            // m1: traceId in filters is stripped so every page & retry gets a distinct fresh UUID
            List<Map<String, Object>> retried = tsClient.listAllTransactions(
                    1000L, 2000L, 2,
                    Map.of("username", "player_9527", "traceId", "caller-fixed-trace"),
                    3, 0L
            );
            checkEq(retried.size(), 3, "s2s:listAllRateLimitRetry");
            checkEq(p1Count.get(), 2, "s2s:p1Attempts");
            checkEq(listTraces.size(), 3, "s2s:m1TraceCount");
            checkEq(new java.util.HashSet<>(listTraces).size(), 3, "s2s:m1UniqueTraces");
            check(!listTraces.contains("caller-fixed-trace"), "s2s:m1StrippedCallerTrace");
        } finally {
            rlSrv.stop(0);
        }

        // 5. v1.5.11 regressions: deadlock, S2S ApiException/TransportException/overflow, allowlist SdkException & sneaky-thrown checked exceptions -> SC_OPERATOR_TIMEOUT sanitized, string-only traceId, strict InMemoryWallet typing, strict UTF-8, & walletOk/walletError guards
        BaccaratSdk.WalletHandler deadlockWallet = new BaccaratSdk.WalletHandler() {
            @Override public Map<String, Object> onBalance(Map<String, Object> req) {
                throw new BaccaratSdk.SdkException(BaccaratSdk.StatusCode.SC_INSUFFICIENT_FUNDS, "explicit sdk err");
            }
            @Override public Map<String, Object> onBet(Map<String, Object> req) {
                Object amt = req.get("amount");
                BaccaratSdk.decimalToLedgerUnits(amt == null ? "bad_amt" : String.valueOf(amt), 2, false);
                return BaccaratSdk.walletOk(String.valueOf(req.get("traceId")), "p1", "USD", "100.00");
            }
            @Override public Map<String, Object> onBetResult(Map<String, Object> req) {
                Object mode = req.get("mode");
                if ("bad_balance".equals(mode)) {
                    return BaccaratSdk.walletOk(String.valueOf(req.get("traceId")), "p1", "USD", "-1.00");
                }
                if ("nan_balance".equals(mode)) {
                    return BaccaratSdk.walletOk(String.valueOf(req.get("traceId")), "p1", "USD", "NaN");
                }
                if ("s2s_api_err".equals(mode)) {
                    throw new BaccaratSdk.ApiException(
                            BaccaratSdk.StatusCode.SC_INVALID_REQUEST,
                            "upstream S2S failure secret detail",
                            "t_upstream_s2s",
                            null,
                            400
                    );
                }
                if ("s2s_overflow_err".equals(mode)) {
                    throw new BaccaratSdk.ApiException(
                            BaccaratSdk.StatusCode.SC_INVALID_REQUEST,
                            "Gateway response exceeded 16 MiB limit",
                            "t_upstream_overflow",
                            null,
                            200
                    );
                }
                if ("s2s_transport_err".equals(mode)) {
                    throw new BaccaratSdk.TransportException("curl failed: 10.0.1.5:8443 proxy refused");
                }
                if ("sdk_sc_ok".equals(mode)) {
                    throw new BaccaratSdk.SdkException(BaccaratSdk.StatusCode.SC_OK, "bogus SC_OK error");
                }
                if ("sdk_sc_custom".equals(mode)) {
                    throw new BaccaratSdk.SdkException("SC_CUSTOM", "bogus custom error");
                }
                if ("sdk_sc_prefix".equals(mode)) {
                    throw new BaccaratSdk.SdkException("SC_", "bogus prefix error");
                }
                throw new RuntimeException("ERROR: deadlock detected (40P01) on table wallets");
            }
            @Override public Map<String, Object> onRollback(Map<String, Object> req) {
                return BaccaratSdk.walletOk(String.valueOf(req.get("traceId")), "p1", "USD", "100.00");
            }
            @Override public Map<String, Object> onAdjustment(Map<String, Object> req) {
                sneakyThrow(new java.io.IOException("jdbc pool exhausted"));
                return null;
            }
        };
        BaccaratSdk.WebhookDispatcher dlDisp = new BaccaratSdk.WebhookDispatcher(apiKey, secret, deadlockWallet);
        byte[] dlRaw = "{\"traceId\":\"t_java_dl\",\"transactionId\":\"stl_1\"}".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> dlResp = dlDisp.handle("/wallet/bet_result", apiKey, BaccaratSdk.signBody(dlRaw, secret), dlRaw);
        checkEq(dlResp.get("traceId"), "t_java_dl", "wb:deadlockTraceId");
        checkEq(dlResp.get("status"), BaccaratSdk.StatusCode.SC_OPERATOR_TIMEOUT, "wb:deadlockStatus");
        checkEq(dlResp.get("message"), "Temporary wallet handler error", "wb:deadlockSanitizedMsg");
        check(!String.valueOf(dlResp.get("message")).contains("40P01"), "wb:deadlockNoSqlLeak");

        for (String mode : new String[]{"bad_balance", "nan_balance", "s2s_api_err", "s2s_overflow_err", "s2s_transport_err", "sdk_sc_ok", "sdk_sc_custom", "sdk_sc_prefix"}) {
            byte[] bbRaw = ("{\"traceId\":\"t_java_" + mode + "\",\"mode\":\"" + mode + "\"}").getBytes(StandardCharsets.UTF_8);
            Map<String, Object> bbResp = dlDisp.handle("/wallet/bet_result", apiKey, BaccaratSdk.signBody(bbRaw, secret), bbRaw);
            checkEq(bbResp.get("traceId"), "t_java_" + mode, "wb:internalSdkErrTrace:" + mode);
            checkEq(bbResp.get("status"), BaccaratSdk.StatusCode.SC_OPERATOR_TIMEOUT, "wb:internalSdkErrStatus:" + mode);
            checkEq(bbResp.get("message"), "Temporary wallet handler error", "wb:internalSdkErrMsg:" + mode);
            check(!String.valueOf(bbResp.get("message")).contains("walletOk"), "wb:internalSdkErrNoLeak:" + mode);
            check(!String.valueOf(bbResp.get("message")).contains("upstream"), "wb:internalSdkErrNoS2sLeak:" + mode);
            check(!String.valueOf(bbResp.get("message")).contains("10.0.1.5"), "wb:internalSdkErrNoTransportLeak:" + mode);
            check(!String.valueOf(bbResp.get("message")).contains("16 MiB"), "wb:internalSdkErrNoOverflowLeak:" + mode);
            check(!String.valueOf(bbResp.get("message")).contains("bogus"), "wb:internalSdkErrNoBogusLeak:" + mode);
        }

        // P3-3: non-string traceId (e.g. JSON number 123) in validly signed webhook body must echo "" not "123"
        byte[] numTraceUnknownRaw = "{\"traceId\": 123, \"username\": \"alice\"}".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> numTraceUnknownResp = dlDisp.handle("/wallet/unknown", apiKey, BaccaratSdk.signBody(numTraceUnknownRaw, secret), numTraceUnknownRaw);
        checkEq(numTraceUnknownResp.get("status"), BaccaratSdk.StatusCode.SC_INVALID_REQUEST, "wb:p33NumTraceUnknownStatus");
        checkEq(numTraceUnknownResp.get("traceId"), "", "wb:p33NumTraceUnknownEmpty");

        byte[] numTraceErrRaw = "{\"traceId\": 123, \"mode\": \"s2s_transport_err\"}".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> numTraceErrResp = dlDisp.handle("/wallet/bet_result", apiKey, BaccaratSdk.signBody(numTraceErrRaw, secret), numTraceErrRaw);
        checkEq(numTraceErrResp.get("status"), BaccaratSdk.StatusCode.SC_OPERATOR_TIMEOUT, "wb:p33NumTraceErrStatus");
        checkEq(numTraceErrResp.get("traceId"), "", "wb:p33NumTraceErrEmpty");

        for (String badAmt : new String[]{"not_a_number", "1.123456", "-5.00"}) {
            byte[] bdRaw = ("{\"traceId\":\"t_java_bad_dec\",\"amount\":\"" + badAmt + "\"}").getBytes(StandardCharsets.UTF_8);
            Map<String, Object> bdResp = dlDisp.handle("/wallet/bet", apiKey, BaccaratSdk.signBody(bdRaw, secret), bdRaw);
            checkEq(bdResp.get("status"), BaccaratSdk.StatusCode.SC_INVALID_REQUEST, "wb:incomingDecInvalidReq:" + badAmt);
        }

        Map<String, Object> sdkErrResp = dlDisp.handle("/wallet/balance", apiKey, BaccaratSdk.signBody(dlRaw, secret), dlRaw);
        checkEq(sdkErrResp.get("status"), BaccaratSdk.StatusCode.SC_INSUFFICIENT_FUNDS, "wb:sdkErrPreserved");

        // Checked exception thrown via Kotlin/Groovy/Lombok @SneakyThrows must also be caught and sanitized
        byte[] sneakyRaw = "{\"traceId\":\"t_java_sneaky\",\"transactionId\":\"adj_1\"}".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> sneakyResp = dlDisp.handle("/wallet/adjustment", apiKey, BaccaratSdk.signBody(sneakyRaw, secret), sneakyRaw);
        checkEq(sneakyResp.get("traceId"), "t_java_sneaky", "wb:sneakyCheckedTraceId");
        checkEq(sneakyResp.get("status"), BaccaratSdk.StatusCode.SC_OPERATOR_TIMEOUT, "wb:sneakyCheckedStatus");
        checkEq(sneakyResp.get("message"), "Temporary wallet handler error", "wb:sneakyCheckedSanitizedMsg");
        check(!String.valueOf(sneakyResp.get("message")).contains("jdbc"), "wb:sneakyCheckedNoLeak");

        Map<String, Object> builtOk = BaccaratSdk.walletOk("t_ok", "player_1", "JPY", "0");
        checkEq(builtOk.get("status"), BaccaratSdk.StatusCode.SC_OK, "walletOk:status");
        checkEq(((Map<?, ?>) builtOk.get("data")).get("balance"), "0", "walletOk:balance");
        Map<String, Object> builtErr = BaccaratSdk.walletError("t_err", BaccaratSdk.StatusCode.SC_USER_DISABLED, "disabled");
        checkEq(builtErr.get("status"), BaccaratSdk.StatusCode.SC_USER_DISABLED, "walletError:status");
        checkEq(builtErr.get("message"), "disabled", "walletError:message");

        for (String badBal : new String[]{null, "", "   ", "-1.00", "abc", "10.", ".5", "10.00\n"}) {
            boolean threw = false;
            try {
                BaccaratSdk.walletOk("t_bad", "player_1", "USD", badBal);
            } catch (BaccaratSdk.SdkException e) {
                threw = "INVALID_ARGUMENT".equals(e.code);
            }
            check(threw, "walletOk:rejectBadBalance:" + badBal);
        }
        for (String badSt : new String[]{null, "", "   ", BaccaratSdk.StatusCode.SC_OK, " SC_OK ", "sc_ok", "Sc_Ok", " sc_ok ", "SC_", "SC_TIMEOUT", "SC_CUSTOM", "INSUFFICIENT_FUNDS"}) {
            boolean threw = false;
            try {
                BaccaratSdk.walletError("t_bad", badSt, "oops");
            } catch (BaccaratSdk.SdkException e) {
                threw = "INVALID_ARGUMENT".equals(e.code);
            }
            check(threw, "walletError:rejectBadStatus:" + badSt);
        }

        // v1.5.11 P2-1: Java InMemoryWallet strict string/amount typing
        BaccaratSdk.InMemoryWallet strictWallet = new BaccaratSdk.InMemoryWallet();
        strictWallet.addAccount("alice", "USD", "100.00", 2, List.of("tok_ok"));
        BaccaratSdk.WebhookDispatcher strictDisp = new BaccaratSdk.WebhookDispatcher(apiKey, secret, strictWallet);
        String[] badBetPayloads = new String[]{
                "{\"traceId\":\"t_j1\",\"transactionId\":[\"a\"],\"betId\":\"b1\",\"username\":\"alice\",\"currency\":\"USD\",\"amount\":\"10.00\",\"token\":\"tok_ok\"}",
                "{\"traceId\":\"t_j2\",\"transactionId\":\"tx2\",\"betId\":\"b2\",\"username\":123,\"currency\":\"USD\",\"amount\":\"10.00\",\"token\":\"tok_ok\"}",
                "{\"traceId\":\"t_j3\",\"transactionId\":\"tx3\",\"betId\":\"b3\",\"username\":\"alice\",\"currency\":\"USD\",\"amount\":true,\"token\":\"tok_ok\"}",
                "{\"traceId\":[\"t1\"],\"transactionId\":\"tx4\",\"betId\":\"b4\",\"username\":\"alice\",\"currency\":\"USD\",\"amount\":true,\"token\":\"tok_ok\"}"
        };
        for (int i = 0; i < badBetPayloads.length; i++) {
            byte[] raw = badBetPayloads[i].getBytes(StandardCharsets.UTF_8);
            Map<String, Object> resp = strictDisp.handle("/wallet/bet", apiKey, BaccaratSdk.signBody(raw, secret), raw);
            checkEq(resp.get("status"), BaccaratSdk.StatusCode.SC_INVALID_REQUEST, "wb:p21StrictBet:" + i);
            if (i == 3) {
                checkEq(resp.get("traceId"), "", "wb:p21StrictTraceArrayEmpty");
            }
        }
        // Also verify direct onBet with non-string traceId echoes "" and scalarStr ignores List/Map in fingerprints
        Map<String, Object> directArrTrace = strictWallet.onBet(Map.of(
                "traceId", List.of("t1"),
                "transactionId", List.of("a"),
                "betId", "b_direct",
                "username", "alice",
                "currency", "USD",
                "amount", "10.00",
                "token", "tok_ok"
        ));
        checkEq(directArrTrace.get("status"), BaccaratSdk.StatusCode.SC_INVALID_REQUEST, "wb:p21DirectArrTraceStatus");
        checkEq(directArrTrace.get("traceId"), "", "wb:p21DirectArrTraceEmpty");
        checkEq(
                BaccaratSdk.betFingerprint(Map.of("transactionId", "t", "roundId", List.of("a"))),
                BaccaratSdk.betFingerprint(Map.of("transactionId", "t")),
                "fp:p21ScalarStrIgnoresList"
        );
        byte[] balCheckRaw = "{\"traceId\":\"t_chk\",\"username\":\"alice\",\"currency\":\"USD\",\"token\":\"tok_ok\"}".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> balCheckResp = strictDisp.handle("/wallet/balance", apiKey, BaccaratSdk.signBody(balCheckRaw, secret), balCheckRaw);
        checkEq(balCheckResp.get("status"), BaccaratSdk.StatusCode.SC_OK, "wb:p21BalanceUnchangedStatus");
        checkEq(((Map<?, ?>) balCheckResp.get("data")).get("balance"), "100.00", "wb:p21BalanceUnchanged");

        // v1.5.11 P3-2: strict UTF-8 validation in WebhookDispatcher
        byte[] prefix = "{\"traceId\":\"t1".getBytes(StandardCharsets.UTF_8);
        byte[] suffix = "\",\"username\":\"alice\"}".getBytes(StandardCharsets.UTF_8);
        byte[] badUtf8 = new byte[prefix.length + 1 + suffix.length];
        System.arraycopy(prefix, 0, badUtf8, 0, prefix.length);
        badUtf8[prefix.length] = (byte) 0xff;
        System.arraycopy(suffix, 0, badUtf8, prefix.length + 1, suffix.length);
        Map<String, Object> badUtf8Resp = strictDisp.handle("/wallet/balance", apiKey, BaccaratSdk.signBody(badUtf8, secret), badUtf8);
        checkEq(badUtf8Resp.get("status"), BaccaratSdk.StatusCode.SC_INVALID_REQUEST, "wb:p32InvalidUtf8Status");
        checkEq(badUtf8Resp.get("traceId"), "", "wb:p32InvalidUtf8TraceEmpty");

        // 6. v1.6.0: notifyPlayerBalance, getGameCcu, paginated getWalletTransactionStatus,
        //    deterministic isEndRound (0 then 1 in same round), and outbound X-Timestamp header invariance
        HttpServer v160Srv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        v160Srv.createContext("/operator/v1/", ex -> {
            byte[] reqBytes = ex.getRequestBody().readAllBytes();
            String st = BaccaratSdk.verifyWebhookHeaders(
                    ex.getRequestHeaders().getFirst("X-API-Key"),
                    ex.getRequestHeaders().getFirst("X-Signature"),
                    reqBytes, apiKey, secret
            );
            Map<String, Object> body = JsonCodec.parseObject(new String(reqBytes, StandardCharsets.UTF_8));
            Map<String, Object> resp = new LinkedHashMap<>();
            resp.put("traceId", body.get("traceId"));
            if (!BaccaratSdk.StatusCode.SC_OK.equals(st)) {
                resp.put("status", st);
                resp.put("message", "auth failed");
            } else {
                String path = ex.getRequestURI().getPath();
                resp.put("status", "SC_OK");
                if ("/operator/v1/player/balance-notify".equals(path)) {
                    Object u = body.get("username");
                    if ("player_online".equals(u)) {
                        if (!"CNY".equals(body.get("currency")) || !"DEPOSIT".equals(body.get("reason"))) {
                            resp.put("status", "SC_INVALID_REQUEST");
                            resp.put("message", "unexpected notify fields");
                        } else {
                            Map<String, Object> data = new LinkedHashMap<>();
                            data.put("username", "player_online");
                            data.put("currency", "CNY");
                            data.put("notified", true);
                            data.put("activeSessions", 2);
                            data.put("serverTime", 1764200000000L);
                            resp.put("data", data);
                        }
                    } else if ("player_offline".equals(u)) {
                        Map<String, Object> data = new LinkedHashMap<>();
                        data.put("username", "player_offline");
                        data.put("currency", null);
                        data.put("notified", false);
                        data.put("activeSessions", 0);
                        data.put("serverTime", 1764200000001L);
                        resp.put("data", data);
                    } else {
                        resp.put("status", "SC_USER_NOT_EXISTS");
                        resp.put("message", "user not mapped");
                    }
                } else if ("/operator/v1/game/ccu".equals(path)) {
                    Object tableId = body.get("tableId");
                    if (tableId == null || "".equals(tableId)) {
                        resp.put("data", Map.of(
                                "operatorId", "OP_ALPHA",
                                "onlinePlayers", 12,
                                "seatedPlayers", 9,
                                "lobbyPlayers", 3,
                                "tables", List.of(
                                        Map.of("tableId", "T-A1", "gameCode", "BACCARAT_T-A1", "playerCount", 2),
                                        Map.of("tableId", "T-A2", "gameCode", "BACCARAT_T-A2", "playerCount", 7)
                                ),
                                "serverTime", 1764200000100L
                        ));
                    } else if ("T-A2".equals(tableId)) {
                        resp.put("data", Map.of(
                                "operatorId", "OP_ALPHA",
                                "onlinePlayers", 7,
                                "seatedPlayers", 7,
                                "lobbyPlayers", 0,
                                "tables", List.of(
                                        Map.of("tableId", "T-A2", "gameCode", "BACCARAT_T-A2", "playerCount", 7)
                                ),
                                "serverTime", 1764200000200L
                        ));
                    } else {
                        resp.put("status", "SC_INVALID_GAME");
                        resp.put("message", "table not permitted");
                    }
                } else if ("/operator/v1/wallet/transaction-status".equals(path)) {
                    int pageNo = body.get("pageNo") instanceof Number n ? n.intValue() : 1;
                    int pageSize = body.get("pageSize") instanceof Number n ? n.intValue() : 200;
                    List<Map<String, Object>> rows = pageNo == 1
                            ? List.of(
                                    Map.of("transactionId", "bet_j_p1_1", "betId", "b2btkt_j1", "status", "COMPLETED"),
                                    Map.of("transactionId", "stl_j_p1_2", "betId", "b2btkt_j1", "status", "COMPLETED")
                            )
                            : List.of(
                                    Map.of("transactionId", "stl_j_p2_3", "betId", "b2btkt_j2", "status", "PENDING")
                            );
                    boolean hasMore = (long) pageNo * pageSize < 3L;
                    Map<String, Object> data = new LinkedHashMap<>();
                    data.put("transactions", rows);
                    data.put("pageNo", pageNo);
                    data.put("pageSize", pageSize);
                    data.put("total", 3);
                    data.put("hasMore", hasMore);
                    resp.put("data", data);
                }
            }
            byte[] out = JsonCodec.stringify(resp).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        v160Srv.start();
        try {
            BaccaratSdk.Config v160Cfg = new BaccaratSdk.Config(
                    apiKey, secret, BaccaratSdk.Environment.PRODUCTION,
                    "http://127.0.0.1:" + v160Srv.getAddress().getPort(), 5000
            );
            BaccaratSdk.Client v160Client = new BaccaratSdk.Client(v160Cfg);

            // notifyPlayerBalance: online (notified=true) & offline (notified=false, currency=null)
            Map<String, Object> onlineNotify = (Map<String, Object>) v160Client.notifyPlayerBalance(Map.of(
                    "username", "player_online", "currency", "CNY", "reason", "DEPOSIT"
            )).get("data");
            checkEq(onlineNotify.get("username"), "player_online", "v160:notifyOnlineUser");
            checkEq(onlineNotify.get("currency"), "CNY", "v160:notifyOnlineCurrency");
            checkEq(onlineNotify.get("notified"), Boolean.TRUE, "v160:notifyOnlineFlag");
            checkEq(((Number) onlineNotify.get("activeSessions")).intValue(), 2, "v160:notifyOnlineSessions");
            checkEq(((Number) onlineNotify.get("serverTime")).longValue(), 1764200000000L, "v160:notifyOnlineServerTime");

            Map<String, Object> offlineNotify = (Map<String, Object>) v160Client.notifyPlayerBalance(Map.of(
                    "username", "player_offline"
            )).get("data");
            checkEq(offlineNotify.get("username"), "player_offline", "v160:notifyOfflineUser");
            check(offlineNotify.containsKey("currency") && offlineNotify.get("currency") == null, "v160:notifyOfflineNullableCurrency");
            checkEq(offlineNotify.get("notified"), Boolean.FALSE, "v160:notifyOfflineFlag");
            checkEq(((Number) offlineNotify.get("activeSessions")).intValue(), 0, "v160:notifyOfflineSessions");
            checkEq(((Number) offlineNotify.get("serverTime")).longValue(), 1764200000001L, "v160:notifyOfflineServerTime");

            for (Map<String, Object> badNotify : List.<Map<String, Object>>of(Map.of(), Map.of("username", "   "), Map.of("username", 123))) {
                boolean threw = false;
                try {
                    v160Client.notifyPlayerBalance(badNotify);
                } catch (BaccaratSdk.SdkException ex) {
                    threw = "INVALID_ARGUMENT".equals(ex.code);
                }
                check(threw, "v160:notifyInvalidUsername:" + badNotify);
            }
            boolean threwNullNotify = false;
            try {
                v160Client.notifyPlayerBalance(null);
            } catch (BaccaratSdk.SdkException ex) {
                threwNullNotify = "INVALID_ARGUMENT".equals(ex.code);
            }
            check(threwNullNotify, "v160:notifyNullParams");
            boolean caughtNotifyNotExists = false;
            try {
                v160Client.notifyPlayerBalance(Map.of("username", "ghost_user"));
            } catch (BaccaratSdk.ApiException ex) {
                caughtNotifyNotExists = BaccaratSdk.StatusCode.SC_USER_NOT_EXISTS.equals(ex.status);
            }
            check(caughtNotifyNotExists, "v160:notifyUserNotExists");

            // getGameCcu: aggregate (0-arg overload) & tableId filter & SC_INVALID_GAME
            Map<String, Object> ccuAll = (Map<String, Object>) v160Client.getGameCcu().get("data");
            checkEq(ccuAll.get("operatorId"), "OP_ALPHA", "v160:ccuAllOp");
            checkEq(((Number) ccuAll.get("onlinePlayers")).intValue(), 12, "v160:ccuAllOnline");
            checkEq(((Number) ccuAll.get("seatedPlayers")).intValue(), 9, "v160:ccuAllSeated");
            checkEq(((Number) ccuAll.get("lobbyPlayers")).intValue(), 3, "v160:ccuAllLobby");
            checkEq(((Number) ccuAll.get("serverTime")).longValue(), 1764200000100L, "v160:ccuAllServerTime");
            List<Map<String, Object>> allTables = (List<Map<String, Object>>) ccuAll.get("tables");
            checkEq(allTables.size(), 2, "v160:ccuAllTablesCount");
            checkEq(allTables.get(0).get("tableId"), "T-A1", "v160:ccuAllT0Id");
            checkEq(allTables.get(0).get("gameCode"), "BACCARAT_T-A1", "v160:ccuAllT0Code");
            checkEq(((Number) allTables.get(0).get("playerCount")).intValue(), 2, "v160:ccuAllT0Count");
            checkEq(allTables.get(1).get("tableId"), "T-A2", "v160:ccuAllT1Id");
            checkEq(allTables.get(1).get("gameCode"), "BACCARAT_T-A2", "v160:ccuAllT1Code");
            checkEq(((Number) allTables.get(1).get("playerCount")).intValue(), 7, "v160:ccuAllT1Count");

            Map<String, Object> ccuTable = (Map<String, Object>) v160Client.getGameCcu(Map.of("tableId", "T-A2")).get("data");
            checkEq(ccuTable.get("operatorId"), "OP_ALPHA", "v160:ccuTableOp");
            checkEq(((Number) ccuTable.get("onlinePlayers")).intValue(), 7, "v160:ccuTableOnline");
            checkEq(((Number) ccuTable.get("seatedPlayers")).intValue(), 7, "v160:ccuTableSeated");
            checkEq(((Number) ccuTable.get("lobbyPlayers")).intValue(), 0, "v160:ccuTableLobby");
            checkEq(((Number) ccuTable.get("serverTime")).longValue(), 1764200000200L, "v160:ccuTableServerTime");
            List<Map<String, Object>> singleTables = (List<Map<String, Object>>) ccuTable.get("tables");
            checkEq(singleTables.size(), 1, "v160:ccuTableCount");
            checkEq(singleTables.get(0).get("tableId"), "T-A2", "v160:ccuTableT0Id");
            checkEq(singleTables.get(0).get("gameCode"), "BACCARAT_T-A2", "v160:ccuTableT0Code");
            checkEq(((Number) singleTables.get(0).get("playerCount")).intValue(), 7, "v160:ccuTableT0Count");

            boolean caughtInvalidGame = false;
            try {
                v160Client.getGameCcu(Map.of("tableId", "T-UNKNOWN"));
            } catch (BaccaratSdk.ApiException ex) {
                caughtInvalidGame = BaccaratSdk.StatusCode.SC_INVALID_GAME.equals(ex.status);
            }
            check(caughtInvalidGame, "v160:ccuInvalidGame");

            // getWalletTransactionStatus pagination: pageNo, pageSize, total, hasMore
            Map<String, Object> wtsP1 = (Map<String, Object>) v160Client.getWalletTransactionStatus(Map.of(
                    "username", "player_9527",
                    "fromTime", 1764190000000L,
                    "toTime", 1764210000000L,
                    "pageNo", 1,
                    "pageSize", 2
            )).get("data");
            checkEq(((Number) wtsP1.get("pageNo")).intValue(), 1, "v160:wtsP1PageNo");
            checkEq(((Number) wtsP1.get("pageSize")).intValue(), 2, "v160:wtsP1PageSize");
            checkEq(((Number) wtsP1.get("total")).intValue(), 3, "v160:wtsP1Total");
            checkEq(wtsP1.get("hasMore"), Boolean.TRUE, "v160:wtsP1HasMore");
            checkEq(((List<?>) wtsP1.get("transactions")).size(), 2, "v160:wtsP1Rows");

            Map<String, Object> wtsP2 = (Map<String, Object>) v160Client.getWalletTransactionStatus(Map.of(
                    "username", "player_9527",
                    "fromTime", 1764190000000L,
                    "toTime", 1764210000000L,
                    "pageNo", 2,
                    "pageSize", 2
            )).get("data");
            checkEq(((Number) wtsP2.get("pageNo")).intValue(), 2, "v160:wtsP2PageNo");
            checkEq(((Number) wtsP2.get("pageSize")).intValue(), 2, "v160:wtsP2PageSize");
            checkEq(((Number) wtsP2.get("total")).intValue(), 3, "v160:wtsP2Total");
            checkEq(wtsP2.get("hasMore"), Boolean.FALSE, "v160:wtsP2HasMore");
            checkEq(((List<?>) wtsP2.get("transactions")).size(), 1, "v160:wtsP2Rows");
        } finally {
            v160Srv.stop(0);
        }

        // Webhook: same round with isEndRound=0 (non-last) then isEndRound=1 (last), plus outbound X-Timestamp header
        BaccaratSdk.InMemoryWallet v160Wallet = new BaccaratSdk.InMemoryWallet();
        v160Wallet.addAccount("player_9527", "USD", "1000.00", 2, List.of(tok));
        BaccaratSdk.WebhookDispatcher v160Disp = new BaccaratSdk.WebhookDispatcher(apiKey, secret, v160Wallet);
        HttpServer wbSrv = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        java.util.concurrent.atomic.AtomicReference<String> seenWebhookTs = new java.util.concurrent.atomic.AtomicReference<>("");
        wbSrv.createContext("/wallet/", ex -> {
            seenWebhookTs.set(ex.getRequestHeaders().getFirst("X-Timestamp"));
            byte[] raw = ex.getRequestBody().readAllBytes();
            Map<String, Object> outMap = v160Disp.handle(
                    ex.getRequestURI().getPath(),
                    ex.getRequestHeaders().getFirst("X-API-Key"),
                    ex.getRequestHeaders().getFirst("X-Signature"),
                    raw
            );
            byte[] out = JsonCodec.stringify(outMap).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().set("Content-Type", "application/json");
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        wbSrv.start();
        try {
            java.net.http.HttpClient http = java.net.http.HttpClient.newHttpClient();
            int wbPort = wbSrv.getAddress().getPort();
            java.util.function.Function<Object[], Map<String, Object>> postWbTs = argsArr -> {
                String route = (String) argsArr[0];
                Map<String, Object> payload = (Map<String, Object>) argsArr[1];
                String xTs = (String) argsArr[2];
                try {
                    byte[] raw = JsonCodec.stringify(payload).getBytes(StandardCharsets.UTF_8);
                    String sig = BaccaratSdk.signBody(raw, secret);
                    check(BaccaratSdk.verifySignature(raw, sig, secret), "v160:wbVerifySig:" + route);
                    var rbld = java.net.http.HttpRequest.newBuilder()
                            .uri(java.net.URI.create("http://127.0.0.1:" + wbPort + route))
                            .header("Content-Type", "application/json")
                            .header("X-API-Key", apiKey)
                            .header("X-Signature", sig);
                    if (xTs != null && !xTs.isEmpty()) {
                        rbld.header("X-Timestamp", xTs);
                    }
                    var httpResp = http.send(
                            rbld.POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(raw)).build(),
                            java.net.http.HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
                    );
                    checkEq(httpResp.statusCode(), 200, "v160:wbHttp200:" + route);
                    return JsonCodec.parseObject(httpResp.body());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            };

            String rndId = "rnd_v160_java_multi";
            Map<String, Object> b1 = new LinkedHashMap<>();
            b1.put("traceId", "tr_jb1"); b1.put("username", "player_9527"); b1.put("transactionId", "bet_v160_j1");
            b1.put("betId", "b2btkt_v160_j1"); b1.put("externalTransactionId", "b2btkt_v160_j1"); b1.put("roundId", rndId);
            b1.put("amount", "50.00"); b1.put("currency", "USD"); b1.put("token", tok);
            b1.put("gameCode", "BACCARAT_T-A2"); b1.put("timestamp", 1764200000100L);

            Map<String, Object> b2 = new LinkedHashMap<>();
            b2.put("traceId", "tr_jb2"); b2.put("username", "player_9527"); b2.put("transactionId", "bet_v160_j2");
            b2.put("betId", "b2btkt_v160_j2"); b2.put("externalTransactionId", "b2btkt_v160_j2"); b2.put("roundId", rndId);
            b2.put("amount", "30.00"); b2.put("currency", "USD"); b2.put("token", tok);
            b2.put("gameCode", "BACCARAT_T-A2"); b2.put("timestamp", 1764200000150L);

            Map<String, Object> rB1 = postWbTs.apply(new Object[]{"/wallet/bet", b1, "1764200000101"});
            checkEq(rB1.get("status"), "SC_OK", "v160:wbBet1Status");
            checkEq(((Map<?, ?>) rB1.get("data")).get("balance"), "950.00", "v160:wbBet1Bal");
            checkEq(seenWebhookTs.get(), "1764200000101", "v160:wbBet1TsSeen");

            Map<String, Object> rB2 = postWbTs.apply(new Object[]{"/wallet/bet", b2, "1764200000151"});
            checkEq(rB2.get("status"), "SC_OK", "v160:wbBet2Status");
            checkEq(((Map<?, ?>) rB2.get("data")).get("balance"), "920.00", "v160:wbBet2Bal");

            Map<String, Object> s1 = new LinkedHashMap<>();
            s1.put("traceId", "tr_js1"); s1.put("username", "player_9527"); s1.put("transactionId", "stl_v160_j1");
            s1.put("betId", "b2btkt_v160_j1"); s1.put("externalTransactionId", "b2btkt_v160_j1"); s1.put("roundId", rndId);
            s1.put("betAmount", "50.00"); s1.put("winAmount", "100.00"); s1.put("effectiveTurnover", "50.00");
            s1.put("winLoss", "50.00"); s1.put("jackpotAmount", "0.00"); s1.put("resultType", "WIN");
            s1.put("isFreespin", 0); s1.put("isEndRound", 0);
            s1.put("currency", "USD"); s1.put("token", tok); s1.put("gameCode", "BACCARAT_T-A2");
            s1.put("betTime", 1764200000100L); s1.put("settledTime", 1764200000300L);

            Map<String, Object> rS1 = postWbTs.apply(new Object[]{"/wallet/bet_result", s1, "1764200000301"});
            checkEq(rS1.get("status"), "SC_OK", "v160:wbSettleEndRound0Status");
            checkEq(((Map<?, ?>) rS1.get("data")).get("balance"), "1020.00", "v160:wbSettleEndRound0Bal");
            checkEq(seenWebhookTs.get(), "1764200000301", "v160:wbSettleEndRound0TsSeen");

            Map<String, Object> s1Retry = new LinkedHashMap<>(s1);
            s1Retry.put("traceId", "tr_js1_retry");
            s1Retry.put("settledTime", 1764200030300L);
            Map<String, Object> rS1Retry = postWbTs.apply(new Object[]{"/wallet/bet_result", s1Retry, "1764200030301"});
            checkEq(rS1Retry.get("status"), "SC_OK", "v160:wbSettleEndRound0RetryStatus");
            checkEq(((Map<?, ?>) rS1Retry.get("data")).get("balance"), "1020.00", "v160:wbSettleEndRound0RetryBal");

            Map<String, Object> s1Conflict = new LinkedHashMap<>(s1);
            s1Conflict.put("traceId", "tr_js1_conflict");
            s1Conflict.put("isEndRound", 1);
            Map<String, Object> rS1Conflict = postWbTs.apply(new Object[]{"/wallet/bet_result", s1Conflict, "1764200040301"});
            checkEq(rS1Conflict.get("status"), "SC_TRANSACTION_DUPLICATED", "v160:wbSettleEndRoundFlipConflict");

            Map<String, Object> s2 = new LinkedHashMap<>();
            s2.put("traceId", "tr_js2"); s2.put("username", "player_9527"); s2.put("transactionId", "stl_v160_j2");
            s2.put("betId", "b2btkt_v160_j2"); s2.put("externalTransactionId", "b2btkt_v160_j2"); s2.put("roundId", rndId);
            s2.put("betAmount", "30.00"); s2.put("winAmount", "0.00"); s2.put("effectiveTurnover", "30.00");
            s2.put("winLoss", "-30.00"); s2.put("jackpotAmount", "0.00"); s2.put("resultType", "LOSE");
            s2.put("isFreespin", 0); s2.put("isEndRound", 1);
            s2.put("currency", "USD"); s2.put("token", tok); s2.put("gameCode", "BACCARAT_T-A2");
            s2.put("betTime", 1764200000150L); s2.put("settledTime", 1764200000400L);

            Map<String, Object> rS2 = postWbTs.apply(new Object[]{"/wallet/bet_result", s2, "1764200000401"});
            checkEq(rS2.get("status"), "SC_OK", "v160:wbSettleEndRound1Status");
            checkEq(((Map<?, ?>) rS2.get("data")).get("balance"), "1020.00", "v160:wbSettleEndRound1Bal");
            checkEq(seenWebhookTs.get(), "1764200000401", "v160:wbSettleEndRound1TsSeen");

            // Replay without X-Timestamp verifies identical X-Signature validation
            Map<String, Object> rS2NoTs = postWbTs.apply(new Object[]{"/wallet/bet_result", s2, ""});
            checkEq(rS2NoTs.get("status"), "SC_OK", "v160:wbSettleEndRound1NoTsStatus");
            checkEq(((Map<?, ?>) rS2NoTs.get("data")).get("balance"), "1020.00", "v160:wbSettleEndRound1NoTsBal");
        } finally {
            wbSrv.stop(0);
        }

        System.out.println("JAVA 17 SDK: ALL TESTS PASSED");
    }

    @SuppressWarnings("unchecked")
    private static <E extends Throwable> void sneakyThrow(Throwable t) throws E {
        throw (E) t;
    }
}

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
            } catch (BaccaratSdk.SdkException ex) {
                caughtM4Overflow = !(ex instanceof BaccaratSdk.ApiException)
                        && BaccaratSdk.StatusCode.SC_INVALID_REQUEST.equals(ex.code)
                        && !BaccaratSdk.StatusCode.isRetryable(ex.code);
            }
            check(caughtM4Overflow, "s2s:m4Overflow16MiB");

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
                    } catch (BaccaratSdk.SdkException ex) {
                        caughtBodyTimeout = !(ex instanceof BaccaratSdk.ApiException)
                                && BaccaratSdk.StatusCode.SC_OPERATOR_TIMEOUT.equals(ex.code)
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

        // 5. v1.5.5 regressions: deadlock RuntimeException -> SC_OPERATOR_TIMEOUT sanitized & walletOk/walletError builders
        BaccaratSdk.WalletHandler deadlockWallet = new BaccaratSdk.WalletHandler() {
            @Override public Map<String, Object> onBalance(Map<String, Object> req) {
                throw new BaccaratSdk.SdkException(BaccaratSdk.StatusCode.SC_INSUFFICIENT_FUNDS, "explicit sdk err");
            }
            @Override public Map<String, Object> onBet(Map<String, Object> req) {
                throw new RuntimeException("ERROR: deadlock detected (40P01) on table wallets");
            }
            @Override public Map<String, Object> onBetResult(Map<String, Object> req) {
                throw new RuntimeException("ERROR: deadlock detected (40P01) on table wallets");
            }
            @Override public Map<String, Object> onRollback(Map<String, Object> req) {
                return BaccaratSdk.walletOk(String.valueOf(req.get("traceId")), "p1", "USD", "100.00");
            }
        };
        BaccaratSdk.WebhookDispatcher dlDisp = new BaccaratSdk.WebhookDispatcher(apiKey, secret, deadlockWallet);
        byte[] dlRaw = "{\"traceId\":\"t_java_dl\",\"transactionId\":\"stl_1\"}".getBytes(StandardCharsets.UTF_8);
        Map<String, Object> dlResp = dlDisp.handle("/wallet/bet_result", apiKey, BaccaratSdk.signBody(dlRaw, secret), dlRaw);
        checkEq(dlResp.get("traceId"), "t_java_dl", "wb:deadlockTraceId");
        checkEq(dlResp.get("status"), BaccaratSdk.StatusCode.SC_OPERATOR_TIMEOUT, "wb:deadlockStatus");
        checkEq(dlResp.get("message"), "Temporary wallet handler error", "wb:deadlockSanitizedMsg");
        check(!String.valueOf(dlResp.get("message")).contains("40P01"), "wb:deadlockNoSqlLeak");
        Map<String, Object> sdkErrResp = dlDisp.handle("/wallet/balance", apiKey, BaccaratSdk.signBody(dlRaw, secret), dlRaw);
        checkEq(sdkErrResp.get("status"), BaccaratSdk.StatusCode.SC_INSUFFICIENT_FUNDS, "wb:sdkErrPreserved");

        Map<String, Object> builtOk = BaccaratSdk.walletOk("t_ok", "player_1", "JPY", "0");
        checkEq(builtOk.get("status"), BaccaratSdk.StatusCode.SC_OK, "walletOk:status");
        checkEq(((Map<?, ?>) builtOk.get("data")).get("balance"), "0", "walletOk:balance");
        Map<String, Object> builtErr = BaccaratSdk.walletError("t_err", BaccaratSdk.StatusCode.SC_USER_DISABLED, "disabled");
        checkEq(builtErr.get("status"), BaccaratSdk.StatusCode.SC_USER_DISABLED, "walletError:status");
        checkEq(builtErr.get("message"), "disabled", "walletError:message");

        System.out.println("JAVA 17 SDK: ALL TESTS PASSED");
    }
}

// SPDX-License-Identifier: MIT
package cloud.cniia.baccarat.sdk;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class BaccaratSdk {
    public static final String SANDBOX_BASE_URL = "https://api.lt.cniia.cloud";
    public static final long MAX_DETAIL_WINDOW_MS = 604_800_000L;
    public static final int MAX_PAGE_SIZE = 20_000;
    public static final int MAX_WEBHOOK_BODY_BYTES = 1_048_576;
    private static final int MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024;

    private static final Pattern HEX64_RE = Pattern.compile("^[0-9a-fA-F]{64}$");
    private static final Pattern DECIMAL_RE = Pattern.compile("^(-?)(\\d+)(?:\\.(\\d+))?$");
    private static final Pattern TRACE_HINT_RE = Pattern.compile("\"traceId\"\\s*:\\s*\"([A-Za-z0-9_.:-]{1,128})\"");
    private static final HexFormat HEX = HexFormat.of();

    private BaccaratSdk() {}

    public enum Environment {
        SANDBOX,
        PRODUCTION
    }

    public static final class StatusCode {
        public static final String SC_OK = "SC_OK";
        public static final String SC_INVALID_REQUEST = "SC_INVALID_REQUEST";
        public static final String SC_AUTHENTICATION_FAILED = "SC_AUTHENTICATION_FAILED";
        public static final String SC_INVALID_SIGNATURE = "SC_INVALID_SIGNATURE";
        public static final String SC_INVALID_TOKEN = "SC_INVALID_TOKEN";
        public static final String SC_INVALID_GAME = "SC_INVALID_GAME";
        public static final String SC_USER_NOT_EXISTS = "SC_USER_NOT_EXISTS";
        public static final String SC_USER_DISABLED = "SC_USER_DISABLED";
        public static final String SC_WRONG_CURRENCY = "SC_WRONG_CURRENCY";
        public static final String SC_CURRENCY_NOT_SUPPORTED = "SC_CURRENCY_NOT_SUPPORTED";
        public static final String SC_INSUFFICIENT_FUNDS = "SC_INSUFFICIENT_FUNDS";
        public static final String SC_TRANSACTION_DUPLICATED = "SC_TRANSACTION_DUPLICATED";
        public static final String SC_TRANSACTION_NOT_EXISTS = "SC_TRANSACTION_NOT_EXISTS";
        public static final String SC_TRANSACTION_STILL_PROCESSING = "SC_TRANSACTION_STILL_PROCESSING";
        public static final String SC_OPERATOR_TIMEOUT = "SC_OPERATOR_TIMEOUT";
        public static final String SC_UNDER_MAINTENANCE = "SC_UNDER_MAINTENANCE";
        public static final String SC_GAME_DISABLED = "SC_GAME_DISABLED";
        public static final String SC_RATE_LIMITED = "SC_RATE_LIMITED";

        private static final Set<String> VALID_ERROR_CODES = Set.of(
                SC_INVALID_REQUEST,
                SC_AUTHENTICATION_FAILED,
                SC_INVALID_SIGNATURE,
                SC_INVALID_TOKEN,
                SC_INVALID_GAME,
                SC_USER_NOT_EXISTS,
                SC_USER_DISABLED,
                SC_WRONG_CURRENCY,
                SC_CURRENCY_NOT_SUPPORTED,
                SC_INSUFFICIENT_FUNDS,
                SC_TRANSACTION_DUPLICATED,
                SC_TRANSACTION_NOT_EXISTS,
                SC_TRANSACTION_STILL_PROCESSING,
                SC_OPERATOR_TIMEOUT,
                SC_UNDER_MAINTENANCE,
                SC_GAME_DISABLED,
                SC_RATE_LIMITED
        );

        public static boolean isValidErrorCode(String status) {
            return status != null && VALID_ERROR_CODES.contains(status);
        }

        public static boolean isRetryable(String status) {
            if (status == null) return false;
            String s = status.trim();
            return SC_TRANSACTION_STILL_PROCESSING.equals(s)
                    || SC_OPERATOR_TIMEOUT.equals(s)
                    || SC_RATE_LIMITED.equals(s);
        }
    }

    public static class SdkException extends RuntimeException {
        public final String code;

        public SdkException(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    public static final class ApiException extends SdkException {
        public final String traceId;
        public final String status;
        public final Map<String, String> validation;
        public final int httpStatus;

        public ApiException(String status, String message, String traceId, Map<String, String> validation, int httpStatus) {
            super(status, (message == null || message.isEmpty()) ? ("B2B API error: " + status) : message);
            this.status = status;
            this.traceId = traceId;
            this.validation = validation;
            this.httpStatus = httpStatus;
        }

        public boolean isRetryable() {
            return StatusCode.isRetryable(status);
        }
    }

    // ── 1. Raw-Byte HMAC-SHA256 Signing & Timing-Safe Verification ──────────

    public static String signBody(byte[] rawBody, String hmacSecret) {
        if (hmacSecret == null || hmacSecret.isEmpty()) {
            throw new SdkException("INVALID_CONFIG", "hmacSecret must be non-empty");
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            // CRITICAL: Use raw UTF-8 bytes of hmacSecret string directly — NEVER Base64-decode!
            mac.init(new SecretKeySpec(hmacSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HEX.formatHex(mac.doFinal(rawBody == null ? new byte[0] : rawBody));
        } catch (Exception e) {
            throw new SdkException("CRYPTO_ERROR", e.getMessage());
        }
    }

    public static String signBody(String rawBodyUtf8, String hmacSecret) {
        return signBody((rawBodyUtf8 == null ? "" : rawBodyUtf8).getBytes(StandardCharsets.UTF_8), hmacSecret);
    }

    public static boolean verifySignature(byte[] rawBody, String signatureHeader, String hmacSecret) {
        if (hmacSecret == null || hmacSecret.isEmpty() || signatureHeader == null) return false;
        String trimmed = signatureHeader.trim();
        if (!HEX64_RE.matcher(trimmed).matches()) return false;
        byte[] expected = HEX.parseHex(signBody(rawBody, hmacSecret));
        byte[] actual = HEX.parseHex(trimmed.toLowerCase(Locale.ROOT));
        return MessageDigest.isEqual(actual, expected);
    }

    public static String verifyWebhookHeaders(
            String apiKeyHeader,
            String signatureHeader,
            byte[] rawBody,
            String expectedApiKey,
            String hmacSecret
    ) {
        String expKey = expectedApiKey == null ? "" : expectedApiKey.trim();
        String actKey = apiKeyHeader == null ? "" : apiKeyHeader.trim();
        if (expKey.isEmpty() || actKey.isEmpty() || !MessageDigest.isEqual(
                actKey.getBytes(StandardCharsets.UTF_8),
                expKey.getBytes(StandardCharsets.UTF_8)
        )) {
            return StatusCode.SC_AUTHENTICATION_FAILED;
        }
        if (!verifySignature(rawBody, signatureHeader, hmacSecret)) {
            return StatusCode.SC_INVALID_SIGNATURE;
        }
        return StatusCode.SC_OK;
    }

    // ── 2. Arbitrary-Precision Decimal <-> Ledger Units (BigInteger) ────────

    public static BigInteger decimalToLedgerUnits(String raw, int displayExponent, boolean allowNegative) {
        if (displayExponent < 0 || displayExponent > 18) {
            throw new SdkException("INVALID_DISPLAY_EXPONENT", "displayExponent out of range: " + displayExponent);
        }
        if (raw == null) throw new SdkException("INVALID_DECIMAL_AMOUNT", "null decimal amount");
        String text = raw.trim();
        Matcher m = DECIMAL_RE.matcher(text);
        if (!m.matches()) {
            throw new SdkException("INVALID_DECIMAL_AMOUNT", "malformed decimal amount: " + raw);
        }
        boolean negative = "-".equals(m.group(1));
        String wholePart = m.group(2);
        String rawFrac = m.group(3) == null ? "" : m.group(3);
        int scaleDigits = displayExponent + 3;
        String trimmedFrac = rawFrac.replaceFirst("0+$", "");
        if (trimmedFrac.length() > scaleDigits) {
            throw new SdkException("DECIMAL_PRECISION_EXCEEDED", "decimal precision exceeded");
        }
        String fracPadded = trimmedFrac + "0".repeat(scaleDigits - trimmedFrac.length());
        BigInteger divisor = BigInteger.TEN.pow(scaleDigits);
        BigInteger abs = new BigInteger(wholePart).multiply(divisor)
                .add(fracPadded.isEmpty() ? BigInteger.ZERO : new BigInteger(fracPadded));
        if (negative && abs.signum() > 0) {
            if (!allowNegative) {
                throw new SdkException("NEGATIVE_DECIMAL_FORBIDDEN", "negative decimal amount forbidden");
            }
            return abs.negate();
        }
        return abs;
    }

    public static String ledgerUnitsToDecimal(BigInteger amount, int displayExponent) {
        if (displayExponent < 0 || displayExponent > 18) {
            throw new SdkException("INVALID_DISPLAY_EXPONENT", "displayExponent out of range: " + displayExponent);
        }
        BigInteger val = amount == null ? BigInteger.ZERO : amount;
        boolean negative = val.signum() < 0;
        BigInteger abs = val.abs();
        int scaleDigits = displayExponent + 3;
        BigInteger divisor = BigInteger.TEN.pow(scaleDigits);
        BigInteger[] qr = abs.divideAndRemainder(divisor);
        BigInteger whole = qr[0];
        BigInteger frac = qr[1];
        String sign = negative ? "-" : "";
        if (displayExponent == 0) {
            if (frac.signum() == 0) return sign + whole;
            String fs = frac.toString();
            if (fs.length() < 3) fs = "0".repeat(3 - fs.length()) + fs;
            return sign + whole + "." + fs.replaceFirst("0+$", "");
        }
        String fs = frac.toString();
        if (fs.length() < scaleDigits) fs = "0".repeat(scaleDigits - fs.length()) + fs;
        String shown = fs.substring(0, displayExponent);
        String sub = fs.substring(displayExponent).replaceFirst("0+$", "");
        return sign + whole + "." + shown + sub;
    }

    // ── 3. Canonical Idempotency Fingerprints ───────────────────────────────

    public static String encodeTupleFingerprint(String domain, List<String> fields) {
        StringBuilder sb = new StringBuilder("v1|").append(domain);
        for (String f : fields) {
            String s = f == null ? "" : f;
            int byteLen = s.getBytes(StandardCharsets.UTF_8).length;
            sb.append('|').append(byteLen).append(':').append(s);
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HEX.formatHex(md.digest(sb.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new SdkException("CRYPTO_ERROR", e.getMessage());
        }
    }

    private static String str(Map<String, Object> m, String k) {
        if (m == null) return "";
        Object v = m.get(k);
        return v == null ? "" : String.valueOf(v);
    }

    private static long requireLong(Map<String, Object> m, String k) {
        if (m == null) throw new SdkException("INVALID_ARGUMENT", k + " is required");
        Object v = m.get(k);
        if (v instanceof Integer || v instanceof Long) {
            return ((Number) v).longValue();
        }
        if (v instanceof BigInteger bi) {
            try {
                return bi.longValueExact();
            } catch (ArithmeticException e) {
                throw new SdkException("INVALID_ARGUMENT", k + " is out of 64-bit integer range");
            }
        }
        throw new SdkException("INVALID_ARGUMENT", k + " must be an integer");
    }

    public static String betFingerprint(Map<String, Object> p) {
        return encodeTupleFingerprint("wallet/bet", List.of(
                str(p, "transactionId"), str(p, "username"), str(p, "betId"), str(p, "externalTransactionId"),
                str(p, "roundId"), str(p, "currency"), str(p, "gameCode"), str(p, "amount")
        ));
    }

    public static String betResultFingerprint(Map<String, Object> p) {
        return encodeTupleFingerprint("wallet/bet_result", List.of(
                str(p, "transactionId"), str(p, "username"), str(p, "betId"), str(p, "externalTransactionId"),
                str(p, "roundId"), str(p, "currency"), str(p, "gameCode"), str(p, "betAmount"),
                str(p, "winAmount"), str(p, "effectiveTurnover"), str(p, "winLoss"), str(p, "jackpotAmount"),
                str(p, "resultType"), str(p, "isFreespin"), str(p, "isEndRound"), str(p, "betTime")
        ));
    }

    public static String rollbackFingerprint(Map<String, Object> p) {
        return encodeTupleFingerprint("wallet/rollback", List.of(
                str(p, "transactionId"), str(p, "username"), str(p, "betId"), str(p, "externalTransactionId"),
                str(p, "roundId"), str(p, "currency"), str(p, "gameCode"), str(p, "amount")
        ));
    }

    public static String adjustmentFingerprint(Map<String, Object> p) {
        return encodeTupleFingerprint("wallet/adjustment", List.of(
                str(p, "transactionId"), str(p, "username"), str(p, "betId"), str(p, "externalTransactionId"),
                str(p, "roundId"), str(p, "currency"), str(p, "gameCode"), str(p, "direction"),
                str(p, "amount"), str(p, "reasonCode")
        ));
    }

    // ── 4. Config & S2S Client (/operator/v1/*) ─────────────────────────────

    public static final class Config {
        public final String apiKey;
        public final String hmacSecret;
        public final Environment environment;
        public final String baseUrl;
        public final int timeoutMs;
        public final boolean sendTimestamp;

        public Config(String apiKey, String hmacSecret, Environment environment, String baseUrl, int timeoutMs) {
            this(apiKey, hmacSecret, environment, baseUrl, timeoutMs, false);
        }

        public Config(String apiKey, String hmacSecret, Environment environment, String baseUrl, int timeoutMs, boolean sendTimestamp) {
            String k = apiKey == null ? "" : apiKey.trim();
            if (k.isEmpty()) throw new SdkException("INVALID_CONFIG", "apiKey is required");
            if (hmacSecret == null || hmacSecret.isEmpty()) throw new SdkException("INVALID_CONFIG", "hmacSecret is required");
            Environment env = environment == null ? Environment.PRODUCTION : environment;
            String resolved = baseUrl == null ? "" : baseUrl.trim();
            if (resolved.isEmpty()) {
                if (env == Environment.SANDBOX) resolved = SANDBOX_BASE_URL;
                else throw new SdkException("INVALID_CONFIG", "baseUrl is required when environment is PRODUCTION");
            }
            String low = resolved.toLowerCase(Locale.ROOT);
            if (!low.startsWith("http://") && !low.startsWith("https://")) {
                throw new SdkException("INVALID_CONFIG", "baseUrl must start with http:// or https://");
            }
            if (timeoutMs <= 0) throw new SdkException("INVALID_CONFIG", "timeoutMs must be positive");
            this.apiKey = k;
            this.hmacSecret = hmacSecret;
            this.environment = env;
            this.baseUrl = resolved.replaceAll("/+$", "");
            this.timeoutMs = timeoutMs;
            this.sendTimestamp = sendTimestamp;
        }
    }

    public static final class Client {
        private final Config config;
        private final HttpClient httpClient;

        public Client(Config config) {
            if (config == null) throw new SdkException("INVALID_CONFIG", "config is required");
            this.config = config;
            this.httpClient = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofMillis(Math.min(config.timeoutMs, 5000)))
                    .build();
        }

        private static String fallbackStatusForHttp(int httpStatus) {
            if (httpStatus == 429) return StatusCode.SC_RATE_LIMITED;
            if (httpStatus >= 500 || httpStatus == 408) return StatusCode.SC_OPERATOR_TIMEOUT;
            return StatusCode.SC_INVALID_REQUEST;
        }

        private static final class BoundedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
            private final int maxBytes;
            private final ByteArrayOutputStream out = new ByteArrayOutputStream(1024);
            private final CompletableFuture<byte[]> body = new CompletableFuture<>();
            private volatile Flow.Subscription subscription;
            private long totalBytes = 0L;
            private volatile boolean failed = false;

            BoundedBodySubscriber(int maxBytes) {
                this.maxBytes = maxBytes;
            }

            void cancel() {
                failed = true;
                Flow.Subscription sub = this.subscription;
                if (sub != null) {
                    sub.cancel();
                }
                body.cancel(true);
            }

            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                if (failed || this.subscription != null) {
                    subscription.cancel();
                    return;
                }
                this.subscription = subscription;
                if (failed) {
                    subscription.cancel();
                    return;
                }
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(List<ByteBuffer> items) {
                if (failed || items == null) return;
                for (ByteBuffer buf : items) {
                    int rem = buf.remaining();
                    if (rem == 0) continue;
                    if (totalBytes + rem > maxBytes) {
                        failed = true;
                        Flow.Subscription sub = this.subscription;
                        if (sub != null) {
                            sub.cancel();
                        }
                        body.completeExceptionally(
                                new SdkException(StatusCode.SC_INVALID_REQUEST, "Gateway response exceeded 16 MiB limit")
                        );
                        return;
                    }
                    totalBytes += rem;
                    if (buf.hasArray()) {
                        out.write(buf.array(), buf.arrayOffset() + buf.position(), rem);
                        buf.position(buf.limit());
                    } else {
                        byte[] tmp = new byte[rem];
                        buf.get(tmp);
                        out.write(tmp, 0, rem);
                    }
                }
            }

            @Override
            public void onError(Throwable throwable) {
                if (!failed) {
                    failed = true;
                    body.completeExceptionally(throwable);
                }
            }

            @Override
            public void onComplete() {
                if (!failed) {
                    body.complete(out.toByteArray());
                }
            }

            @Override
            public CompletionStage<byte[]> getBody() {
                return body;
            }
        }

        private static SdkException unwrapSdkException(Throwable t) {
            Throwable cur = t;
            int depth = 0;
            while (cur != null && depth < 16) {
                if (cur instanceof SdkException se) {
                    return se;
                }
                cur = cur.getCause();
                depth++;
            }
            return null;
        }

        @SuppressWarnings("unchecked")
        public Map<String, Object> postSigned(String routePath, Map<String, Object> input) {
            Map<String, Object> payload = new LinkedHashMap<>();
            String traceId = input != null && input.get("traceId") != null ? String.valueOf(input.get("traceId")).trim() : "";
            if (traceId.isEmpty()) traceId = UUID.randomUUID().toString();
            payload.put("traceId", traceId);
            if (input != null) payload.putAll(input);
            payload.put("traceId", traceId);

            byte[] rawBytes = JsonCodec.stringify(payload).getBytes(StandardCharsets.UTF_8);
            String sig = signBody(rawBytes, config.hmacSecret);

            HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(config.baseUrl + routePath))
                    .timeout(Duration.ofMillis(config.timeoutMs))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("X-API-Key", config.apiKey)
                    .header("X-Signature", sig);
            if (config.sendTimestamp) {
                reqBuilder.header("X-Timestamp", String.valueOf(System.currentTimeMillis()));
            }
            HttpRequest req = reqBuilder
                    .POST(HttpRequest.BodyPublishers.ofByteArray(rawBytes))
                    .build();

            int statusCode;
            String responseBody;
            AtomicBoolean cancelled = new AtomicBoolean(false);
            AtomicReference<BoundedBodySubscriber> activeSub = new AtomicReference<>();
            HttpResponse.BodyHandler<byte[]> boundedHandler = responseInfo -> {
                BoundedBodySubscriber sub = new BoundedBodySubscriber(MAX_HTTP_RESPONSE_BYTES);
                activeSub.set(sub);
                if (cancelled.get()) {
                    sub.cancel();
                }
                return sub;
            };
            CompletableFuture<HttpResponse<byte[]>> cf = httpClient.sendAsync(req, boundedHandler);
            try {
                HttpResponse<byte[]> resp = cf.get(config.timeoutMs, TimeUnit.MILLISECONDS);
                statusCode = resp.statusCode();
                byte[] respBytes = resp.body();
                responseBody = respBytes == null ? "" : new String(respBytes, StandardCharsets.UTF_8);
            } catch (TimeoutException e) {
                cancelled.set(true);
                BoundedBodySubscriber sub = activeSub.get();
                if (sub != null) {
                    sub.cancel();
                }
                cf.cancel(true);
                throw new SdkException(StatusCode.SC_OPERATOR_TIMEOUT, "Request timed out after " + config.timeoutMs + "ms");
            } catch (InterruptedException e) {
                cancelled.set(true);
                BoundedBodySubscriber sub = activeSub.get();
                if (sub != null) {
                    sub.cancel();
                }
                cf.cancel(true);
                Thread.currentThread().interrupt();
                throw new SdkException(StatusCode.SC_OPERATOR_TIMEOUT, "Request interrupted: " + e.getMessage());
            } catch (Exception e) {
                SdkException cause = unwrapSdkException(e);
                if (cause != null) {
                    throw cause;
                }
                throw new SdkException(StatusCode.SC_OPERATOR_TIMEOUT, "Network error: " + e.getMessage());
            }

            Map<String, Object> parsed;
            try {
                parsed = JsonCodec.parseObject(responseBody);
            } catch (Exception e) {
                throw new ApiException(fallbackStatusForHttp(statusCode), "Non-JSON HTTP " + statusCode, traceId, null, statusCode);
            }

            String respStatus = parsed.get("status") instanceof String s ? s.trim() : "";
            String parsedTrace = parsed.get("traceId") instanceof String t ? t.trim() : "";
            String effTrace = parsedTrace.isEmpty() ? traceId : parsedTrace;
            if (statusCode != 200 || !StatusCode.SC_OK.equals(respStatus)) {
                Map<String, String> valMap = null;
                if (parsed.get("validation") instanceof Map<?, ?> vm) {
                    valMap = new LinkedHashMap<>();
                    for (Map.Entry<?, ?> e : vm.entrySet()) {
                        valMap.put(String.valueOf(e.getKey()), String.valueOf(e.getValue()));
                    }
                }
                throw new ApiException(
                        respStatus.isEmpty() ? fallbackStatusForHttp(statusCode) : respStatus,
                        str(parsed, "message"),
                        effTrace,
                        valMap,
                        statusCode
                );
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("traceId", effTrace);
            out.put("status", StatusCode.SC_OK);
            out.put("data", parsed.get("data"));
            return out;
        }

        public Map<String, Object> ping(Map<String, Object> params) {
            return postSigned("/operator/v1/ping", params);
        }

        public Map<String, Object> createGameUrl(Map<String, Object> params) {
            return postSigned("/operator/v1/game/url", params);
        }

        public Map<String, Object> listTables(Map<String, Object> params) {
            return postSigned("/operator/v1/game/tables", params);
        }

        public Map<String, Object> terminateSessions(Map<String, Object> params) {
            return postSigned("/operator/v1/game/terminate", params);
        }

        public Map<String, Object> updatePlayerStatus(Map<String, Object> params) {
            return postSigned("/operator/v1/player/status", params);
        }

        public Map<String, Object> updatePlayerLimits(Map<String, Object> params) {
            return postSigned("/operator/v1/player/limits", params);
        }

        public Map<String, Object> listTransactions(Map<String, Object> params) {
            long from = requireLong(params, "fromTime");
            long to = requireLong(params, "toTime");
            if (from < 0 || to < from) throw new SdkException("INVALID_ARGUMENT", "Invalid [fromTime, toTime]");
            return postSigned("/operator/v1/transaction/list", params);
        }

        public List<Map<String, Object>> listAllTransactions(long fromTime, long toTime, int pageSize) {
            return listAllTransactions(fromTime, toTime, pageSize, Map.of(), 3, 1000L);
        }

        @SuppressWarnings("unchecked")
        public List<Map<String, Object>> listAllTransactions(
                long fromTime,
                long toTime,
                int pageSize,
                Map<String, Object> filters,
                int rateLimitMaxRetries,
                long rateLimitBackoffMs
        ) {
            if (pageSize < 1 || pageSize > MAX_PAGE_SIZE) {
                throw new SdkException("INVALID_ARGUMENT", "pageSize must be in 1.." + MAX_PAGE_SIZE);
            }
            int maxRetries = Math.max(0, rateLimitMaxRetries);
            long backoffMs = Math.max(0L, rateLimitBackoffMs);
            List<Map<String, Object>> all = new ArrayList<>();
            int pageNo = 1;
            while (true) {
                Map<String, Object> p = new LinkedHashMap<>();
                if (filters != null) p.putAll(filters);
                p.remove("traceId");
                p.put("fromTime", fromTime);
                p.put("toTime", toTime);
                p.put("pageNo", pageNo);
                p.put("pageSize", pageSize);
                Map<String, Object> res;
                int attempt = 0;
                while (true) {
                    try {
                        res = listTransactions(p);
                        break;
                    } catch (ApiException e) {
                        if (StatusCode.SC_RATE_LIMITED.equals(e.status) && attempt < maxRetries) {
                            attempt++;
                            long waitMs = backoffMs * attempt;
                            if (waitMs > 0L) {
                                try {
                                    Thread.sleep(waitMs);
                                } catch (InterruptedException ie) {
                                    Thread.currentThread().interrupt();
                                    throw new SdkException(StatusCode.SC_OPERATOR_TIMEOUT, "Interrupted during rate-limit backoff");
                                }
                            }
                            continue;
                        }
                        throw e;
                    }
                }
                Map<String, Object> data = res.get("data") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
                List<Map<String, Object>> rows = data.get("transactions") instanceof List<?> l
                        ? (List<Map<String, Object>>) l
                        : List.of();
                all.addAll(rows);
                int total = data.get("total") instanceof Number n ? n.intValue() : all.size();
                if (all.size() >= total || rows.isEmpty()) break;
                pageNo++;
            }
            return all;
        }

        public Map<String, Object> getTransactionDetail(Map<String, Object> params) {
            String betId = str(params, "betId").trim();
            if (betId.isEmpty()) {
                throw new SdkException("INVALID_ARGUMENT", "betId is required");
            }
            if (params != null && (params.containsKey("fromTime") || params.containsKey("toTime"))) {
                long from = requireLong(params, "fromTime");
                long to = requireLong(params, "toTime");
                if (from < 0 || to < from || (to - from) > MAX_DETAIL_WINDOW_MS) {
                    throw new SdkException("INVALID_ARGUMENT", "Detail window must satisfy 0 <= toTime - fromTime <= 604800000");
                }
            }
            return postSigned("/operator/v1/transaction/detail", params);
        }

        public Map<String, Object> listUnsettledTransactions(Map<String, Object> params) {
            if (params != null && (params.containsKey("fromTime") || params.containsKey("toTime"))) {
                long from = requireLong(params, "fromTime");
                long to = requireLong(params, "toTime");
                if (from < 0 || to < from || (to - from) > MAX_DETAIL_WINDOW_MS) {
                    throw new SdkException("INVALID_ARGUMENT", "Unsettled window must satisfy 0 <= toTime - fromTime <= 604800000");
                }
            }
            return postSigned("/operator/v1/transaction/unsettled", params);
        }

        public Map<String, Object> getWalletTransactionStatus(Map<String, Object> params) {
            String txId = str(params, "transactionId").trim();
            String betId = str(params, "betId").trim();
            String username = str(params, "username").trim();
            if (txId.isEmpty() && betId.isEmpty() && username.isEmpty()) {
                throw new SdkException("INVALID_ARGUMENT", "At least one of transactionId, betId, or username is required");
            }
            boolean userOnly = !username.isEmpty() && txId.isEmpty() && betId.isEmpty();
            boolean hasWindow = params != null && (params.containsKey("fromTime") || params.containsKey("toTime"));
            if (userOnly || hasWindow) {
                long from = requireLong(params, "fromTime");
                long to = requireLong(params, "toTime");
                if (from < 0 || to < from || (userOnly && (to - from) > 86_400_000L)) {
                    throw new SdkException(
                            "INVALID_ARGUMENT",
                            userOnly
                                    ? "Username query window must satisfy 0 <= toTime - fromTime <= 86400000 (24 hours)"
                                    : "Invalid [fromTime, toTime] window"
                    );
                }
            }
            return postSigned("/operator/v1/wallet/transaction-status", params);
        }
    }

    // ── 5. Seamless Wallet Webhook Dispatcher & Thread-Safe InMemoryWallet ──

    public interface WalletHandler {
        Map<String, Object> onBalance(Map<String, Object> req);
        Map<String, Object> onBet(Map<String, Object> req);
        Map<String, Object> onBetResult(Map<String, Object> req);
        Map<String, Object> onRollback(Map<String, Object> req);
        default Map<String, Object> onAdjustment(Map<String, Object> req) {
            return makeErrEnvelope(str(req, "traceId"), StatusCode.SC_INVALID_REQUEST, "onAdjustment not implemented");
        }
    }

    private static final Pattern NON_NEGATIVE_DECIMAL_RE = Pattern.compile("\\A[0-9]+(?:\\.[0-9]+)?\\z");

    public static Map<String, Object> walletOk(String traceId, String username, String currency, String balance) {
        return walletOk(traceId, username, currency, balance, System.currentTimeMillis());
    }

    public static Map<String, Object> walletOk(String traceId, String username, String currency, String balance, long timestamp) {
        if (balance == null || !NON_NEGATIVE_DECIMAL_RE.matcher(balance).matches()) {
            throw new SdkException(
                    "INVALID_ARGUMENT",
                    "walletOk balance must be a non-empty non-negative decimal string matching ^\\d+(?:\\.\\d+)?$"
            );
        }
        long ts = timestamp > 0L ? timestamp : System.currentTimeMillis();
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("username", username == null ? "" : username);
        data.put("currency", currency == null ? "" : currency);
        data.put("balance", balance);
        data.put("timestamp", ts);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("traceId", traceId == null ? "" : traceId);
        r.put("status", StatusCode.SC_OK);
        r.put("data", data);
        return r;
    }

    public static Map<String, Object> walletError(String traceId, String status, String message) {
        String st = status == null ? "" : status.trim();
        if (!StatusCode.isValidErrorCode(st)) {
            throw new SdkException(
                    "INVALID_ARGUMENT",
                    "walletError status must be a valid non-SC_OK operator error StatusCode"
            );
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("traceId", traceId == null ? "" : traceId);
        r.put("status", st);
        if (message != null && !message.isEmpty()) {
            r.put("message", message);
        }
        return r;
    }

    private static Map<String, Object> makeErrEnvelope(String traceId, String status, String msg) {
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("traceId", traceId == null ? "" : traceId);
        r.put("status", status);
        r.put("message", msg);
        return r;
    }

    public static final class InMemoryWallet implements WalletHandler {
        private static final class Acct {
            final String currency;
            final int exponent;
            BigInteger units;
            final Set<String> tokens = new HashSet<>();
            boolean disabled;

            Acct(String currency, int exponent, BigInteger units) {
                this.currency = currency;
                this.exponent = exponent;
                this.units = units;
            }
        }

        private record TxRec(String type, String fp, boolean empty) {}

        private static final class BetRec {
            final String txId;
            final String username;
            final String currency;
            final BigInteger stake;
            String state = "DEDUCTED";

            BetRec(String txId, String username, String currency, BigInteger stake) {
                this.txId = txId;
                this.username = username;
                this.currency = currency;
                this.stake = stake;
            }
        }

        private final Map<String, Acct> accounts = new HashMap<>();
        private final Map<String, TxRec> transactions = new HashMap<>();
        private final Map<String, BetRec> deductedBets = new HashMap<>();

        public synchronized void addAccount(String username, String currency, String balance, int exponent, List<String> tokens) {
            Acct a = new Acct(currency.trim().toUpperCase(Locale.ROOT), exponent, decimalToLedgerUnits(balance, exponent, false));
            if (tokens != null) a.tokens.addAll(tokens);
            accounts.put(username, a);
        }

        public synchronized void setDisabled(String username, boolean disabled) {
            Acct a = accounts.get(username);
            if (a != null) a.disabled = disabled;
        }

        private Map<String, Object> okResp(String traceId, String username, Acct a) {
            return walletOk(traceId, username, a.currency, ledgerUnitsToDecimal(a.units, a.exponent));
        }

        @Override
        public synchronized Map<String, Object> onBalance(Map<String, Object> req) {
            String traceId = str(req, "traceId");
            String username = str(req, "username").trim();
            String currency = str(req, "currency").trim().toUpperCase(Locale.ROOT);
            if (username.isEmpty() || currency.isEmpty()) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "username and currency are required");
            }
            Acct a = accounts.get(username);
            if (a == null) return makeErrEnvelope(traceId, StatusCode.SC_USER_NOT_EXISTS, "User not exists");
            if (!a.currency.equals(currency)) return makeErrEnvelope(traceId, StatusCode.SC_WRONG_CURRENCY, "Wrong currency");
            if (a.disabled) return makeErrEnvelope(traceId, StatusCode.SC_USER_DISABLED, "User disabled");
            if (!a.tokens.isEmpty() && !a.tokens.contains(str(req, "token"))) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_TOKEN, "Invalid token");
            }
            return okResp(traceId, username, a);
        }

        @Override
        public synchronized Map<String, Object> onBet(Map<String, Object> req) {
            String traceId = str(req, "traceId");
            String txId = str(req, "transactionId").trim();
            String betId = str(req, "betId").trim();
            String username = str(req, "username").trim();
            String currency = str(req, "currency").trim().toUpperCase(Locale.ROOT);
            if (txId.isEmpty() || betId.isEmpty() || username.isEmpty() || currency.isEmpty() || str(req, "amount").isEmpty()) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Missing required bet fields");
            }
            Acct a = accounts.get(username);
            if (a == null) return makeErrEnvelope(traceId, StatusCode.SC_USER_NOT_EXISTS, "User not exists");
            if (!a.currency.equals(currency)) return makeErrEnvelope(traceId, StatusCode.SC_WRONG_CURRENCY, "Wrong currency");

            String fp = betFingerprint(req);
            TxRec prior = transactions.get(txId);
            if (prior != null) {
                if (!"BET".equals(prior.type) || !prior.fp.equals(fp)) {
                    return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_DUPLICATED, "Conflict");
                }
                return okResp(traceId, username, a);
            }
            if (deductedBets.containsKey(betId)) {
                return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_DUPLICATED, "Duplicate betId");
            }
            if (a.disabled) return makeErrEnvelope(traceId, StatusCode.SC_USER_DISABLED, "User disabled");
            if (!a.tokens.isEmpty() && !a.tokens.contains(str(req, "token"))) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_TOKEN, "Invalid token");
            }
            BigInteger stake = decimalToLedgerUnits(str(req, "amount"), a.exponent, false);
            if (stake.signum() <= 0) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Bet amount must be positive");
            }
            if (a.units.compareTo(stake) < 0) {
                return makeErrEnvelope(traceId, StatusCode.SC_INSUFFICIENT_FUNDS, "Insufficient funds");
            }
            a.units = a.units.subtract(stake);
            transactions.put(txId, new TxRec("BET", fp, false));
            deductedBets.put(betId, new BetRec(txId, username, a.currency, stake));
            return okResp(traceId, username, a);
        }

        @Override
        public synchronized Map<String, Object> onBetResult(Map<String, Object> req) {
            String traceId = str(req, "traceId");
            String txId = str(req, "transactionId").trim();
            String betId = str(req, "betId").trim();
            String username = str(req, "username").trim();
            String currency = str(req, "currency").trim().toUpperCase(Locale.ROOT);
            if (txId.isEmpty() || betId.isEmpty() || username.isEmpty() || currency.isEmpty()
                    || str(req, "winAmount").isEmpty() || str(req, "betAmount").isEmpty()) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Missing required bet_result fields");
            }
            Acct a = accounts.get(username);
            if (a == null) return makeErrEnvelope(traceId, StatusCode.SC_USER_NOT_EXISTS, "User not exists");
            if (!a.currency.equals(currency)) return makeErrEnvelope(traceId, StatusCode.SC_WRONG_CURRENCY, "Wrong currency");

            String fp = betResultFingerprint(req);
            TxRec prior = transactions.get(txId);
            if (prior != null) {
                if (!"SETTLE".equals(prior.type) || !prior.fp.equals(fp)) {
                    return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_DUPLICATED, "Conflict");
                }
                return okResp(traceId, username, a);
            }
            BetRec orig = deductedBets.get(betId);
            if (orig == null) {
                return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_NOT_EXISTS, "Original betId missing");
            }
            BigInteger betAmt = decimalToLedgerUnits(str(req, "betAmount"), a.exponent, false);
            BigInteger win = decimalToLedgerUnits(str(req, "winAmount"), a.exponent, false);
            if (!orig.username.equals(username) || !orig.currency.equals(a.currency) || !orig.stake.equals(betAmt)) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "bet_result mismatch");
            }
            if (!"DEDUCTED".equals(orig.state)) {
                return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_DUPLICATED, "betId already finalized");
            }
            a.units = a.units.add(win);
            orig.state = "SETTLED";
            transactions.put(txId, new TxRec("SETTLE", fp, false));
            return okResp(traceId, username, a);
        }

        @Override
        public synchronized Map<String, Object> onRollback(Map<String, Object> req) {
            String traceId = str(req, "traceId");
            String txId = str(req, "transactionId").trim();
            String betId = str(req, "betId").trim();
            String username = str(req, "username").trim();
            String currency = str(req, "currency").trim().toUpperCase(Locale.ROOT);
            if (txId.isEmpty() || betId.isEmpty() || username.isEmpty() || currency.isEmpty() || str(req, "amount").isEmpty()) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Missing required rollback fields");
            }
            Acct a = accounts.get(username);
            if (a == null) return makeErrEnvelope(traceId, StatusCode.SC_USER_NOT_EXISTS, "User not exists");
            if (!a.currency.equals(currency)) return makeErrEnvelope(traceId, StatusCode.SC_WRONG_CURRENCY, "Wrong currency");

            String fp = rollbackFingerprint(req);
            TxRec prior = transactions.get(txId);
            if (prior != null) {
                if (!"ROLLBACK".equals(prior.type) || !prior.fp.equals(fp)) {
                    return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_DUPLICATED, "Conflict");
                }
                if (prior.empty) return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_NOT_EXISTS, "Never deducted");
                return okResp(traceId, username, a);
            }
            BigInteger refund = decimalToLedgerUnits(str(req, "amount"), a.exponent, false);
            if (refund.signum() <= 0) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Rollback amount must be positive");
            }
            BetRec orig = deductedBets.get(betId);
            if (orig == null) {
                transactions.put(txId, new TxRec("ROLLBACK", fp, true));
                return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_NOT_EXISTS, "Never deducted");
            }
            if (!orig.username.equals(username) || !orig.currency.equals(a.currency) || !orig.stake.equals(refund)) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Rollback mismatch");
            }
            if (!"DEDUCTED".equals(orig.state)) {
                return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_DUPLICATED, "betId already finalized");
            }
            a.units = a.units.add(refund);
            orig.state = "ROLLED_BACK";
            transactions.put(txId, new TxRec("ROLLBACK", fp, false));
            return okResp(traceId, username, a);
        }

        @Override
        public synchronized Map<String, Object> onAdjustment(Map<String, Object> req) {
            String traceId = str(req, "traceId");
            String txId = str(req, "transactionId").trim();
            String betId = str(req, "betId").trim();
            String username = str(req, "username").trim();
            String currency = str(req, "currency").trim().toUpperCase(Locale.ROOT);
            String direction = str(req, "direction").trim().toUpperCase(Locale.ROOT);
            String reasonCode = str(req, "reasonCode").trim();
            if (txId.isEmpty() || betId.isEmpty() || username.isEmpty() || currency.isEmpty()
                    || reasonCode.isEmpty() || str(req, "amount").isEmpty()
                    || (!"CREDIT".equals(direction) && !"DEBIT".equals(direction))) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Missing or invalid adjustment fields");
            }
            Acct a = accounts.get(username);
            if (a == null) return makeErrEnvelope(traceId, StatusCode.SC_USER_NOT_EXISTS, "User not exists");
            if (!a.currency.equals(currency)) return makeErrEnvelope(traceId, StatusCode.SC_WRONG_CURRENCY, "Wrong currency");

            String fp = adjustmentFingerprint(req);
            TxRec prior = transactions.get(txId);
            if (prior != null) {
                if (!"ADJUSTMENT".equals(prior.type) || !prior.fp.equals(fp)) {
                    return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_DUPLICATED, "Conflict");
                }
                return okResp(traceId, username, a);
            }
            BetRec orig = deductedBets.get(betId);
            if (orig == null) {
                return makeErrEnvelope(traceId, StatusCode.SC_TRANSACTION_NOT_EXISTS, "Original betId missing");
            }
            if (!orig.username.equals(username) || !orig.currency.equals(a.currency)) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Adjustment mismatch");
            }
            BigInteger adjUnits = decimalToLedgerUnits(str(req, "amount"), a.exponent, false);
            if (adjUnits.signum() <= 0) {
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Adjustment amount must be positive");
            }
            if ("DEBIT".equals(direction)) {
                if (a.units.compareTo(adjUnits) < 0) {
                    return makeErrEnvelope(traceId, StatusCode.SC_INSUFFICIENT_FUNDS, "Insufficient funds");
                }
                a.units = a.units.subtract(adjUnits);
            } else {
                a.units = a.units.add(adjUnits);
            }
            transactions.put(txId, new TxRec("ADJUSTMENT", fp, false));
            return okResp(traceId, username, a);
        }
    }

    private static String extractTraceHint(byte[] rawBody) {
        if (rawBody == null || rawBody.length == 0) return "";
        int len = Math.min(rawBody.length, 1024);
        String head = new String(rawBody, 0, len, StandardCharsets.UTF_8);
        Matcher m = TRACE_HINT_RE.matcher(head);
        return m.find() ? m.group(1) : "";
    }

    private static final Set<String> INCOMING_DECIMAL_ERROR_CODES = Set.of(
            "INVALID_DECIMAL_AMOUNT",
            "DECIMAL_PRECISION_EXCEEDED",
            "NEGATIVE_DECIMAL_FORBIDDEN"
    );

    public static final class WebhookDispatcher {
        private final String apiKey;
        private final String hmacSecret;
        private final WalletHandler wallet;

        public WebhookDispatcher(Config config, WalletHandler wallet) {
            if (config == null || wallet == null) {
                throw new SdkException("INVALID_CONFIG", "config and wallet handler are required");
            }
            this.apiKey = config.apiKey;
            this.hmacSecret = config.hmacSecret;
            this.wallet = wallet;
        }

        public WebhookDispatcher(String apiKey, String hmacSecret, WalletHandler wallet) {
            String k = apiKey == null ? "" : apiKey.trim();
            if (k.isEmpty() || hmacSecret == null || hmacSecret.isEmpty() || wallet == null) {
                throw new SdkException("INVALID_CONFIG", "apiKey, hmacSecret, and wallet handler are required");
            }
            this.apiKey = k;
            this.hmacSecret = hmacSecret;
            this.wallet = wallet;
        }

        public Map<String, Object> handle(String routePath, String apiKeyHeader, String signatureHeader, byte[] rawBody) {
            byte[] safeBody = rawBody == null ? new byte[0] : rawBody;
            if (safeBody.length > MAX_WEBHOOK_BODY_BYTES) {
                return makeErrEnvelope("", StatusCode.SC_INVALID_REQUEST, "Request body exceeds 1 MiB limit");
            }

            // Verify X-API-Key & X-Signature over raw bytes BEFORE JSON parsing!
            String auth = verifyWebhookHeaders(apiKeyHeader, signatureHeader, safeBody, apiKey, hmacSecret);
            if (!StatusCode.SC_OK.equals(auth)) {
                return makeErrEnvelope(extractTraceHint(safeBody), auth, "Auth/signature failed");
            }

            Map<String, Object> parsed;
            String traceId = "";
            try {
                parsed = JsonCodec.parseObject(new String(safeBody, StandardCharsets.UTF_8));
                traceId = str(parsed, "traceId").trim();
                if (traceId.length() > 128) traceId = traceId.substring(0, 128);
            } catch (Exception e) {
                return makeErrEnvelope("", StatusCode.SC_INVALID_REQUEST, "Invalid JSON");
            }

            String clean = (routePath == null ? "" : routePath).split("\\?", 2)[0].replaceAll("/+$", "");
            try {
                if (clean.endsWith("/wallet/balance")) return wallet.onBalance(parsed);
                if (clean.endsWith("/wallet/bet")) return wallet.onBet(parsed);
                if (clean.endsWith("/wallet/bet_result")) return wallet.onBetResult(parsed);
                if (clean.endsWith("/wallet/rollback")) return wallet.onRollback(parsed);
                if (clean.endsWith("/wallet/adjustment")) return wallet.onAdjustment(parsed);
                return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, "Unknown route");
            } catch (SdkException e) {
                if (!(e instanceof ApiException)) {
                    if (StatusCode.isValidErrorCode(e.code)) {
                        return makeErrEnvelope(traceId, e.code, e.getMessage());
                    }
                    if (e.code != null && INCOMING_DECIMAL_ERROR_CODES.contains(e.code)) {
                        return makeErrEnvelope(traceId, StatusCode.SC_INVALID_REQUEST, e.getMessage());
                    }
                }
                return makeErrEnvelope(traceId, StatusCode.SC_OPERATOR_TIMEOUT, "Temporary wallet handler error");
            } catch (Exception e) {
                return makeErrEnvelope(traceId, StatusCode.SC_OPERATOR_TIMEOUT, "Temporary wallet handler error");
            }
        }
    }
}

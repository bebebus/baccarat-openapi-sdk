// SPDX-License-Identifier: MIT
package cloud.cniia.baccarat.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Zero-dependency RFC-8259 JSON parser and serializer (preserves UTF-8, unescaped slashes, and surrogate pairs).
 */
public final class JsonCodec {
    private final String s;
    private int pos;

    private JsonCodec(String s) {
        this.s = s;
        this.pos = 0;
    }

    public static Object parse(String json) {
        if (json == null) throw new IllegalArgumentException("null JSON input");
        JsonCodec p = new JsonCodec(json);
        p.skipWs();
        Object val = p.readValue();
        p.skipWs();
        if (p.pos != p.s.length()) {
            throw new IllegalArgumentException("Unexpected trailing token at " + p.pos);
        }
        return val;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) {
        Object v = parse(json);
        if (!(v instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("Expected JSON object");
        }
        return (Map<String, Object>) v;
    }

    public static String stringify(Object val) {
        StringBuilder sb = new StringBuilder(128);
        writeJson(sb, val);
        return sb.toString();
    }

    private static void writeJson(StringBuilder sb, Object val) {
        if (val == null) {
            sb.append("null");
        } else if (val instanceof Boolean || val instanceof Integer || val instanceof Long) {
            sb.append(val);
        } else if (val instanceof Number n) {
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                throw new IllegalArgumentException("Non-finite number in JSON");
            }
            sb.append(val);
        } else if (val instanceof String str) {
            writeString(sb, str);
        } else if (val instanceof Map<?, ?> map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(':');
                writeJson(sb, e.getValue());
            }
            sb.append('}');
        } else if (val instanceof Iterable<?> list) {
            sb.append('[');
            boolean first = true;
            for (Object item : list) {
                if (!first) sb.append(',');
                first = false;
                writeJson(sb, item);
            }
            sb.append(']');
        } else {
            writeString(sb, String.valueOf(val));
        }
    }

    private static void writeString(StringBuilder sb, String str) {
        sb.append('"');
        for (int i = 0; i < str.length(); i++) {
            char c = str.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    private void skipWs() {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
            else break;
        }
    }

    private Object readValue() {
        skipWs();
        if (pos >= s.length()) throw new IllegalArgumentException("Unexpected end of JSON");
        char c = s.charAt(pos);
        return switch (c) {
            case '{' -> readObject();
            case '[' -> readArray();
            case '"' -> readString();
            case 't' -> readLiteral("true", Boolean.TRUE);
            case 'f' -> readLiteral("false", Boolean.FALSE);
            case 'n' -> readLiteral("null", null);
            default -> {
                if (c == '-' || (c >= '0' && c <= '9')) yield readNumber();
                throw new IllegalArgumentException("Unexpected char '" + c + "' at " + pos);
            }
        };
    }

    private Object readLiteral(String lit, Object val) {
        if (!s.startsWith(lit, pos)) throw new IllegalArgumentException("Expected " + lit + " at " + pos);
        pos += lit.length();
        return val;
    }

    private Map<String, Object> readObject() {
        pos++; // '{'
        Map<String, Object> map = new LinkedHashMap<>();
        skipWs();
        if (pos < s.length() && s.charAt(pos) == '}') {
            pos++;
            return map;
        }
        while (true) {
            skipWs();
            if (pos >= s.length() || s.charAt(pos) != '"') {
                throw new IllegalArgumentException("Expected string key at " + pos);
            }
            String key = readString();
            skipWs();
            if (pos >= s.length() || s.charAt(pos) != ':') {
                throw new IllegalArgumentException("Expected ':' at " + pos);
            }
            pos++;
            Object val = readValue();
            map.put(key, val);
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ',') {
                pos++;
            } else if (pos < s.length() && s.charAt(pos) == '}') {
                pos++;
                return map;
            } else {
                throw new IllegalArgumentException("Expected ',' or '}' at " + pos);
            }
        }
    }

    private List<Object> readArray() {
        pos++; // '['
        List<Object> list = new ArrayList<>();
        skipWs();
        if (pos < s.length() && s.charAt(pos) == ']') {
            pos++;
            return list;
        }
        while (true) {
            list.add(readValue());
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ',') {
                pos++;
            } else if (pos < s.length() && s.charAt(pos) == ']') {
                pos++;
                return list;
            } else {
                throw new IllegalArgumentException("Expected ',' or ']' at " + pos);
            }
        }
    }

    private String readString() {
        pos++; // '"'
        StringBuilder sb = new StringBuilder();
        while (pos < s.length()) {
            char c = s.charAt(pos++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                if (pos >= s.length()) throw new IllegalArgumentException("Unterminated escape");
                char esc = s.charAt(pos++);
                switch (esc) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > s.length()) throw new IllegalArgumentException("Short \\u escape");
                        int cp = Integer.parseInt(s.substring(pos, pos + 4), 16);
                        pos += 4;
                        sb.append((char) cp);
                    }
                    default -> throw new IllegalArgumentException("Invalid escape \\" + esc);
                }
            } else {
                sb.append(c);
            }
        }
        throw new IllegalArgumentException("Unterminated string");
    }

    private Number readNumber() {
        int start = pos;
        if (s.charAt(pos) == '-') pos++;
        while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
        boolean isFloat = false;
        if (pos < s.length() && s.charAt(pos) == '.') {
            isFloat = true;
            pos++;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
        }
        if (pos < s.length() && (s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
            isFloat = true;
            pos++;
            if (pos < s.length() && (s.charAt(pos) == '+' || s.charAt(pos) == '-')) pos++;
            while (pos < s.length() && Character.isDigit(s.charAt(pos))) pos++;
        }
        String raw = s.substring(start, pos);
        if (!isFloat) {
            return Long.parseLong(raw);
        }
        return Double.parseDouble(raw);
    }
}

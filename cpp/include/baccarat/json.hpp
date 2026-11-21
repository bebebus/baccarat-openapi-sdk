// SPDX-License-Identifier: MIT
#pragma once

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace baccarat {

/**
 * Minimal, zero-dependency RFC-8259 JSON Value, Parser & Serializer (preserves insertion order & UTF-8).
 */
class Json {
public:
    enum class Type { Null, Bool, Int, Double, String, Array, Object };
    using Array = std::vector<Json>;
    using Object = std::vector<std::pair<std::string, Json>>;

private:
    Type type_ = Type::Null;
    bool bool_val_ = false;
    int64_t int_val_ = 0;
    double double_val_ = 0.0;
    std::string str_val_;
    Array arr_val_;
    Object obj_val_;

public:
    Json() = default;
    Json(std::nullptr_t) : type_(Type::Null) {}
    Json(bool b) : type_(Type::Bool), bool_val_(b) {}
    Json(int v) : type_(Type::Int), int_val_(v) {}
    Json(int64_t v) : type_(Type::Int), int_val_(v) {}
    Json(double d) : type_(Type::Double), double_val_(d) {}
    Json(const char* s) : type_(Type::String), str_val_(s ? s : "") {}
    Json(std::string s) : type_(Type::String), str_val_(std::move(s)) {}
    Json(Array a) : type_(Type::Array), arr_val_(std::move(a)) {}
    Json(Object o) : type_(Type::Object), obj_val_(std::move(o)) {}

    static Json object() { return Json(Object{}); }
    static Json array() { return Json(Array{}); }

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_bool() const { return type_ == Type::Bool; }
    bool is_int() const { return type_ == Type::Int; }
    bool is_string() const { return type_ == Type::String; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_object() const { return type_ == Type::Object; }

    bool as_bool(bool fallback = false) const { return type_ == Type::Bool ? bool_val_ : fallback; }
    int64_t as_int(int64_t fallback = 0) const {
        if (type_ == Type::Int) return int_val_;
        if (type_ == Type::Double) return static_cast<int64_t>(double_val_);
        return fallback;
    }
    const std::string& as_string() const {
        static const std::string empty;
        return type_ == Type::String ? str_val_ : empty;
    }
    std::string to_scalar_string() const {
        if (type_ == Type::String) return str_val_;
        if (type_ == Type::Int) return std::to_string(int_val_);
        if (type_ == Type::Bool) return bool_val_ ? "true" : "false";
        return "";
    }

    const Array& as_array() const { return arr_val_; }
    Array& as_array_mut() { return arr_val_; }
    const Object& as_object() const { return obj_val_; }

    bool contains(const std::string& key) const {
        if (type_ != Type::Object) return false;
        for (const auto& kv : obj_val_) {
            if (kv.first == key) return true;
        }
        return false;
    }

    const Json& at(const std::string& key) const {
        static const Json null_json;
        if (type_ != Type::Object) return null_json;
        for (const auto& kv : obj_val_) {
            if (kv.first == key) return kv.second;
        }
        return null_json;
    }

    void set(const std::string& key, Json val) {
        if (type_ != Type::Object) {
            type_ = Type::Object;
            obj_val_.clear();
        }
        for (auto& kv : obj_val_) {
            if (kv.first == key) {
                kv.second = std::move(val);
                return;
            }
        }
        obj_val_.emplace_back(key, std::move(val));
    }

    std::string dump() const {
        std::string out;
        write_to(out);
        return out;
    }

    static Json parse(const std::string& src) {
        Parser p(src);
        p.skip_ws();
        Json v = p.read_value();
        p.skip_ws();
        if (p.pos != src.size()) {
            throw std::runtime_error("Trailing characters in JSON");
        }
        return v;
    }

private:
    static void append_escaped(std::string& out, const std::string& s) {
        out.push_back('"');
        for (unsigned char c : s) {
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        char buf[8];
                        std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                        out += buf;
                    } else {
                        out.push_back(static_cast<char>(c));
                    }
            }
        }
        out.push_back('"');
    }

    void write_to(std::string& out) const {
        switch (type_) {
            case Type::Null: out += "null"; break;
            case Type::Bool: out += (bool_val_ ? "true" : "false"); break;
            case Type::Int: out += std::to_string(int_val_); break;
            case Type::Double: {
                char buf[64];
                std::snprintf(buf, sizeof(buf), "%.15g", double_val_);
                out += buf;
                break;
            }
            case Type::String: append_escaped(out, str_val_); break;
            case Type::Array:
                out.push_back('[');
                for (size_t i = 0; i < arr_val_.size(); ++i) {
                    if (i > 0) out.push_back(',');
                    arr_val_[i].write_to(out);
                }
                out.push_back(']');
                break;
            case Type::Object:
                out.push_back('{');
                for (size_t i = 0; i < obj_val_.size(); ++i) {
                    if (i > 0) out.push_back(',');
                    append_escaped(out, obj_val_[i].first);
                    out.push_back(':');
                    obj_val_[i].second.write_to(out);
                }
                out.push_back('}');
                break;
        }
    }

    struct Parser {
        const std::string& s;
        size_t pos = 0;
        explicit Parser(const std::string& src) : s(src) {}

        void skip_ws() {
            while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\n' || s[pos] == '\r')) {
                ++pos;
            }
        }

        Json read_value() {
            skip_ws();
            if (pos >= s.size()) throw std::runtime_error("Unexpected EOF in JSON");
            char c = s[pos];
            if (c == '{') return read_object();
            if (c == '[') return read_array();
            if (c == '"') return Json(read_string());
            if (c == 't') { expect("true"); return Json(true); }
            if (c == 'f') { expect("false"); return Json(false); }
            if (c == 'n') { expect("null"); return Json(nullptr); }
            if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return read_number();
            throw std::runtime_error("Unexpected character in JSON");
        }

        void expect(const char* lit) {
            for (size_t i = 0; lit[i] != '\0'; ++i) {
                if (pos >= s.size() || s[pos] != lit[i]) throw std::runtime_error("Invalid JSON literal");
                ++pos;
            }
        }

        static void append_utf8(std::string& out, uint32_t cp) {
            if (cp <= 0x7F) {
                out.push_back(static_cast<char>(cp));
            } else if (cp <= 0x7FF) {
                out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else if (cp <= 0xFFFF) {
                out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            } else {
                out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
        }

        uint16_t read_hex4() {
            if (pos + 4 > s.size()) throw std::runtime_error("Short \\uXXXX escape");
            uint16_t val = 0;
            for (int i = 0; i < 4; ++i) {
                char c = s[pos++];
                val <<= 4;
                if (c >= '0' && c <= '9') val |= static_cast<uint16_t>(c - '0');
                else if (c >= 'a' && c <= 'f') val |= static_cast<uint16_t>(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') val |= static_cast<uint16_t>(c - 'A' + 10);
                else throw std::runtime_error("Bad hex digit in \\uXXXX");
            }
            return val;
        }

        std::string read_string() {
            ++pos; // '"'
            std::string out;
            while (pos < s.size()) {
                char c = s[pos++];
                if (c == '"') return out;
                if (c == '\\') {
                    if (pos >= s.size()) throw std::runtime_error("Unterminated escape");
                    char e = s[pos++];
                    switch (e) {
                        case '"': out.push_back('"'); break;
                        case '\\': out.push_back('\\'); break;
                        case '/': out.push_back('/'); break;
                        case 'b': out.push_back('\b'); break;
                        case 'f': out.push_back('\f'); break;
                        case 'n': out.push_back('\n'); break;
                        case 'r': out.push_back('\r'); break;
                        case 't': out.push_back('\t'); break;
                        case 'u': {
                            uint32_t cp = read_hex4();
                            if (cp >= 0xD800 && cp <= 0xDBFF && pos + 2 <= s.size() && s[pos] == '\\' && s[pos + 1] == 'u') {
                                pos += 2;
                                uint32_t low = read_hex4();
                                cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
                            }
                            append_utf8(out, cp);
                            break;
                        }
                        default: throw std::runtime_error("Invalid escape sequence");
                    }
                } else {
                    out.push_back(c);
                }
            }
            throw std::runtime_error("Unterminated JSON string");
        }

        Json read_number() {
            size_t start = pos;
            if (s[pos] == '-') ++pos;
            while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) ++pos;
            bool is_float = false;
            if (pos < s.size() && s[pos] == '.') {
                is_float = true;
                ++pos;
                while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) ++pos;
            }
            if (pos < s.size() && (s[pos] == 'e' || s[pos] == 'E')) {
                is_float = true;
                ++pos;
                if (pos < s.size() && (s[pos] == '+' || s[pos] == '-')) ++pos;
                while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) ++pos;
            }
            std::string tok = s.substr(start, pos - start);
            if (!is_float) {
                return Json(static_cast<int64_t>(std::stoll(tok)));
            }
            return Json(std::stod(tok));
        }

        Json read_array() {
            ++pos; // '['
            Array arr;
            skip_ws();
            if (pos < s.size() && s[pos] == ']') { ++pos; return Json(std::move(arr)); }
            while (true) {
                arr.push_back(read_value());
                skip_ws();
                if (pos < s.size() && s[pos] == ',') { ++pos; }
                else if (pos < s.size() && s[pos] == ']') { ++pos; return Json(std::move(arr)); }
                else throw std::runtime_error("Expected ',' or ']'");
            }
        }

        Json read_object() {
            ++pos; // '{'
            Object obj;
            skip_ws();
            if (pos < s.size() && s[pos] == '}') { ++pos; return Json(std::move(obj)); }
            while (true) {
                skip_ws();
                if (pos >= s.size() || s[pos] != '"') throw std::runtime_error("Expected object key");
                std::string k = read_string();
                skip_ws();
                if (pos >= s.size() || s[pos] != ':') throw std::runtime_error("Expected ':'");
                ++pos;
                Json v = read_value();
                obj.emplace_back(std::move(k), std::move(v));
                skip_ws();
                if (pos < s.size() && s[pos] == ',') { ++pos; }
                else if (pos < s.size() && s[pos] == '}') { ++pos; return Json(std::move(obj)); }
                else throw std::runtime_error("Expected ',' or '}'");
            }
        }
    };
};

} // namespace baccarat

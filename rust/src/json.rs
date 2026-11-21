// SPDX-License-Identifier: MIT
#![forbid(unsafe_code)]

use std::fmt::Write;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn object() -> Self {
        Json::Obj(Vec::new())
    }

    pub fn is_object(&self) -> bool {
        matches!(self, Json::Obj(_))
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(v) => Some(*v),
            Json::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    pub fn to_scalar_string(&self) -> String {
        match self {
            Json::Str(s) => s.clone(),
            Json::Int(v) => v.to_string(),
            Json::Bool(b) => b.to_string(),
            _ => String::new(),
        }
    }

    pub fn get(&self, key: &str) -> &Json {
        static NULL: Json = Json::Null;
        if let Json::Obj(entries) = self {
            for (k, v) in entries {
                if k == key {
                    return v;
                }
            }
        }
        &NULL
    }

    pub fn contains(&self, key: &str) -> bool {
        if let Json::Obj(entries) = self {
            entries.iter().any(|(k, _)| k == key)
        } else {
            false
        }
    }

    pub fn set(&mut self, key: impl Into<String>, val: Json) {
        let k = key.into();
        if !matches!(self, Json::Obj(_)) {
            *self = Json::Obj(Vec::new());
        }
        if let Json::Obj(entries) = self {
            for (ek, ev) in entries.iter_mut() {
                if *ek == k {
                    *ev = val;
                    return;
                }
            }
            entries.push((k, val));
        }
    }

    pub fn dump(&self) -> String {
        let mut out = String::new();
        self.write_to(&mut out);
        out
    }

    fn write_escaped(out: &mut String, s: &str) {
        out.push('"');
        for ch in s.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\x08' => out.push_str("\\b"),
                '\x0c' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    let _ = write!(out, "\\u{:04x}", c as u32);
                }
                c => out.push(c),
            }
        }
        out.push('"');
    }

    fn write_to(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(v) => {
                let _ = write!(out, "{}", v);
            }
            Json::Float(f) => {
                let _ = write!(out, "{}", f);
            }
            Json::Str(s) => Self::write_escaped(out, s),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_to(out);
                }
                out.push(']');
            }
            Json::Obj(entries) => {
                out.push('{');
                for (i, (k, v)) in entries.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    Self::write_escaped(out, k);
                    out.push(':');
                    v.write_to(out);
                }
                out.push('}');
            }
        }
    }

    pub fn parse(src: &str) -> Result<Json, String> {
        let mut p = Parser {
            b: src.as_bytes(),
            src,
            pos: 0,
        };
        p.skip_ws();
        let val = p.read_value()?;
        p.skip_ws();
        if p.pos != p.b.len() {
            return Err(format!("trailing JSON bytes at {}", p.pos));
        }
        Ok(val)
    }
}

struct Parser<'a> {
    b: &'a [u8],
    src: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.pos < self.b.len() && matches!(self.b[self.pos], b' ' | b'\t' | b'\n' | b'\r') {
            self.pos += 1;
        }
    }

    fn read_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        if self.pos >= self.b.len() {
            return Err("unexpected EOF".into());
        }
        match self.b[self.pos] {
            b'{' => self.read_object(),
            b'[' => self.read_array(),
            b'"' => Ok(Json::Str(self.read_string()?)),
            b't' => {
                self.expect(b"true")?;
                Ok(Json::Bool(true))
            }
            b'f' => {
                self.expect(b"false")?;
                Ok(Json::Bool(false))
            }
            b'n' => {
                self.expect(b"null")?;
                Ok(Json::Null)
            }
            c if c == b'-' || c.is_ascii_digit() => self.read_number(),
            c => Err(format!("unexpected byte '{}' at {}", c as char, self.pos)),
        }
    }

    fn expect(&mut self, lit: &[u8]) -> Result<(), String> {
        if self.b.get(self.pos..self.pos + lit.len()) != Some(lit) {
            return Err("invalid literal".into());
        }
        self.pos += lit.len();
        Ok(())
    }

    fn read_hex4(&mut self) -> Result<u16, String> {
        if self.pos + 4 > self.b.len() {
            return Err("short \\u escape".into());
        }
        let mut val = 0u16;
        for _ in 0..4 {
            let d = match self.b[self.pos] {
                b'0'..=b'9' => self.b[self.pos] - b'0',
                b'a'..=b'f' => self.b[self.pos] - b'a' + 10,
                b'A'..=b'F' => self.b[self.pos] - b'A' + 10,
                _ => return Err("bad hex digit".into()),
            };
            self.pos += 1;
            val = (val << 4) | (d as u16);
        }
        Ok(val)
    }

    fn read_string(&mut self) -> Result<String, String> {
        self.pos += 1; // '"'
        let mut out = String::new();
        while self.pos < self.b.len() {
            let b0 = self.b[self.pos];
            if b0 == b'"' {
                self.pos += 1;
                return Ok(out);
            }
            if b0 == b'\\' {
                self.pos += 1;
                if self.pos >= self.b.len() {
                    return Err("unterminated escape".into());
                }
                let esc = self.b[self.pos];
                self.pos += 1;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\x08'),
                    b'f' => out.push('\x0c'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hi = self.read_hex4()? as u32;
                        let cp = if (0xD800..=0xDBFF).contains(&hi)
                            && self.b.get(self.pos..self.pos + 2) == Some(b"\\u")
                        {
                            self.pos += 2;
                            let lo = self.read_hex4()? as u32;
                            0x10000 + (((hi - 0xD800) << 10) | (lo - 0xDC00))
                        } else {
                            hi
                        };
                        let ch = char::from_u32(cp).ok_or_else(|| "invalid unicode scalar".to_string())?;
                        out.push(ch);
                    }
                    _ => return Err("invalid escape".into()),
                }
            } else {
                let tail = &self.src[self.pos..];
                let ch = tail.chars().next().ok_or_else(|| "invalid UTF-8".to_string())?;
                self.pos += ch.len_utf8();
                out.push(ch);
            }
        }
        Err("unterminated string".into())
    }

    fn read_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.b[self.pos] == b'-' {
            self.pos += 1;
        }
        while self.pos < self.b.len() && self.b[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let mut is_float = false;
        if self.pos < self.b.len() && self.b[self.pos] == b'.' {
            is_float = true;
            self.pos += 1;
            while self.pos < self.b.len() && self.b[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }
        if self.pos < self.b.len() && matches!(self.b[self.pos], b'e' | b'E') {
            is_float = true;
            self.pos += 1;
            if self.pos < self.b.len() && matches!(self.b[self.pos], b'+' | b'-') {
                self.pos += 1;
            }
            while self.pos < self.b.len() && self.b[self.pos].is_ascii_digit() {
                self.pos += 1;
            }
        }
        let s = &self.src[start..self.pos];
        if !is_float {
            let v = s.parse::<i64>().map_err(|e| e.to_string())?;
            Ok(Json::Int(v))
        } else {
            let f = s.parse::<f64>().map_err(|e| e.to_string())?;
            Ok(Json::Float(f))
        }
    }

    fn read_array(&mut self) -> Result<Json, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.pos < self.b.len() && self.b[self.pos] == b']' {
            self.pos += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.read_value()?);
            self.skip_ws();
            if self.pos < self.b.len() && self.b[self.pos] == b',' {
                self.pos += 1;
            } else if self.pos < self.b.len() && self.b[self.pos] == b']' {
                self.pos += 1;
                return Ok(Json::Arr(items));
            } else {
                return Err("expected ',' or ']'".into());
            }
        }
    }

    fn read_object(&mut self) -> Result<Json, String> {
        self.pos += 1;
        let mut entries = Vec::new();
        self.skip_ws();
        if self.pos < self.b.len() && self.b[self.pos] == b'}' {
            self.pos += 1;
            return Ok(Json::Obj(entries));
        }
        loop {
            self.skip_ws();
            if self.pos >= self.b.len() || self.b[self.pos] != b'"' {
                return Err("expected string key".into());
            }
            let k = self.read_string()?;
            self.skip_ws();
            if self.pos >= self.b.len() || self.b[self.pos] != b':' {
                return Err("expected ':'".into());
            }
            self.pos += 1;
            let v = self.read_value()?;
            entries.push((k, v));
            self.skip_ws();
            if self.pos < self.b.len() && self.b[self.pos] == b',' {
                self.pos += 1;
            } else if self.pos < self.b.len() && self.b[self.pos] == b'}' {
                self.pos += 1;
                return Ok(Json::Obj(entries));
            } else {
                return Err("expected ',' or '}'".into());
            }
        }
    }
}

// SPDX-License-Identifier: MIT
use std::ffi::{c_char, c_long, c_void, CString};
use std::sync::Once;

#[repr(C)]
struct CurlEasy {
    _private: [u8; 0],
}

#[repr(C)]
struct CurlSlist {
    _private: [u8; 0],
}

const CURL_GLOBAL_DEFAULT: c_long = 3;
const CURLOPT_WRITEDATA: i32 = 10001;
const CURLOPT_URL: i32 = 10002;
const CURLOPT_POSTFIELDS: i32 = 10015;
const CURLOPT_HTTPHEADER: i32 = 10023;
const CURLOPT_WRITEFUNCTION: i32 = 20011;
const CURLOPT_POST: i32 = 47;
const CURLOPT_NOSIGNAL: i32 = 99;
const CURLOPT_TIMEOUT_MS: i32 = 155;
const CURLOPT_CONNECTTIMEOUT_MS: i32 = 156;
const CURLOPT_POSTFIELDSIZE_LARGE: i32 = 30120;
const CURLINFO_RESPONSE_CODE: i32 = 0x200002;
const MAX_HTTP_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[link(name = "curl")]
extern "C" {
    fn curl_global_init(flags: c_long) -> i32;
    fn curl_easy_init() -> *mut CurlEasy;
    fn curl_easy_cleanup(handle: *mut CurlEasy);
    fn curl_easy_perform(handle: *mut CurlEasy) -> i32;
    fn curl_easy_setopt(handle: *mut CurlEasy, option: i32, ...) -> i32;
    fn curl_easy_getinfo(handle: *mut CurlEasy, info: i32, ...) -> i32;
    fn curl_slist_append(list: *mut CurlSlist, val: *const c_char) -> *mut CurlSlist;
    fn curl_slist_free_all(list: *mut CurlSlist);
}

static CURL_INIT: Once = Once::new();

struct CurlGuard {
    handle: *mut CurlEasy,
    headers: *mut CurlSlist,
}

impl Drop for CurlGuard {
    fn drop(&mut self) {
        unsafe {
            if !self.headers.is_null() {
                curl_slist_free_all(self.headers);
            }
            if !self.handle.is_null() {
                curl_easy_cleanup(self.handle);
            }
        }
    }
}

extern "C" fn write_callback(ptr: *const u8, size: usize, nmemb: usize, userdata: *mut c_void) -> usize {
    let Some(total) = size.checked_mul(nmemb) else {
        return 0;
    };
    if total == 0 || ptr.is_null() || userdata.is_null() {
        return 0;
    }
    unsafe {
        let buf = &mut *(userdata as *mut Vec<u8>);
        let Some(new_len) = buf.len().checked_add(total) else {
            return 0;
        };
        if new_len > MAX_HTTP_RESPONSE_BYTES || buf.try_reserve(total).is_err() {
            return 0; // signal write failure to libcurl without unwinding across extern "C"
        }
        let slice = std::slice::from_raw_parts(ptr, total);
        buf.extend_from_slice(slice);
    }
    total
}

pub fn libcurl_post_json(
    url: &str,
    api_key: &str,
    signature: &str,
    timestamp: Option<&str>,
    raw_body: &[u8],
    timeout_ms: u64,
) -> Result<(u16, Vec<u8>), String> {
    CURL_INIT.call_once(|| unsafe {
        let _ = curl_global_init(CURL_GLOBAL_DEFAULT);
    });

    let c_url = CString::new(url).map_err(|_| "NUL byte in URL".to_string())?;
    let h_ct = CString::new("Content-Type: application/json").unwrap();
    let h_acc = CString::new("Accept: application/json").unwrap();
    let h_key = CString::new(format!("X-API-Key: {}", api_key)).map_err(|_| "NUL in API key".to_string())?;
    let h_sig = CString::new(format!("X-Signature: {}", signature)).map_err(|_| "NUL in signature".to_string())?;
    let h_ts = match timestamp {
        Some(ts) => Some(CString::new(format!("X-Timestamp: {}", ts)).map_err(|_| "NUL in timestamp".to_string())?),
        None => None,
    };

    let clamped_timeout = timeout_ms.min(i32::MAX as u64) as c_long;
    let clamped_connect = timeout_ms.min(5000) as c_long;
    let body_len = i64::try_from(raw_body.len()).map_err(|_| "request body too large".to_string())?;

    let mut resp_buf: Vec<u8> = Vec::with_capacity(512);
    unsafe {
        let handle = curl_easy_init();
        if handle.is_null() {
            return Err("curl_easy_init failed".into());
        }
        let mut guard = CurlGuard {
            handle,
            headers: std::ptr::null_mut(),
        };
        guard.headers = curl_slist_append(guard.headers, h_ct.as_ptr());
        guard.headers = curl_slist_append(guard.headers, h_acc.as_ptr());
        guard.headers = curl_slist_append(guard.headers, h_key.as_ptr());
        guard.headers = curl_slist_append(guard.headers, h_sig.as_ptr());
        if let Some(ref ts_hdr) = h_ts {
            guard.headers = curl_slist_append(guard.headers, ts_hdr.as_ptr());
        }

        curl_easy_setopt(guard.handle, CURLOPT_URL, c_url.as_ptr());
        curl_easy_setopt(guard.handle, CURLOPT_POST, 1 as c_long);
        curl_easy_setopt(guard.handle, CURLOPT_NOSIGNAL, 1 as c_long);
        curl_easy_setopt(guard.handle, CURLOPT_HTTPHEADER, guard.headers);
        curl_easy_setopt(guard.handle, CURLOPT_POSTFIELDS, raw_body.as_ptr() as *const c_char);
        curl_easy_setopt(guard.handle, CURLOPT_POSTFIELDSIZE_LARGE, body_len);
        curl_easy_setopt(guard.handle, CURLOPT_TIMEOUT_MS, clamped_timeout);
        curl_easy_setopt(guard.handle, CURLOPT_CONNECTTIMEOUT_MS, clamped_connect);
        let write_fn: extern "C" fn(*const u8, usize, usize, *mut c_void) -> usize = write_callback;
        curl_easy_setopt(guard.handle, CURLOPT_WRITEFUNCTION, write_fn);
        curl_easy_setopt(guard.handle, CURLOPT_WRITEDATA, (&mut resp_buf) as *mut Vec<u8> as *mut c_void);

        let rc = curl_easy_perform(guard.handle);
        let mut status_code: c_long = 0;
        curl_easy_getinfo(guard.handle, CURLINFO_RESPONSE_CODE, &mut status_code as *mut c_long);

        if rc != 0 {
            return Err(format!("libcurl perform failed with code {}", rc));
        }
        Ok((status_code as u16, resp_buf))
    }
}

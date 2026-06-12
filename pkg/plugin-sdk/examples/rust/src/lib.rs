//! detect-dns-dga — ebpf-guard WASM plugin (Rust / wasm32-wasi)
//!
//! Fires a warning alert when a DNS query's label entropy exceeds a threshold
//! that is characteristic of domain-generation algorithm (DGA) traffic.
//!
//! # Build
//!
//! ```bash
//! cargo build --target wasm32-wasi --release
//! cp target/wasm32-wasi/release/detect_dns_dga.wasm \
//!    /path/to/rules/custom/detect_dns_dga.wasm
//! ```
//!
//! # ABI
//!
//! Implements the ebpf-guard WASM ABI v1:
//!   malloc / free / evaluate / alert_severity / alert_message_ptr / alert_message_len
//!
//! Event JSON is passed as raw bytes; we do a lightweight scan without pulling
//! in a full JSON parser so the binary stays under 20 KiB.

use std::alloc::{alloc, dealloc, Layout};

// ── module-level alert state ──────────────────────────────────────────────────

static mut ALERT_MSG: Vec<u8> = Vec::new();
static mut ALERT_SEV: i32 = 0; // 0 = warning, 1 = critical

// ── WASM ABI exports ──────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "C" fn malloc(size: u32) -> *mut u8 {
    let layout = Layout::from_size_align(size as usize, 1).unwrap();
    alloc(layout)
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut u8) {
    // size is unknown here; use size 1 as a placeholder — real plugins should
    // track allocation sizes if they need to free non-trivially.
    let layout = Layout::from_size_align(1, 1).unwrap();
    dealloc(ptr, layout);
}

#[no_mangle]
pub unsafe extern "C" fn evaluate(ptr: *const u8, len: u32) -> i32 {
    let data = std::slice::from_raw_parts(ptr, len as usize);
    let json = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    // Fast-path: only inspect DNS events (type == 5).
    if !json.contains("\"type\":5") && !json.contains("\"type\": 5") {
        return 0;
    }

    let qname = extract_string_field(json, "qname").unwrap_or("");
    if qname.is_empty() {
        return 0;
    }

    // Score each label in the FQDN by Shannon entropy; alert if any label
    // has entropy > 3.5 bits/char AND is longer than 12 characters.
    let matched = qname.split('.').any(|label| {
        label.len() > 12 && shannon_entropy(label) > 3.5
    });

    if matched {
        ALERT_SEV = 0; // warning
        let msg = format!("high-entropy DNS label detected (possible DGA): {}", qname);
        ALERT_MSG = msg.into_bytes();
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn alert_severity() -> i32 {
    ALERT_SEV
}

#[no_mangle]
pub unsafe extern "C" fn alert_message_ptr() -> *const u8 {
    if ALERT_MSG.is_empty() {
        return std::ptr::null();
    }
    ALERT_MSG.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn alert_message_len() -> u32 {
    ALERT_MSG.len() as u32
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Minimal JSON string-field extractor — avoids pulling in serde.
fn extract_string_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("\"{}\":", key);
    let start = json.find(&needle)? + needle.len();
    let rest = json[start..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let inner = &rest[1..];
    let end = inner.find('"')?;
    Some(&inner[..end])
}

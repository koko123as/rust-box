//! Go encodings the API's answers use.

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

/// `json.Encoder.Encode` with HTML escaping (what go-chi `render.JSON`
/// writes): `<`, `>`, `&`, U+2028 and U+2029 escaped, and a newline.
pub fn go_json(value: &Value) -> Vec<u8> {
    let text = serde_json::to_string(value).unwrap_or_else(|_| "null".into());
    let mut out = String::with_capacity(text.len() + 1);
    for character in text.chars() {
        match character {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other => out.push(other),
        }
    }
    out.push('\n');
    out.into_bytes()
}

/// The local UTC offset in seconds at `seconds` since the epoch.
fn local_offset(seconds: i64) -> i64 {
    #[cfg(unix)]
    {
        let time = seconds as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        // SAFETY: `localtime_r` writes only into `tm`.
        if unsafe { libc::localtime_r(&time, &mut tm) }.is_null() {
            return 0;
        }
        tm.tm_gmtoff
    }
    #[cfg(not(unix))]
    {
        let _ = seconds;
        0
    }
}

/// Days since 1970-01-01 to a civil date.
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// `time.Time.MarshalJSON` in the local zone: RFC 3339 with the fraction's
/// trailing zeros dropped.
pub fn rfc3339_nano(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = duration.as_secs() as i64;
    let nanos = duration.subsec_nanos();
    let offset = local_offset(seconds);
    let local = seconds + offset;
    let (year, month, day) = civil(local.div_euclid(86_400));
    let second_of_day = local.rem_euclid(86_400);
    let mut out = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        second_of_day / 3600,
        second_of_day / 60 % 60,
        second_of_day % 60
    );
    if nanos != 0 {
        let fraction = format!("{nanos:09}");
        out.push('.');
        out.push_str(fraction.trim_end_matches('0'));
    }
    if offset == 0 {
        out.push('Z');
    } else {
        let sign = if offset < 0 { '-' } else { '+' };
        let offset = offset.abs();
        out.push_str(&format!("{sign}{:02}:{:02}", offset / 3600, offset / 60 % 60));
    }
    out
}

/// `url.QueryUnescape` / `url.PathUnescape` (with `+` as space only for
/// queries); `None` for a bad escape.
pub fn unescape(text: &str, query: bool) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = bytes.get(index + 1..index + 3)?;
                let value = u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
                out.push(value);
                index += 3;
            }
            b'+' if query => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodings() {
        assert_eq!(go_json(&serde_json::json!({"a": "<&>"})), b"{\"a\":\"\\u003c\\u0026\\u003e\"}\n");
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_000), (2024, 10, 4));
        assert_eq!(unescape("a%2Fb+c", true).as_deref(), Some("a/b c"));
        assert_eq!(unescape("a%2Fb+c", false).as_deref(), Some("a/b+c"));
        assert_eq!(unescape("%zz", false), None);
        let text = rfc3339_nano(UNIX_EPOCH + std::time::Duration::new(1_700_000_000, 120_000_000));
        assert!(text.contains(".12"), "{text}");
    }
}

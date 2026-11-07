//! OS strings that are not valid Unicode, for tests of the paths that must
//! refuse or preserve them (sr-winpar.25). Include with
//! `#[path = "support/non_unicode.rs"] mod non_unicode;`.
//!
//! Unix strings are bytes, so a `0xff` byte makes one invalid. Windows strings
//! are UTF-16, so a lone surrogate (`0xD800`) does. `OsStr::to_str` refuses both.

use std::ffi::OsString;

/// `prefix` followed by one unit that cannot be decoded as Unicode.
pub fn with_prefix(prefix: &str) -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = prefix.as_bytes().to_vec();
        bytes.push(0xff);
        OsString::from_vec(bytes)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let mut wide: Vec<u16> = prefix.encode_utf16().collect();
        wide.push(0xD800);
        OsString::from_wide(&wide)
    }
}

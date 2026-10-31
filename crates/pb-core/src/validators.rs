//! `govalidator` compatible email and URL validation.
//!
//! `core/field_email.go` validates with `is.EmailFormat` (ozzo), which wraps
//! `govalidator.IsEmail`, and `core/field_url.go` uses `is.URL` (wrapping
//! `govalidator.IsURL`). Both are regex based; the exact patterns are copied
//! from govalidator so the accept/reject boundary matches the oracle.

use std::sync::OnceLock;

use regex::Regex;

const EMAIL_PATTERN: &str = r#"^(((([a-zA-Z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])+(\.([a-zA-Z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])|(\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-zA-Z]|\d|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])|(([a-zA-Z]|\d|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])([a-zA-Z]|\d|-|\.|_|~|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])*([a-zA-Z]|\d|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])))\.)+(([a-zA-Z]|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])|(([a-zA-Z]|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])([a-zA-Z]|\d|-|_|~|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])*([a-zA-Z]|[\x{00A0}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFEF}])))\.?$"#;

const URL_PATTERN: &str = r#"^((ftp|tcp|udp|wss?|https?):\/\/)?(\S+(:\S*)?@)?((([1-9]\d?|1\d\d|2[01]\d|22[0-3]|24\d|25[0-5])(\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-5]))|(\[(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\])|(([a-zA-Z0-9]([a-zA-Z0-9-_]+)?[a-zA-Z0-9]([-\.][a-zA-Z0-9]+)*)|(((www\.)|([a-zA-Z0-9]+([-_\.]?[a-zA-Z0-9])*[a-zA-Z0-9]\.[a-zA-Z0-9]+))?))?(([a-zA-Z\x{00a1}-\x{ffff}0-9]+-?-?)*[a-zA-Z\x{00a1}-\x{ffff}0-9]+)(?:\.([a-zA-Z\x{00a1}-\x{ffff}]{1,}))?))\.?(:(\d{1,5}))?((\/|\?|#)[^\s]*)?$"#;

fn email_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(EMAIL_PATTERN).expect("govalidator email pattern"))
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(URL_PATTERN).expect("govalidator url pattern"))
}

/// `govalidator.IsEmail`.
pub fn is_email(value: &str) -> bool {
    email_re().is_match(value)
}

/// `govalidator.IsURL`.
pub fn is_url(value: &str) -> bool {
    if value.is_empty()
        || value.chars().count() >= 2083
        || value.len() <= 3
        || value.starts_with('.')
    {
        return false;
    }

    // Go appends a scheme when only a port colon is present so that
    // `url.Parse` succeeds.
    let temp = if value.contains(':') && !value.contains("://") {
        format!("http://{value}")
    } else {
        value.to_string()
    };

    let (host, path) = split_host_path(&temp);
    if host.starts_with('.') {
        return false;
    }
    if host.is_empty() && !path.is_empty() && !path.contains('.') {
        return false;
    }

    url_re().is_match(value)
}

/// The `u.Host` part of a URL as Go's `url.Parse` would report it.
pub fn url_host(value: &str) -> String {
    let (host, _) = split_host_path(value);
    host
}

/// A deliberately small `url.Parse` stand-in: returns `(host, path)`.
fn split_host_path(value: &str) -> (String, String) {
    let rest = if let Some((_, after)) = value.split_once("://") {
        after
    } else if let Some(after) = value.strip_prefix("//") {
        after
    } else {
        return (String::new(), value.to_string());
    };

    let end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let authority = &rest[..end];
    let path = &rest[end..];
    let host = authority.rsplit('@').next().unwrap_or(authority);
    (host.to_string(), path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_match_govalidator_examples() {
        for ok in ["test@example.com", "a.b+c@sub.example.co", "x@y.zz"] {
            assert!(is_email(ok), "{ok} should be valid");
        }
        for bad in ["", "test", "test@", "@example.com", "test@example", "a b@example.com"] {
            assert!(!is_email(bad), "{bad} should be invalid");
        }
    }

    #[test]
    fn urls_match_govalidator_examples() {
        for ok in ["http://example.com", "https://example.com/a?b=1", "example.com"] {
            assert!(is_url(ok), "{ok} should be valid");
        }
        for bad in ["", ".example.com", "http://", "foo"] {
            assert!(!is_url(bad), "{bad} should be invalid");
        }
    }

    #[test]
    fn host_extraction() {
        assert_eq!(url_host("https://user:pass@example.com:8080/x"), "example.com:8080");
        assert_eq!(url_host("example.com"), "");
        assert_eq!(url_host("//example.com/x"), "example.com");
    }
}

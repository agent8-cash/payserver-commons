//! Secret and PII redaction for error reports.
//!
//! One implementation, shared. It used to be two: this hand-written version in
//! the client and a regex-based twin in `evm`, kept in step by a differential
//! test. That test was the only thing tying the frontend to a payserver crate,
//! and the duplication was the only reason it existed.
//!
//! Hand-written scanners rather than regexes, and that is the load-bearing
//! choice: pulling `regex` into the browser bundle costs about 1 MB of WASM
//! (measured 2.28 MB -> 3.28 MB), which is not a price worth paying in a client
//! built with `opt-level = "z"` and `wasm-opt -Oz`. Each rule carries the
//! pattern it implements in its doc comment.
//!
//! This crate has no dependencies at all, deliberately. It is compiled into the
//! browser and into every payserver, and a redaction library that pulls in a
//! supply chain is a redaction library that can leak through one.
//!
//! `evm::telemetry` keeps the regex implementation as an audited reference and
//! asserts this one matches it over a corpus. That check lives there because it
//! is the only place both can be compiled.

use std::borrow::Cow;

/// One redaction rule: at byte offset `at`, either a match — its end offset and
/// what to put in its place — or nothing. Offsets are always char boundaries
/// because every pattern is pure ASCII.
type Rule = fn(&str, usize) -> Option<(usize, String)>;

/// Ordered exactly as in `evm::telemetry`. Order is load-bearing: the JWT rule
/// has to run before the keyed-value rule can swallow a `Bearer <jwt>`.
const RULES: &[Rule] = &[
    jwt,
    rpc_key,
    prefixed_hex,
    bare_hex,
    mnemonic,
    email,
    keyed_value,
];

/// Every key name whose value is a secret: the one definition. Free text is
/// scanned for `key: value` / `key=value` with these, and structured data
/// (Sentry extras, breadcrumbs, JSON maps) is checked by [`is_sensitive_key`].
///
/// This is the union of what every consumer once kept for itself, so none of
/// them may restate it. A service that needs one more extends this list
/// visibly at its call site instead of keeping a parallel copy.
pub const SENSITIVE_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "mnemonic",
    "seed",
    "privatekey",
    "private_key",
    "private-key",
    "authorization",
    "bearer",
    "auth",
    "dsn",
    "credential",
    "session",
    "cookie",
    "signature",
];

/// Keys that may be followed by a bare space and still introduce a value
/// (`Bearer <tok>`, `token abc`); the original free-text set.
const BARE_VALUE_KEYS: &[&str] = &[
    "api_key",
    "api-key",
    "apikey",
    "secret",
    "password",
    "passwd",
    "token",
    "mnemonic",
    "seed",
    "private_key",
    "private-key",
    "privatekey",
    "authorization",
    "bearer",
];

/// Whether a structured-data key names something whose value is a secret.
/// Substring match, case-insensitive: `X-Auth-Header` and `sessionId` count.
#[must_use]
pub fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|needle| key.contains(needle))
}

/// Redact secret-shaped substrings from a free-text string.
///
/// Defence-in-depth for panic messages and stack traces, which routinely
/// interpolate whatever the failing code was holding. Rules intentionally err
/// on the side of over-redaction.
#[must_use]
pub fn redact_secrets(input: &str) -> String {
    let mut out = Cow::Borrowed(input);
    for rule in RULES {
        if let Some(redacted) = replace_all(&out, *rule) {
            out = Cow::Owned(redacted);
        }
    }
    out.into_owned()
}

/// Leftmost, non-overlapping replacement of every match — `Regex::replace_all`
/// semantics. `None` when the rule never matched, so the input is left alone.
fn replace_all(input: &str, rule: Rule) -> Option<String> {
    let mut out = String::new();
    let mut copied = 0;
    let mut at = 0;
    while at < input.len() {
        match rule(input, at) {
            Some((end, replacement)) if end > at => {
                out.push_str(&input[copied..at]);
                out.push_str(&replacement);
                copied = end;
                at = end;
            }
            _ => at = next_boundary(input, at),
        }
    }
    (copied > 0).then(|| {
        out.push_str(&input[copied..]);
        out
    })
}

/// `eyJ[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+\.[A-Za-z0-9_=-]+` — JSON Web Tokens
/// (header.payload.signature).
fn jwt(input: &str, at: usize) -> Option<(usize, String)> {
    if !input[at..].starts_with("eyJ") {
        return None;
    }
    let mut end = run(input, at + 3, is_base64url);
    if end == at + 3 {
        return None;
    }
    for _ in 0..2 {
        if byte(input, end) != Some(b'.') {
            return None;
        }
        let segment = run(input, end + 1, is_base64url);
        if segment == end + 1 {
            return None;
        }
        end = segment;
    }
    Some((end, "[redacted-jwt]".to_string()))
}

/// `((?:https?|wss?)://<host>(?::<port>)?(?:/<seg 1-15>)*/)<seg 16+>` — RPC
/// provider URLs carry the API key in the path (Alchemy `/v2/<key>`, Infura
/// `/v3/<key>`, QuickNode `/<token>/`). Scheme and host are kept so reports
/// still say which provider failed; the credential-length segment is not.
fn rpc_key(input: &str, at: usize) -> Option<(usize, String)> {
    let mut pos = ["https://", "http://", "wss://", "ws://"]
        .iter()
        .find_map(|scheme| input[at..].starts_with(scheme).then(|| at + scheme.len()))?;

    let host = run(input, pos, |b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
    });
    if host == pos {
        return None;
    }
    pos = host;
    if byte(input, pos) == Some(b':') {
        let port = run(input, pos + 1, |b| b.is_ascii_digit());
        if port == pos + 1 {
            return None;
        }
        pos = port;
    }

    // Walk the path: any number of ordinary segments, then the first one long
    // enough to be a credential.
    loop {
        if byte(input, pos) != Some(b'/') {
            return None;
        }
        let segment = run(input, pos + 1, is_path_byte);
        let length = segment - (pos + 1);
        if length >= 16 {
            return Some((segment, format!("{}[redacted-rpc-key]", &input[at..=pos])));
        }
        if length == 0 {
            return None;
        }
        pos = segment;
    }
}

/// `0x[0-9a-fA-F]{40,}` — addresses (40), private keys / tx hashes / block
/// hashes (64), signatures (130).
fn prefixed_hex(input: &str, at: usize) -> Option<(usize, String)> {
    if !input[at..].starts_with("0x") {
        return None;
    }
    let end = run(input, at + 2, |b| b.is_ascii_hexdigit());
    (end - (at + 2) >= 40).then(|| (end, "[redacted-hex]".to_string()))
}

/// `\b[0-9a-fA-F]{64}\b` — private keys / hashes without the `0x` prefix.
fn bare_hex(input: &str, at: usize) -> Option<(usize, String)> {
    if !at_word_start(input, at) {
        return None;
    }
    let end = run(input, at, |b| b.is_ascii_hexdigit());
    (end - at == 64 && at_word_end(input, end)).then(|| (end, "[redacted-hex]".to_string()))
}

/// `\b(?:[a-z]+\s+){11,}[a-z]+\b` — BIP-39 mnemonics, i.e. 12+ consecutive
/// lowercase words.
fn mnemonic(input: &str, at: usize) -> Option<(usize, String)> {
    if !at_word_start(input, at) {
        return None;
    }
    let (mut pos, mut words, mut end) = (at, 0_usize, at);
    loop {
        let word = run(input, pos, |b| b.is_ascii_lowercase());
        if word == pos || !at_word_end(input, word) {
            break;
        }
        words += 1;
        end = word;
        let space = run(input, word, |b| b.is_ascii_whitespace());
        if space == word {
            break;
        }
        pos = space;
    }
    (words >= 12).then(|| (end, "[redacted: 12+ word run]".to_string()))
}

/// `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}` — customer PII.
fn email(input: &str, at: usize) -> Option<(usize, String)> {
    let local = run(input, at, |b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
    });
    if local == at || byte(input, local) != Some(b'@') {
        return None;
    }
    let domain = local + 1;
    let domain_end = run(input, domain, |b| {
        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')
    });

    // The greedy `+` backtracks to the *last* dot still followed by a TLD, so
    // `a@b.co.uk` matches through `.uk`, not through `.co`.
    let mut end = None;
    for (offset, _) in input[domain..domain_end].match_indices('.') {
        let tld = run(input, domain + offset + 1, |b| b.is_ascii_alphabetic());
        if tld - (domain + offset + 1) >= 2 {
            end = Some(tld);
        }
    }
    end.map(|end| (end, "[redacted-email]".to_string()))
}

/// `(?i)\b(<SENSITIVE_KEYS>)\b(\s*[:=]\s*|\s+)("?)[^\s,;"']+`
/// — `key: value` / `key=value` for sensitive keys, plus `Bearer <token>`. Key,
/// separator and opening quote are kept; only the value is replaced.
fn keyed_value(input: &str, at: usize) -> Option<(usize, String)> {
    if !at_word_start(input, at) {
        return None;
    }
    let (key_end, key) = sensitive_key_end(input, at)?;
    if !at_word_end(input, key_end) {
        return None;
    }
    let separated = separator_end(input, key_end)?;
    // Everyday words (`auth failed`, `session expired`) are keys too, so
    // outside the original set only an explicit `:` or `=` marks a value.
    if !BARE_VALUE_KEYS.contains(&key) && !input[key_end..separated].contains([':', '=']) {
        return None;
    }
    let value = separated + usize::from(byte(input, separated) == Some(b'"'));
    let end = run(input, value, |b| {
        !b.is_ascii_whitespace() && !matches!(b, b',' | b';' | b'"' | b'\'')
    });
    (end > value).then(|| (end, format!("{}[redacted]", &input[at..value])))
}

/// End offset of the longest sensitive key starting at `at`, case-insensitively.
/// Longest wins so `authorization` is not cut short by `auth`.
fn sensitive_key_end(input: &str, at: usize) -> Option<(usize, &'static str)> {
    SENSITIVE_KEYS
        .iter()
        .filter_map(|key| {
            let end = at + key.len();
            input
                .as_bytes()
                .get(at..end)
                .is_some_and(|found| found.eq_ignore_ascii_case(key.as_bytes()))
                .then_some((end, *key))
        })
        .max_by_key(|(end, _)| *end)
}

/// `(\s*[:=]\s*|\s+)` — end offset of the separator between key and value.
fn separator_end(input: &str, from: usize) -> Option<usize> {
    let spaced = run(input, from, |b| b.is_ascii_whitespace());
    if matches!(byte(input, spaced), Some(b':' | b'=')) {
        return Some(run(input, spaced + 1, |b| b.is_ascii_whitespace()));
    }
    (spaced > from).then_some(spaced)
}

/// End offset of the run of bytes matching `predicate` that starts at `from`.
fn run(input: &str, from: usize, predicate: impl Fn(u8) -> bool) -> usize {
    input.as_bytes()[from.min(input.len())..]
        .iter()
        .position(|byte| !predicate(*byte))
        .map_or(input.len(), |length| from + length)
}

fn byte(input: &str, at: usize) -> Option<u8> {
    input.as_bytes().get(at).copied()
}

fn is_base64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'=' | b'-')
}

fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

/// `\w` for the purposes of `\b`.
fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn at_word_start(input: &str, at: usize) -> bool {
    at == 0 || byte(input, at - 1).is_none_or(|b| !is_word(b))
}

fn at_word_end(input: &str, at: usize) -> bool {
    byte(input, at).is_none_or(|b| !is_word(b))
}

/// Next char boundary at or after `at + 1`.
fn next_boundary(input: &str, at: usize) -> usize {
    input[at..]
        .chars()
        .next()
        .map_or(at + 1, |c| at + c.len_utf8())
}

#[cfg(test)]
mod tests {
    use super::redact_secrets;

    #[test]
    fn redacts_jwt() {
        let text = "auth failed for eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123";
        let out = redact_secrets(text);
        assert!(out.contains("[redacted-jwt]"), "{out}");
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"), "{out}");
    }

    #[test]
    fn redacts_wallet_addresses_and_keys() {
        let address = "0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let private_key = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
        let out = redact_secrets(&format!("send from {address} signed with {private_key}"));
        assert_eq!(out, "send from [redacted-hex] signed with [redacted-hex]");
    }

    #[test]
    fn redacts_bare_64_char_hex() {
        let out = redact_secrets(
            "seed 4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318 leaked",
        );
        // The hex rule fires first, then the `seed <value>` rule rewrites its
        // placeholder — belt and braces, and identical to the `evm` behaviour.
        assert_eq!(out, "seed [redacted] leaked");
    }

    #[test]
    fn redacts_emails() {
        let out = redact_secrets("no store for merchant@example.com");
        assert_eq!(out, "no store for [redacted-email]");
    }

    #[test]
    fn redacts_bearer_tokens_and_keyed_values() {
        let out = redact_secrets(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig api_key=zzz999",
        );
        assert!(!out.contains("eyJhbGciOiJIUzI1NiJ9"), "{out}");
        assert!(!out.contains("zzz999"), "{out}");
    }

    /// Pins a known gap inherited from `evm::telemetry`, so that fixing the
    /// rule table there fails here and both copies get updated together:
    /// `authorization` and `bearer` are alternatives of the *same* rule, so the
    /// match starting at `Authorization` consumes `Bearer` as its value and an
    /// opaque token behind it survives. The tokens this client actually holds
    /// are JWTs, which the JWT rule above redacts before this rule runs.
    #[test]
    fn known_gap_opaque_token_after_authorization_bearer() {
        let out = redact_secrets("Authorization: Bearer rc_live_opaque123");
        assert_eq!(out, "Authorization: [redacted] rc_live_opaque123");
    }

    #[test]
    fn redacts_rpc_provider_keys() {
        let out = redact_secrets("GET https://eth-mainnet.g.alchemy.com/v2/9f8e7d6c5b4a3210zz");
        assert_eq!(
            out,
            "GET https://eth-mainnet.g.alchemy.com/v2/[redacted-rpc-key]"
        );
    }

    #[test]
    fn redacts_mnemonics() {
        let out = redact_secrets(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        );
        assert_eq!(out, "[redacted: 12+ word run]");
    }

    #[test]
    fn placeholder_states_the_shape_not_the_secret_kind() {
        // A shape rule fires on prose as readily as on a seed phrase, so the
        // label must not claim what the text was.
        let out = redact_secrets(
            "invoice creation allowed on a standing that was never received or is older than the freshness bound",
        );
        assert_eq!(out, "[redacted: 12+ word run]");
        assert!(!out.contains("mnemonic"));
    }

    #[test]
    fn leaves_ordinary_messages_alone() {
        let text = "failed to fetch /api/invoices/inv_001: HTTP 502";
        assert_eq!(redact_secrets(text), text);
    }

    #[test]
    fn handles_multibyte_text() {
        let text = "façade ↔ merchant@example.com ↔ façade";
        assert_eq!(redact_secrets(text), "façade ↔ [redacted-email] ↔ façade");
    }

    #[test]
    fn every_sensitive_key_is_matched() {
        const EXPECTED: [&str; 20] = [
            "password",
            "passwd",
            "secret",
            "token",
            "apikey",
            "api_key",
            "api-key",
            "mnemonic",
            "seed",
            "privatekey",
            "private_key",
            "private-key",
            "authorization",
            "bearer",
            "auth",
            "dsn",
            "credential",
            "session",
            "cookie",
            "signature",
        ];
        assert_eq!(super::SENSITIVE_KEYS.len(), EXPECTED.len());
        for key in EXPECTED {
            assert!(super::SENSITIVE_KEYS.contains(&key), "{key} dropped");
            assert!(super::is_sensitive_key(&key.to_uppercase()), "{key}");
            let out = redact_secrets(&format!("{key}=hunter2value"));
            assert!(!out.contains("hunter2value"), "{key} not redacted: {out}");
        }
        assert!(!super::is_sensitive_key("merchant_name"));
    }

    #[test]
    fn everyday_words_need_an_explicit_separator() {
        assert_eq!(
            redact_secrets("auth failed for user"),
            "auth failed for user"
        );
        assert_eq!(redact_secrets("session expired"), "session expired");
        assert_eq!(redact_secrets("dsn: https://k@h/1"), "dsn: [redacted]");
    }
}

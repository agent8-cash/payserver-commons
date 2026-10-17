//! Contract version negotiation.

/// No contract version is supported by both sides.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "no common chain contract version: orchestrator supports {local:?}, adapter offers {remote:?}"
)]
pub struct NegotiationError {
    pub local: Vec<String>,
    pub remote: Vec<String>,
}

/// The trailing major version of a package such as `payserver.chain.v2`.
fn major(package: &str) -> Option<u32> {
    package.rsplit('.').next()?.strip_prefix('v')?.parse().ok()
}

/// Picks the highest version present on both sides. Entries that do not parse
/// as `...vN` never match, so a future naming scheme is refused rather than
/// guessed at.
pub fn negotiate<L: AsRef<str>, R: AsRef<str>>(
    local: &[L],
    remote: &[R],
) -> Result<String, NegotiationError> {
    local
        .iter()
        .map(AsRef::as_ref)
        .filter(|l| remote.iter().any(|r| r.as_ref() == *l))
        .filter_map(|l| major(l).map(|m| (m, l)))
        .max_by_key(|(m, _)| *m)
        .map(|(_, l)| l.to_owned())
        .ok_or_else(|| NegotiationError {
            local: local.iter().map(|s| s.as_ref().to_owned()).collect(),
            remote: remote.iter().map(|s| s.as_ref().to_owned()).collect(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_highest_common() {
        let got = negotiate(
            &["payserver.chain.v1", "payserver.chain.v2"],
            &[
                "payserver.chain.v1",
                "payserver.chain.v2",
                "payserver.chain.v3",
            ],
        );
        assert_eq!(got.unwrap(), "payserver.chain.v2");
    }

    #[test]
    fn numeric_not_lexical() {
        let got = negotiate(
            &["payserver.chain.v2", "payserver.chain.v10"],
            &["payserver.chain.v2", "payserver.chain.v10"],
        );
        assert_eq!(got.unwrap(), "payserver.chain.v10");
    }

    #[test]
    fn empty_intersection_is_refused() {
        let err = negotiate(&["payserver.chain.v1"], &["payserver.chain.v2"]).unwrap_err();
        assert_eq!(err.remote, vec!["payserver.chain.v2".to_owned()]);
        assert!(negotiate::<&str, &str>(&[], &[]).is_err());
    }
}

//! Authenticated-sender authorization: which `MAIL FROM` / `From:`
//! addresses an AUTH identity may use.
//!
//! AUTH proves *who* the client is. This module answers the separate
//! question of *what that identity may claim*: each login maps to a set of
//! exact addresses and whole domains (`--auth-senders`). The SPF skip and
//! the DMARC-rejection exemption that authenticated sessions get are only
//! safe because every `MAIL FROM` and every `From:` author of an
//! authenticated session is checked against that set first, so being
//! authenticated never means "may use any From".
//!
//! Fail-closed: a login with no grants can authenticate but can't send
//! anything, and the null sender is never allowed for an authenticated
//! session.

use std::collections::{HashMap, HashSet};

use anyhow::{bail, Result};

/// AUTH configuration: the credential store plus each login's sender
/// grants. Grants only exist alongside credentials, so the type rules out
/// a configuration that authorizes senders without AUTH.
#[derive(Debug, Default)]
pub struct AuthConfig {
    /// `user -> password`, in plaintext. Footgun: these come from argv or the
    /// config file, so they show up in `ps` and shell history.
    pub credentials: HashMap<String, String>,
    /// `user -> addresses/domains` that user may send as.
    pub senders: SenderGrants,
}

impl AuthConfig {
    /// Build from the `--auth-users` and `--auth-senders` specs.
    ///
    /// `users_spec` is a comma-separated list of `user:password` pairs
    /// (the user is trimmed; the password is everything after the first
    /// `:`, verbatim). `senders_spec` is the [`SenderGrants`] spec; `None`
    /// or a blank spec means no login has any grants.
    ///
    /// # Errors
    ///
    /// A `users_spec` entry without a `:`, any [`SenderGrants::parse`]
    /// error, or a grant for a login that is not in `users_spec` (almost
    /// always a typo, and silently ignoring it would leave the intended
    /// user unable to send).
    pub fn parse(users_spec: &str, senders_spec: Option<&str>) -> Result<Self> {
        let mut credentials = HashMap::new();
        for pair in users_spec.split(',') {
            let Some((user, pass)) = pair.split_once(':') else {
                bail!("--auth-users entries must be user:password, got {pair:?}");
            };
            credentials.insert(user.trim().to_string(), pass.to_string());
        }
        let senders = match senders_spec {
            Some(spec) if !spec.trim().is_empty() => SenderGrants::parse(spec)?,
            _ => SenderGrants::default(),
        };
        for user in senders.by_user.keys() {
            if !credentials.contains_key(user) {
                bail!("--auth-senders names {user:?}, which is not in --auth-users");
            }
        }
        Ok(AuthConfig {
            credentials,
            senders,
        })
    }

    /// Returns the logins that can authenticate but have no sender grants
    /// (so every `MAIL FROM` they send is refused), sorted for stable logs.
    pub fn users_without_grants(&self) -> Vec<&str> {
        let mut users: Vec<&str> = self
            .credentials
            .keys()
            .filter(|u| !self.senders.by_user.contains_key(*u))
            .map(String::as_str)
            .collect();
        users.sort_unstable();
        users
    }
}

/// What one login may send as.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Grant {
    /// Exact addresses, normalized (see [`normalize`]).
    addresses: HashSet<String>,
    /// Whole domains (`@example.org` in the spec), lowercased.
    domains: HashSet<String>,
}

/// Per-login sender grants, from `--auth-senders`.
///
/// Spec: comma-separated `user=grant|grant|...` entries, where a grant is
/// either an exact address (`alice@example.org`) or a whole domain
/// (`@example.org`). Example:
/// `alice=alice@example.org|@example.net,bob=bob@example.org`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SenderGrants {
    /// Login name -> what that login may send as.
    by_user: HashMap<String, Grant>,
}

impl SenderGrants {
    /// Parse an `--auth-senders` `spec` (format above).
    ///
    /// # Errors
    ///
    /// An entry without `=` or with an empty user, a grant that has no
    /// `@` (including an empty grant list), a grant with an implausible
    /// domain, or a login listed twice.
    pub fn parse(spec: &str) -> Result<Self> {
        let mut by_user: HashMap<String, Grant> = HashMap::new();
        for entry in spec.split(',') {
            let entry = entry.trim();
            let Some((user, grants)) = entry.split_once('=') else {
                bail!("--auth-senders entries must be user=address|@domain, got {entry:?}");
            };
            let user = user.trim();
            if user.is_empty() {
                bail!("--auth-senders entry {entry:?} has no user");
            }
            let mut grant = Grant::default();
            for item in grants.split('|').map(str::trim) {
                let Some((local, domain)) = item.rsplit_once('@') else {
                    bail!(
                        "--auth-senders grant {item:?} for {user:?} must be an address or @domain"
                    );
                };
                let Some(domain) = normalize_domain(domain) else {
                    bail!("--auth-senders grant {item:?} for {user:?} has an invalid domain");
                };
                if local.is_empty() {
                    grant.domains.insert(domain);
                } else {
                    grant.addresses.insert(normalize(local, &domain));
                }
            }
            if by_user.insert(user.to_string(), grant).is_some() {
                bail!("--auth-senders lists {user:?} more than once");
            }
        }
        Ok(SenderGrants { by_user })
    }

    /// May login `user` send as `local@domain`?
    ///
    /// Returns `true` when `user` has a grant for the exact address or for
    /// the whole domain; `false` for an unknown login, an empty
    /// local-part, or an implausible domain.
    ///
    /// The domain is compared case-insensitively (DNS names are). The
    /// local-part is compared ASCII-case-insensitively too: RFC 5321
    /// leaves its case to the receiving host, and every hosted mailbox here
    /// is case-insensitive, so `Alice@` is the same mailbox as `alice@`.
    /// Being looser here never grants another user's mailbox.
    pub fn permits(&self, user: &str, local: &str, domain: &str) -> bool {
        let Some(grant) = self.by_user.get(user) else {
            return false;
        };
        let Some(domain) = normalize_domain(domain) else {
            return false;
        };
        if local.is_empty() {
            return false;
        }
        grant.domains.contains(&domain) || grant.addresses.contains(&normalize(local, &domain))
    }
}

/// Returns `local@domain` with `local` ASCII-lowercased. `domain` must
/// already be normalized (see [`normalize_domain`]).
fn normalize(local: &str, domain: &str) -> String {
    format!("{}@{domain}", local.to_ascii_lowercase())
}

/// Normalize `domain` for comparison.
///
/// Returns it trimmed, lowercased and without a trailing dot, or `None`
/// unless it looks like a hostname (non-empty labels of ASCII letters,
/// digits, `-` and `_`).
fn normalize_domain(domain: &str) -> Option<String> {
    let d = domain.trim();
    let d = d.strip_suffix('.').unwrap_or(d);
    let plausible = !d.is_empty()
        && d.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    plausible.then(|| d.to_ascii_lowercase())
}

/// Split an envelope path address `addr` (`local@domain`, brackets
/// already removed) at its last `@`.
///
/// Returns `(local, domain)`, or `None` for the null sender or an address
/// with no `@`, an empty local-part or an empty domain.
pub fn split_address(addr: &str) -> Option<(&str, &str)> {
    let (local, domain) = addr.rsplit_once('@')?;
    (!local.is_empty() && !domain.is_empty()).then_some((local, domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(senders: &str) -> AuthConfig {
        AuthConfig::parse("alice:pw,bob:pw,carol:pw", Some(senders)).unwrap()
    }

    #[test]
    fn grants_cover_addresses_and_domains() {
        let c = cfg("alice=alice@example.org|@Example.NET.,bob=bob@example.org");
        let g = &c.senders;
        assert!(g.permits("alice", "alice", "example.org"));
        assert!(g.permits("alice", "ALICE", "EXAMPLE.org."));
        assert!(g.permits("alice", "anyone", "example.net"));
        assert!(!g.permits("alice", "bob", "example.org"), "not alice's");
        assert!(
            !g.permits("alice", "x", "sub.example.net"),
            "no subdomain grant"
        );
        assert!(!g.permits("alice", "x", "evil-example.net"));
        assert!(g.permits("bob", "bob", "example.org"));
        assert!(!g.permits("bob", "alice", "example.org"));
        // No grants: fail closed.
        assert!(!g.permits("carol", "carol", "example.org"));
        assert!(!g.permits("mallory", "alice", "example.org"));
        assert!(!g.permits("alice", "", "example.net"), "empty local-part");
        assert_eq!(c.users_without_grants(), vec!["carol"]);
    }

    #[test]
    fn no_senders_spec_means_no_one_may_send() {
        let c = AuthConfig::parse("alice:pw", None).unwrap();
        assert!(!c.senders.permits("alice", "alice", "example.org"));
        assert_eq!(c.users_without_grants(), vec!["alice"]);
    }

    #[test]
    fn bad_specs_are_startup_errors() {
        for bad in [
            "alice",
            "=alice@example.org",
            "alice=",
            "alice=example.org",
            "alice=alice@",
            "alice=a@bad domain",
            "alice=a@ex..ample",
            "alice=a@example.org,alice=@example.net",
        ] {
            assert!(
                AuthConfig::parse("alice:pw", Some(bad)).is_err(),
                "{bad:?} should be refused"
            );
        }
        // A grant for a login that can't authenticate is a typo.
        assert!(AuthConfig::parse("alice:pw", Some("alcie=@example.org")).is_err());
        assert!(AuthConfig::parse("alice", None).is_err());
    }

    #[test]
    fn split_address_rejects_null_and_empty_parts() {
        assert_eq!(split_address("a@b.example"), Some(("a", "b.example")));
        assert_eq!(
            split_address("\"a@b\"@c.example"),
            Some(("\"a@b\"", "c.example"))
        );
        assert_eq!(split_address(""), None);
        assert_eq!(split_address("@b.example"), None);
        assert_eq!(split_address("a@"), None);
        assert_eq!(split_address("nodomain"), None);
    }
}

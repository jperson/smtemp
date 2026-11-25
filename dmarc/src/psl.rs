//! The Public Suffix List, for finding a domain's organizational domain
//! (RFC 7489 §3.2): the public suffix (`com`, `co.uk`, `github.io`) plus
//! one more label.
//!
//! The list is a vendored, dated snapshot (`data/public_suffix_list.dat`,
//! from <https://publicsuffix.org/list/>, MPL-2.0; its header records the
//! version), with both the ICANN and the private sections, so that
//! `alice.github.io` and `bob.github.io` are separate organizations.
//! Update it by replacing the file. Unicode rules are converted to their
//! ASCII (`xn--`) form when the list is loaded, since mail carries domains
//! in that form.

use std::collections::HashSet;
use std::sync::OnceLock;

/// The vendored list.
const LIST: &str = include_str!("../data/public_suffix_list.dat");

/// The parsed list: ordinary rules, wildcard rules (stored without their
/// `*.`), and exception rules (stored without their `!`), all lowercase
/// ASCII.
struct Rules {
    /// `co.uk`: that name is a public suffix.
    exact: HashSet<String>,
    /// `*.ck` stored as `ck`: every direct child of it is a public suffix.
    wildcard: HashSet<String>,
    /// `!www.ck` stored as `www.ck`: not a public suffix, despite a
    /// wildcard; its parent is.
    exception: HashSet<String>,
}

/// Returns the vendored snapshot's version (its `// VERSION:` header
/// line, e.g. `2026-11-24_18-53-27_UTC`), for logging how old it is.
pub fn version() -> Option<&'static str> {
    LIST.lines()
        .find_map(|l| l.strip_prefix("// VERSION:"))
        .map(str::trim)
}

/// Parse the list now rather than on the first lookup (it takes a few
/// milliseconds), so the first message doesn't pay for it.
///
/// Returns the number of rules loaded.
pub fn load() -> usize {
    let rules = rules();
    rules.exact.len() + rules.wildcard.len() + rules.exception.len()
}

/// Returns the parsed list, parsing it on first use.
fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| parse(LIST))
}

/// Parse the list `text`: one rule per line, `//` comments and blank lines
/// ignored, and only the first whitespace-separated word of a line used
/// (as the format specifies).
fn parse(text: &str) -> Rules {
    let mut rules = Rules {
        exact: HashSet::new(),
        wildcard: HashSet::new(),
        exception: HashSet::new(),
    };
    for line in text.lines() {
        let Some(rule) = line.split_whitespace().next() else {
            continue;
        };
        if rule.starts_with("//") {
            continue;
        }
        let Some(rule) = to_ascii(rule) else {
            continue;
        };
        if let Some(rest) = rule.strip_prefix('!') {
            rules.exception.insert(rest.to_string());
        } else if let Some(rest) = rule.strip_prefix("*.") {
            rules.wildcard.insert(rest.to_string());
        } else {
            rules.exact.insert(rule);
        }
    }
    rules
}

/// Returns `domain`'s public suffix under the list (trimmed, lowercased,
/// trailing dot removed): the longest matching rule, an exception rule
/// taking precedence, and the implicit `*` rule (the last label) when none
/// matches. `None` for an empty domain.
pub fn public_suffix(domain: &str) -> Option<String> {
    let domain = normalize(domain)?;
    let labels: Vec<&str> = domain.split('.').collect();
    let rules = rules();
    // Longest candidate first, so the first match is the prevailing rule.
    for i in 0..labels.len() {
        let candidate = labels[i..].join(".");
        if rules.exception.contains(&candidate) {
            return Some(labels[i + 1..].join("."));
        }
        let parent_is_wildcard =
            i + 1 < labels.len() && rules.wildcard.contains(&labels[i + 1..].join("."));
        if rules.exact.contains(&candidate) || parent_is_wildcard {
            return Some(candidate);
        }
    }
    labels.last().map(|l| l.to_string())
}

/// Returns `domain`'s organizational domain (RFC 7489 §3.2): its public
/// suffix plus one more label, or `None` when `domain` is itself a public
/// suffix (or empty).
pub fn organizational_domain(domain: &str) -> Option<String> {
    let domain = normalize(domain)?;
    let suffix = public_suffix(&domain)?;
    if domain == suffix {
        return None;
    }
    let prefix = domain.strip_suffix(&format!(".{suffix}"))?;
    let label = prefix.rsplit('.').next()?;
    Some(format!("{label}.{suffix}"))
}

/// Trim `domain`, drop a trailing dot and lowercase it; `None` if nothing
/// is left or a label is empty.
fn normalize(domain: &str) -> Option<String> {
    let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.split('.').any(str::is_empty) {
        return None;
    }
    Some(domain)
}

/// Convert a list rule to ASCII: each non-ASCII label becomes `xn--` plus
/// its Punycode (RFC 3492). The list's rules are already lowercase and
/// normalized. `None` if a label can't be encoded.
fn to_ascii(rule: &str) -> Option<String> {
    rule.split('.')
        .map(|label| {
            if label.is_ascii() {
                Some(label.to_ascii_lowercase())
            } else {
                punycode(label).map(|p| format!("xn--{p}"))
            }
        })
        .collect::<Option<Vec<_>>>()
        .map(|labels| labels.join("."))
}

/// RFC 3492 Punycode encoding of `input` (without the `xn--` prefix).
/// `None` on arithmetic overflow (not reachable for real labels).
fn punycode(input: &str) -> Option<String> {
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 128;

    fn digit(d: u32) -> char {
        // 0-25 are a-z, 26-35 are 0-9.
        char::from_u32(if d < 26 { d + 97 } else { d + 22 }).unwrap_or('?')
    }
    fn adapt(mut delta: u32, points: u32, first: bool) -> u32 {
        delta /= if first { DAMP } else { 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > ((BASE - T_MIN) * T_MAX) / 2 {
            delta /= BASE - T_MIN;
            k += BASE;
        }
        k + (BASE - T_MIN + 1) * delta / (delta + SKEW)
    }

    let code_points: Vec<u32> = input.chars().map(u32::from).collect();
    let mut output: String = input.chars().filter(char::is_ascii).collect();
    let basic = output.len() as u32;
    let mut handled = basic;
    if basic > 0 {
        output.push('-');
    }
    let (mut n, mut delta, mut bias) = (INITIAL_N, 0u32, INITIAL_BIAS);
    while (handled as usize) < code_points.len() {
        let m = *code_points.iter().filter(|&&c| c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in &code_points {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias {
                        T_MIN
                    } else if k >= bias + T_MAX {
                        T_MAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    output.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta = delta.checked_add(1)?;
        n = n.checked_add(1)?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The snapshot has a version and thousands of rules.
    #[test]
    fn snapshot_loads() {
        assert!(
            version().is_some_and(|v| v.starts_with("20")),
            "{:?}",
            version()
        );
        assert!(load() > 5000);
    }

    /// RFC 3492 §7.1 sample strings and common IDN labels.
    #[test]
    fn punycode_matches_known_encodings() {
        assert_eq!(punycode("bücher").as_deref(), Some("bcher-kva"));
        assert_eq!(punycode("münchen").as_deref(), Some("mnchen-3ya"));
        // RFC 3492 §7.1 (L): Japanese "3年B組金八先生".
        assert_eq!(
            punycode("3年B組金八先生").as_deref(),
            Some("3B-ww4c5e180e575a65lsy2b")
        );
        // 中国 (China's IDN TLD).
        assert_eq!(punycode("中国").as_deref(), Some("fiqs8s"));
    }

    /// The PSL's own test cases (from its `test_psl.txt`), expressed as
    /// organizational domains, plus the private section.
    #[test]
    fn organizational_domains() {
        let org = |d: &str| organizational_domain(d);
        // Ordinary and multi-label suffixes.
        assert_eq!(org("example.com"), Some("example.com".into()));
        assert_eq!(org("b.example.com"), Some("example.com".into()));
        assert_eq!(org("a.b.example.com"), Some("example.com".into()));
        assert_eq!(org("Mail.Example.CO.UK."), Some("example.co.uk".into()));
        assert_eq!(org("com"), None, "a public suffix has none");
        assert_eq!(org("co.uk"), None);
        // Wildcard (*.ck) and its exception (!www.ck).
        assert_eq!(org("test.ck"), None);
        assert_eq!(org("b.test.ck"), Some("b.test.ck".into()));
        assert_eq!(org("www.ck"), Some("www.ck".into()));
        assert_eq!(org("www.www.ck"), Some("www.ck".into()));
        // An unlisted TLD falls back to the implicit `*` rule.
        assert_eq!(org("example.example"), Some("example.example".into()));
        assert_eq!(org("b.example.example"), Some("example.example".into()));
        // Private section: each github.io site is its own organization.
        assert_eq!(org("alice.github.io"), Some("alice.github.io".into()));
        assert_eq!(org("www.alice.github.io"), Some("alice.github.io".into()));
        // IDN suffixes in ASCII form: 公司.cn is xn--55qx5d.cn.
        assert_eq!(
            public_suffix("xn--55qx5d.cn").as_deref(),
            Some("xn--55qx5d.cn")
        );
        assert_eq!(
            org("shishi.xn--55qx5d.cn"),
            Some("shishi.xn--55qx5d.cn".into())
        );
        // Malformed input.
        assert_eq!(org(""), None);
        assert_eq!(org("a..b.com"), None);
    }
}

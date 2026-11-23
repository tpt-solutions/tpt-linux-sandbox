//! Parser and validator for AppArmor profiles.
//!
//! Converts AppArmor filesystem rules to Landlock-compatible rules where a
//! direct mapping exists. Rules without an equivalent are returned by
//! [`AppArmorProfile::unmapped_rules`] so the caller decides how to report
//! them.
//!
//! The parser is pure Rust with no dependency on the system AppArmor library.
//!
//! # Scope
//!
//! - Nested `profile` blocks are rejected (their rules could otherwise widen
//!   the parent profile).
//! - `deny` rules are never turned into grants.
//! - `@{VAR} = value...` definitions are expanded in path patterns; undefined
//!   variables are an error.
//!
//! # Example
//!
//! ```
//! use tpt_l_apparmor_parser::AppArmorProfile;
//!
//! let src = r"
//!     /usr/bin/firefox {
//!       /etc/firefox/** r,
//!       /tmp/** rw,
//!     }
//! ";
//!
//! let profile = AppArmorProfile::parse(src).unwrap();
//! for rule in &profile.rules {
//!     println!("{rule:?}");
//! }
//! ```

use std::collections::BTreeMap;
use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum AppArmorError {
    /// A parse error at a specific line.
    #[error("parse error at line {line}: {message}")]
    Parse {
        /// 1-based line number where the problem was found.
        line: usize,
        /// Human-readable description of the problem.
        message: String,
    },
}

/// A parsed AppArmor profile.
#[derive(Debug, Clone)]
pub struct AppArmorProfile {
    /// Profile name (usually the path to the confined binary).
    pub name: String,
    /// Parsed rules in order of appearance.
    pub rules: Vec<Rule>,
}

/// A single rule extracted from an AppArmor profile.
#[derive(Debug, Clone)]
pub enum Rule {
    /// Filesystem access rule (`/path/** r,` etc.).
    File {
        /// Glob pattern for the matched path (variables already expanded).
        path_pattern: String,
        /// Permission bits parsed from the rule.
        permissions: FilePermissions,
    },
    /// Network access rule.
    Network {
        /// Address domain (e.g. `"inet"`, `"inet6"`, `"unix"`).
        domain: String,
        /// Socket type (e.g. `"stream"`, `"dgram"`).
        kind: String,
        /// Protocol (e.g. `"tcp"`, `"udp"`).
        protocol: String,
    },
    /// Any rule that cannot be mapped to a Landlock rule — preserved for
    /// diagnostic output. Also used for `deny` rules, which never grant access.
    Other(String),
}

/// Filesystem permission bits from an AppArmor file rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FilePermissions {
    /// Read access (`r`).
    pub read: bool,
    /// Write access (`w` / `a`).
    pub write: bool,
    /// Execute access (`x` / `ix` / `px` / `cx` / `ux`).
    pub execute: bool,
    /// Hard-link access (`l`).
    pub link: bool,
}

impl AppArmorProfile {
    /// Parse an AppArmor profile from its textual representation.
    ///
    /// Supports the common subset:
    /// - `profile <name> { … }` (outer block may be omitted, path used as name)
    /// - File rules: `<path-pattern> <perms>,` (several per line allowed)
    /// - Network rules: `network <domain> <kind>,`
    /// - `@{VAR} = value...` variable definitions
    /// - `#include`, `capability`, `signal`, `ptrace`, `dbus`, `unix`, `deny …`
    ///   → [`Rule::Other`]
    ///
    /// # Errors
    ///
    /// Returns [`AppArmorError::Parse`] for nested profiles, unterminated or
    /// unexpected braces, malformed file rules, unknown permission characters,
    /// and references to undefined variables.
    pub fn parse(src: &str) -> Result<Self, AppArmorError> {
        let mut name = String::new();
        let mut rules = Vec::new();
        let mut vars: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut in_profile = false;
        let mut last_line = 0;

        for (idx, raw_line) in src.lines().enumerate() {
            let line_num = idx + 1;
            last_line = line_num;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if let Some(header) = line.strip_suffix('{') {
                if in_profile {
                    return Err(parse_err(
                        line_num,
                        "nested profiles are not supported (they could widen the parent)",
                    ));
                }
                let header = header.trim();
                let candidate = header.strip_prefix("profile").map_or(header, str::trim);
                let first = candidate
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches('"');
                name.clear();
                name.push_str(first);
                in_profile = true;
                continue;
            }

            if line == "}" {
                if !in_profile {
                    return Err(parse_err(line_num, "unexpected '}' outside a profile"));
                }
                in_profile = false;
                continue;
            }

            // A line may hold several comma-terminated statements.
            for stmt in line.split(',') {
                let stmt = stmt.trim();
                if stmt.is_empty() {
                    continue;
                }
                if let Some((var, values)) = parse_variable_def(stmt) {
                    vars.insert(var, values);
                    continue;
                }
                parse_statement(stmt, line_num, &vars, &mut rules)?;
            }
        }

        if in_profile {
            return Err(parse_err(
                last_line,
                "unterminated profile block: missing closing '}'",
            ));
        }

        Ok(AppArmorProfile { name, rules })
    }

    /// Emit Landlock-compatible path rules for every [`Rule::File`] entry.
    ///
    /// Use [`unmapped_rules`](Self::unmapped_rules) to find the rules that were
    /// not converted.
    pub fn landlock_rules(&self) -> Vec<LandlockFileRule> {
        self.rules
            .iter()
            .filter_map(|r| match r {
                Rule::File {
                    path_pattern,
                    permissions,
                } => Some(LandlockFileRule {
                    path_pattern: path_pattern.clone(),
                    permissions: permissions.clone(),
                }),
                Rule::Network { .. } | Rule::Other(_) => None,
            })
            .collect()
    }

    /// Rules with no Landlock equivalent (network, capability, deny, …).
    pub fn unmapped_rules(&self) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| !matches!(r, Rule::File { .. }))
            .collect()
    }
}

fn parse_err(line: usize, message: impl Into<String>) -> AppArmorError {
    AppArmorError::Parse {
        line,
        message: message.into(),
    }
}

/// Remove a `#` comment, ignoring `#` characters inside double quotes.
fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Parse `@{NAME} = a b c` or `@NAME = a b c`.
fn parse_variable_def(stmt: &str) -> Option<(String, Vec<String>)> {
    let rest = stmt.strip_prefix('@')?;
    let (lhs, rhs) = rest.split_once('=')?;
    let name = lhs
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .trim();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let values = rhs
        .split_whitespace()
        .map(|v| v.trim_matches('"').to_owned())
        .collect();
    Some((name.to_owned(), values))
}

fn parse_statement(
    stmt: &str,
    line: usize,
    vars: &BTreeMap<String, Vec<String>>,
    rules: &mut Vec<Rule>,
) -> Result<(), AppArmorError> {
    // `network` must be the whole first word (not e.g. `networkfoo`).
    if let Some(rest) = stmt.strip_prefix("network") {
        if rest.is_empty() || rest.starts_with(char::is_whitespace) {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            rules.push(Rule::Network {
                domain: parts.first().copied().unwrap_or("inet").to_owned(),
                kind: parts.get(1).copied().unwrap_or("stream").to_owned(),
                protocol: parts.get(2).copied().unwrap_or("").to_owned(),
            });
            return Ok(());
        }
    }

    let mut body = stmt;
    loop {
        let before = body;
        for qualifier in ["audit ", "owner "] {
            if let Some(rest) = body.strip_prefix(qualifier) {
                body = rest.trim_start();
            }
        }
        if body == before {
            break;
        }
    }
    // Deny rules never grant anything; keep them only for diagnostics.
    if body.starts_with("deny ") {
        rules.push(Rule::Other(stmt.to_owned()));
        return Ok(());
    }

    // A file rule starts with a path, optionally quoted (quotes allow spaces
    // and '#'), or with a variable reference.
    let unquoted = body.trim_start_matches('"');
    if unquoted.starts_with('/') || unquoted.starts_with("@{") {
        let (path, perm) = split_file_rule(body)
            .ok_or_else(|| parse_err(line, format!("malformed file rule: {stmt:?}")))?;
        let permissions = checked_permissions(perm, line)?;
        for expanded in expand_variables(path, vars, line)? {
            rules.push(Rule::File {
                path_pattern: expanded,
                permissions: permissions.clone(),
            });
        }
        return Ok(());
    }

    rules.push(Rule::Other(stmt.to_owned()));
    Ok(())
}

/// Expand every `@{NAME}` in `path` using the defined values. A variable with
/// several values yields one path per value.
fn expand_variables(
    path: &str,
    vars: &BTreeMap<String, Vec<String>>,
    line: usize,
) -> Result<Vec<String>, AppArmorError> {
    let Some(start) = path.find("@{") else {
        return Ok(vec![path.to_owned()]);
    };
    let end = path[start..]
        .find('}')
        .map(|rel| start + rel)
        .ok_or_else(|| parse_err(line, format!("unterminated variable in {path:?}")))?;
    let name = &path[start + 2..end];
    let values = vars
        .get(name)
        .ok_or_else(|| parse_err(line, format!("undefined variable @{{{name}}}")))?;

    let mut out = Vec::new();
    for value in values {
        let replaced = format!("{}{}{}", &path[..start], value, &path[end + 1..]);
        out.extend(expand_variables(&replaced, vars, line)?);
    }
    Ok(out)
}

/// Split a file rule body into its path and permission parts. The permission
/// string is the last whitespace-separated token; a quoted path may contain
/// spaces.
fn split_file_rule(body: &str) -> Option<(&str, &str)> {
    let idx = body.rfind(char::is_whitespace)?;
    let path = body[..idx].trim().trim_matches('"');
    let perm = body[idx..].trim();
    if path.is_empty() || perm.is_empty() {
        return None;
    }
    Some((path, perm))
}

/// Characters that may appear in an AppArmor file permission string.
const KNOWN_PERM_CHARS: &str = "rwaxmklipcu";

fn checked_permissions(perms: &str, line: usize) -> Result<FilePermissions, AppArmorError> {
    let lower = perms.to_lowercase();
    if let Some(bad) = lower.chars().find(|c| !KNOWN_PERM_CHARS.contains(*c)) {
        return Err(parse_err(
            line,
            format!("unknown permission character {bad:?} in {perms:?}"),
        ));
    }
    Ok(parse_permissions(perms))
}

/// Parse an AppArmor permission string (e.g. `"rwix"`, `"r"`, `"rw"`) into
/// [`FilePermissions`]. Unknown characters are ignored here; use the
/// validating path in [`AppArmorProfile::parse`] for strict checking.
fn parse_permissions(perms: &str) -> FilePermissions {
    let mut fp = FilePermissions::default();
    for ch in perms.to_lowercase().chars() {
        match ch {
            'r' => fp.read = true,
            'w' | 'a' => fp.write = true,
            'x' | 'i' | 'p' | 'c' | 'u' => fp.execute = true,
            'l' => fp.link = true,
            _ => {}
        }
    }
    fp
}

/// A Landlock-compatible filesystem rule derived from an AppArmor file rule.
#[derive(Debug, Clone)]
pub struct LandlockFileRule {
    /// The path pattern from the original AppArmor rule (variables expanded).
    pub path_pattern: String,
    /// The mapped permission set.
    pub permissions: FilePermissions,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r"
/usr/bin/firefox {
  /etc/firefox/** r,
  /tmp/** rw,
  /usr/lib/** rx,
  /home/** l,
  network inet stream,
  capability sys_ptrace,
}
";

    #[test]
    fn parse_profile_name() {
        let p = AppArmorProfile::parse(SAMPLE).unwrap();
        assert_eq!(p.name, "/usr/bin/firefox");
    }

    #[test]
    fn parse_file_rules() {
        let p = AppArmorProfile::parse(SAMPLE).unwrap();
        let files: Vec<_> = p
            .rules
            .iter()
            .filter(|r| matches!(r, Rule::File { .. }))
            .collect();
        assert_eq!(files.len(), 4);
    }

    #[test]
    fn permissions_read_only() {
        let fp = parse_permissions("r");
        assert!(fp.read && !fp.write && !fp.execute && !fp.link);
    }

    #[test]
    fn permissions_read_write() {
        let fp = parse_permissions("rw");
        assert!(fp.read && fp.write && !fp.execute);
    }

    #[test]
    fn permissions_exec() {
        let fp = parse_permissions("rx");
        assert!(fp.read && fp.execute);
    }

    #[test]
    fn permissions_link() {
        let fp = parse_permissions("l");
        assert!(fp.link && !fp.read);
    }

    #[test]
    fn network_rule_parsed() {
        let p = AppArmorProfile::parse(SAMPLE).unwrap();
        let nets: Vec<_> = p
            .rules
            .iter()
            .filter(|r| matches!(r, Rule::Network { .. }))
            .collect();
        assert_eq!(nets.len(), 1);
    }

    #[test]
    fn parse_empty_input() {
        let p = AppArmorProfile::parse("").unwrap();
        assert!(p.rules.is_empty());
    }

    #[test]
    fn file_permissions_default_all_false() {
        let p = FilePermissions::default();
        assert!(!p.read && !p.write && !p.execute && !p.link);
    }

    #[test]
    fn nested_profile_rejected() {
        let src = "/a {\n  /b {\n  }\n}\n";
        assert!(matches!(
            AppArmorProfile::parse(src),
            Err(AppArmorError::Parse { line: 2, .. })
        ));
    }

    #[test]
    fn unterminated_block_rejected() {
        let src = "/a {\n  /b r,\n";
        assert!(AppArmorProfile::parse(src).is_err());
    }

    #[test]
    fn unexpected_close_brace_rejected() {
        assert!(AppArmorProfile::parse("}\n").is_err());
    }

    #[test]
    fn multiple_rules_per_line() {
        let p = AppArmorProfile::parse("/a {\n  /x r, /y rw,\n}\n").unwrap();
        assert_eq!(p.landlock_rules().len(), 2);
    }

    #[test]
    fn deny_rules_do_not_grant() {
        let p = AppArmorProfile::parse("/a {\n  deny /secret r,\n}\n").unwrap();
        assert!(p.landlock_rules().is_empty());
        assert_eq!(p.unmapped_rules().len(), 1);
    }

    #[test]
    fn variables_expand() {
        let src = "/a {\n  @{ROOTS} = /usr /opt\n  @{ROOTS}/lib/** r,\n}\n";
        let p = AppArmorProfile::parse(src).unwrap();
        let paths: Vec<_> = p
            .landlock_rules()
            .into_iter()
            .map(|r| r.path_pattern)
            .collect();
        assert_eq!(paths, vec!["/usr/lib/**", "/opt/lib/**"]);
    }

    #[test]
    fn undefined_variable_rejected() {
        assert!(AppArmorProfile::parse("/a {\n  @{NOPE}/x r,\n}\n").is_err());
    }

    #[test]
    fn network_prefix_is_not_network() {
        let p = AppArmorProfile::parse("/a {\n  networkfoo,\n}\n").unwrap();
        assert!(matches!(p.rules[0], Rule::Other(_)));
    }

    #[test]
    fn hash_inside_quotes_is_not_a_comment() {
        let p = AppArmorProfile::parse("/a {\n  \"/tmp/a#b\" r,\n}\n").unwrap();
        assert_eq!(p.landlock_rules()[0].path_pattern, "/tmp/a#b");
    }

    #[test]
    fn unknown_permission_char_rejected() {
        assert!(AppArmorProfile::parse("/a {\n  /x rz,\n}\n").is_err());
    }
}

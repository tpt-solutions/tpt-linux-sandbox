//! Parser and validator for AppArmor profiles.
//!
//! Converts AppArmor filesystem rules to Landlock-compatible rules where a
//! direct mapping exists, and logs a warning for rules with no equivalent.
//!
//! The parser is pure Rust with no dependency on the system AppArmor library.
//!
//! # Example
//!
//! ```
//! use tpt_l_apparmor_parser::AppArmorProfile;
//!
//! let src = r#"
//!     /usr/bin/firefox {
//!       /etc/firefox/** r,
//!       /tmp/** rw,
//!     }
//! "#;
//!
//! let profile = AppArmorProfile::parse(src).unwrap();
//! for rule in &profile.rules {
//!     println!("{rule:?}");
//! }
//! ```

use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum AppArmorError {
    /// A parse error at a specific line.
    #[error("parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
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
        /// Glob pattern for the matched path.
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
    /// diagnostic output.
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
    /// - File rules: `<path-pattern> <perms>,`
    /// - Network rules: `network <domain> <kind>,`
    /// - `#include`, `capability`, `signal`, `ptrace`, `dbus`, `unix` → [`Rule::Other`]
    pub fn parse(src: &str) -> Result<Self, AppArmorError> {
        let mut name = String::new();
        let mut rules = Vec::new();
        let mut inside_block = false;
        let mut depth: u32 = 0;

        for (lineno, raw_line) in src.lines().enumerate() {
            let line_num = lineno + 1;
            // Strip comments and leading/trailing whitespace.
            let line = match raw_line.find('#') {
                Some(pos) => &raw_line[..pos],
                None => raw_line,
            }
            .trim();

            if line.is_empty() {
                continue;
            }

            // Opening brace — enter profile block.
            if line.ends_with('{') {
                depth += 1;
                if depth == 1 {
                    // Extract profile name from `profile <name> {` or `<name> {`.
                    let header = line.trim_end_matches('{').trim();
                    let candidate = if let Some(rest) = header.strip_prefix("profile") {
                        rest.trim().to_owned()
                    } else {
                        header.to_owned()
                    };
                    // Strip optional flags like `(enforce)` / `(complain)`.
                    name = candidate
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim_matches('"')
                        .to_owned();
                    inside_block = true;
                }
                continue;
            }

            if line == "}" || line.starts_with('}') {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    inside_block = false;
                }
                continue;
            }

            if !inside_block && depth == 0 {
                // Lines before the opening brace — treat as outer profile header.
                continue;
            }

            // Strip trailing comma.
            let stmt = line.trim_end_matches(',').trim();

            // --- Network rule ---
            // `network [domain [type [protocol]]],`
            if let Some(rest) = stmt.strip_prefix("network") {
                let parts: Vec<&str> = rest.split_whitespace().collect();
                rules.push(Rule::Network {
                    domain: parts.first().unwrap_or(&"inet").to_string(),
                    kind: parts.get(1).unwrap_or(&"stream").to_string(),
                    protocol: parts.get(2).unwrap_or(&"").to_string(),
                });
                continue;
            }

            // --- File rule ---
            // `<path> <perms>,` where path starts with `/` or `@{`.
            if stmt.starts_with('/') || stmt.starts_with("@{") {
                if let Some((path_part, perm_part)) = split_file_rule(stmt) {
                    let permissions = parse_permissions(perm_part);
                    rules.push(Rule::File {
                        path_pattern: path_part.to_owned(),
                        permissions,
                    });
                    continue;
                }
                return Err(AppArmorError::Parse {
                    line: line_num,
                    message: format!("malformed file rule: {stmt:?}"),
                });
            }

            // --- Anything else ---
            rules.push(Rule::Other(stmt.to_owned()));
        }

        Ok(AppArmorProfile { name, rules })
    }

    /// Emit Landlock-compatible path rules for every [`Rule::File`] entry
    /// that has a direct mapping.
    ///
    /// Rules with no mapping (network, dbus, etc.) are logged to stderr as
    /// warnings.
    pub fn landlock_rules(&self) -> Vec<LandlockFileRule> {
        self.rules
            .iter()
            .filter_map(|r| match r {
                Rule::File { path_pattern, permissions } => Some(LandlockFileRule {
                    path_pattern: path_pattern.clone(),
                    permissions: permissions.clone(),
                }),
                Rule::Network { domain, kind, protocol } => {
                    eprintln!(
                        "tpt-l-apparmor-parser: network rule \
                         (domain={domain} kind={kind} protocol={protocol}) \
                         has no Landlock equivalent, skipping"
                    );
                    None
                }
                Rule::Other(raw) => {
                    eprintln!(
                        "tpt-l-apparmor-parser: no Landlock mapping for rule: {raw:?}"
                    );
                    None
                }
            })
            .collect()
    }
}

/// Split a file rule into its path and permission parts.
///
/// Handles optional quoting and extra whitespace.
fn split_file_rule(stmt: &str) -> Option<(&str, &str)> {
    // Path ends at the last whitespace-separated token that looks like permissions.
    let tokens: Vec<&str> = stmt.split_whitespace().collect();
    if tokens.len() < 2 {
        return None;
    }
    let perm = tokens.last()?;
    let path = tokens.first()?;
    Some((path, perm))
}

/// Parse an AppArmor permission string (e.g. `"rwix"`, `"r"`, `"rw"`) into
/// [`FilePermissions`].
fn parse_permissions(perms: &str) -> FilePermissions {
    let mut fp = FilePermissions::default();
    let lower = perms.to_lowercase();
    for ch in lower.chars() {
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
    /// The path pattern from the original AppArmor rule.
    pub path_pattern: String,
    /// The mapped permission set.
    pub permissions: FilePermissions,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
/usr/bin/firefox {
  /etc/firefox/** r,
  /tmp/** rw,
  /usr/lib/** rx,
  /home/** l,
  network inet stream,
  capability sys_ptrace,
}
"#;

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
}

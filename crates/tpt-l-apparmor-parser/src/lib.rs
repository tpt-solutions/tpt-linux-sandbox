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
//! println!("profile: {}", profile.name);
//! ```

use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum AppArmorError {
    /// A parse error at a specific line.
    #[error("parse error at line {line}: {message}")]
    Parse { line: usize, message: String },
    /// A profile feature that cannot be represented.
    #[error("unsupported profile feature: {0}")]
    UnsupportedFeature(String),
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
    /// Execute access (`x` / `ix` / `px` / `cx`).
    pub execute: bool,
    /// Link access (`l`).
    pub link: bool,
}

impl AppArmorProfile {
    /// Parse an AppArmor profile from its textual representation.
    pub fn parse(src: &str) -> Result<Self, AppArmorError> {
        // TODO: implement a nom (or hand-rolled) parser for the AppArmor
        // profile grammar:
        //   profile  := name '{' rule* '}'
        //   rule     := file_rule | network_rule | capability_rule | ...
        //   file_rule := path permissions ','
        //
        // For now return a placeholder.
        let _ = src;
        Ok(AppArmorProfile {
            name: String::new(),
            rules: Vec::new(),
        })
    }

    /// Emit Landlock-compatible path rules for every [`Rule::File`] entry
    /// that has a direct mapping.
    ///
    /// Rules with no mapping (e.g. network, dbus) are logged to stderr as
    /// warnings.
    pub fn landlock_rules(&self) -> Vec<LandlockFileRule> {
        self.rules
            .iter()
            .filter_map(|r| match r {
                Rule::File { path_pattern, permissions } => Some(LandlockFileRule {
                    path_pattern: path_pattern.clone(),
                    permissions: permissions.clone(),
                }),
                Rule::Network { .. } => {
                    eprintln!(
                        "tpt-l-apparmor-parser: network rules have no Landlock equivalent, skipping"
                    );
                    None
                }
                Rule::Other(raw) => {
                    eprintln!(
                        "tpt-l-apparmor-parser: no Landlock mapping for rule: {raw}"
                    );
                    None
                }
            })
            .collect()
    }
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

    #[test]
    fn parse_returns_ok_for_empty_input() {
        AppArmorProfile::parse("").unwrap();
    }

    #[test]
    fn file_permissions_default_all_false() {
        let p = FilePermissions::default();
        assert!(!p.read && !p.write && !p.execute && !p.link);
    }
}

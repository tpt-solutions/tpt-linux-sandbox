//! `AppArmor` profile textual format parser with `Landlock` rule emission.

#![deny(missing_docs)]
#![allow(clippy::struct_excessive_bools)]

use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1};
use nom::character::complete::{multispace0, multispace1, space0};
use nom::combinator::opt;
use nom::multi::many0;
use nom::sequence::preceded;
use nom::IResult;
use std::path::PathBuf;
use thiserror::Error;
use tracing::warn;

/// Errors that can occur when parsing `AppArmor` profiles.
#[derive(Debug, Error)]
pub enum AppArmorError {
    /// Parse error at the given position.
    #[error("parse error at position {0}: {1}")]
    ParseError(usize, String),
    /// Invalid rule syntax.
    #[error("invalid rule syntax: {0}")]
    InvalidRule(String),
}

/// Represents a parsed `AppArmor` profile AST.
#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    /// Profile name.
    pub name: String,
    /// Rules within the profile.
    pub rules: Vec<AppArmorRule>,
}

/// A single `AppArmor` rule.
#[derive(Debug, Clone, PartialEq)]
pub enum AppArmorRule {
    /// File access rule.
    FileRule {
        /// Path pattern.
        path: String,
        /// Access permissions.
        permissions: FilePermissions,
    },
    /// Network access rule.
    NetworkRule {
        /// Address family.
        family: String,
        /// Socket type.
        sock_type: String,
        /// Protocol.
        protocol: String,
    },
    /// Capability rule.
    CapabilityRule {
        /// Capability name.
        capability: String,
    },
    /// Mount rule.
    MountRule {
        /// Mount source.
        source: Option<String>,
        /// Mount target.
        target: Option<String>,
        /// Filesystem type.
        fstype: Option<String>,
        /// Mount flags.
        flags: Vec<String>,
    },
    /// Unmount rule.
    UnmountRule {
        /// Target path.
        target: Option<String>,
    },
    /// Ptrace rule.
    PtraceRule {
        /// Permissions.
        permissions: Vec<String>,
    },
    /// Signal rule.
    SignalRule {
        /// Signal permissions.
        permissions: Vec<String>,
    },
    /// Raw unparsed rule.
    Other(String),
}

/// File access permissions.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FilePermissions {
    /// Read permission.
    pub read: bool,
    /// Write permission.
    pub write: bool,
    /// Execute permission.
    pub execute: bool,
    /// Memory-map for execution.
    pub execute_mmap: bool,
    /// Link permission.
    pub link: bool,
    /// Lock permission.
    pub lock: bool,
}

impl FilePermissions {
    /// Parses `AppArmor` permission characters into a `FilePermissions` struct.
    fn parse(input: &str) -> IResult<&str, Self> {
        let (input, chars) = take_while1(|c: char| "rwlkmix".contains(c))(input)?;
        let mut perms = FilePermissions::default();
        for c in chars.chars() {
            match c {
                'r' => perms.read = true,
                'w' => perms.write = true,
                'l' => perms.link = true,
                'k' => perms.lock = true,
                'm' => perms.execute_mmap = true,
                'x' => perms.execute = true,
                _ => {}
            }
        }
        Ok((input, perms))
    }
}

/// Parses an `AppArmor` profile from its textual representation.
///
/// # Errors
///
/// Returns `AppArmorError::ParseError` if the profile cannot be parsed.
pub fn parse_profile(input: &str) -> Result<Profile, AppArmorError> {
    let input = input.trim();
    let (remaining, profile) = parse_profile_inner(input)
        .map_err(|e| AppArmorError::ParseError(input.len(), e.to_string()))?;

    if !remaining.trim().is_empty() {
        warn!("unparsed content after profile: {}", remaining.trim());
    }

    Ok(profile)
}

fn parse_profile_inner(input: &str) -> IResult<&str, Profile> {
    let (input, _) = multispace0(input)?;
    let (input, name) = parse_profile_name(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("{")(input)?;
    let (input, _) = multispace0(input)?;
    let (input, rules) = many0(parse_rule)(input)?;
    let (input, _) = multispace0(input)?;
    let (input, _) = tag("}")(input)?;
    let (input, _) = multispace0(input)?;
    Ok((input, Profile { name, rules }))
}

fn parse_profile_name(input: &str) -> IResult<&str, String> {
    let (input, name) =
        take_while1(|c: char| c.is_alphanumeric() || c == '/' || c == '.' || c == '_' || c == '-')(
            input,
        )?;
    Ok((input, name.to_string()))
}

fn parse_rule(input: &str) -> IResult<&str, AppArmorRule> {
    let (input, _) = multispace0(input)?;
    let (input, rule) = alt((
        parse_capability_rule,
        parse_network_rule,
        parse_mount_rule,
        parse_unmount_rule,
        parse_ptrace_rule,
        parse_signal_rule,
        parse_file_rule,
        parse_other_rule,
    ))(input)?;
    let (input, _) = multispace0(input)?;
    Ok((input, rule))
}

/// Parse a path: sequence of non-whitespace, non-comma characters
fn parse_path(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| !c.is_whitespace() && c != ',')(input)
}

fn parse_file_rule(input: &str) -> IResult<&str, AppArmorRule> {
    // Format: path permissions,
    // But not a reserved keyword like "capability", "network", etc.
    let (input, path) = parse_path(input)?;
    if is_reserved_keyword(path) {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )));
    }
    let (input, _) = multispace1(input)?;
    let (input, perms) = FilePermissions::parse(input)?;
    let (input, _) = opt(tag(","))(input)?;
    Ok((
        input,
        AppArmorRule::FileRule {
            path: path.to_string(),
            permissions: perms,
        },
    ))
}

fn is_reserved_keyword(s: &str) -> bool {
    matches!(
        s,
        "capability" | "network" | "mount" | "umount" | "ptrace" | "signal"
    )
}

fn parse_network_rule(input: &str) -> IResult<&str, AppArmorRule> {
    let (input, _) = tag("network")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, family) = take_while1(|c: char| c.is_alphanumeric())(input)?;
    let (input, sock_type) =
        opt(preceded(multispace1, take_while1(|c: char| !c.is_whitespace() && c != ',')))(input)?;
    let (input, protocol) =
        opt(preceded(multispace1, take_while1(|c: char| !c.is_whitespace() && c != ',')))(input)?;
    let (input, _) = opt(tag(","))(input)?;
    Ok((
        input,
        AppArmorRule::NetworkRule {
            family: family.to_string(),
            sock_type: sock_type.unwrap_or("").to_string(),
            protocol: protocol.unwrap_or("").to_string(),
        },
    ))
}

fn parse_capability_rule(input: &str) -> IResult<&str, AppArmorRule> {
    let (input, _) = tag("capability")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, cap) = take_while1(|c: char| c.is_alphanumeric() || c == '_')(input)?;
    let (input, _) = opt(tag(","))(input)?;
    Ok((
        input,
        AppArmorRule::CapabilityRule {
            capability: cap.to_string(),
        },
    ))
}

fn parse_mount_rule(input: &str) -> IResult<&str, AppArmorRule> {
    let (input, _) = tag("mount")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, source) = opt(take_while1(|c: char| !c.is_whitespace() && c != ','))(input)?;
    let (input, _) = space0(input)?;
    let (input, target) = opt(take_while1(|c: char| !c.is_whitespace() && c != ','))(input)?;
    let (input, _) = space0(input)?;
    let (input, fstype) = opt(take_while1(|c: char| !c.is_whitespace() && c != ','))(input)?;
    let (input, _) = space0(input)?;
    let (input, flags) =
        many0(preceded(space0, take_while1(|c: char| c.is_alphanumeric() || c == '_')))(input)?;
    let (input, _) = opt(tag(","))(input)?;
    Ok((
        input,
        AppArmorRule::MountRule {
            source: source.map(String::from),
            target: target.map(String::from),
            fstype: fstype.map(String::from),
            flags: flags.into_iter().map(String::from).collect(),
        },
    ))
}

fn parse_unmount_rule(input: &str) -> IResult<&str, AppArmorRule> {
    let (input, _) = tag("umount")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, target) = opt(take_while1(|c: char| !c.is_whitespace() && c != ','))(input)?;
    let (input, _) = opt(tag(","))(input)?;
    Ok((
        input,
        AppArmorRule::UnmountRule {
            target: target.map(String::from),
        },
    ))
}

fn parse_ptrace_rule(input: &str) -> IResult<&str, AppArmorRule> {
    let (input, _) = tag("ptrace")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, perms) =
        many0(preceded(space0, take_while1(|c: char| c.is_alphanumeric() || c == '_')))(input)?;
    let (input, _) = opt(tag(","))(input)?;
    Ok((
        input,
        AppArmorRule::PtraceRule {
            permissions: perms.into_iter().map(String::from).collect(),
        },
    ))
}

fn parse_signal_rule(input: &str) -> IResult<&str, AppArmorRule> {
    let (input, _) = tag("signal")(input)?;
    let (input, _) = multispace1(input)?;
    let (input, perms) =
        many0(preceded(space0, take_while1(|c: char| c.is_alphanumeric() || c == '_')))(input)?;
    let (input, _) = opt(tag(","))(input)?;
    Ok((
        input,
        AppArmorRule::SignalRule {
            permissions: perms.into_iter().map(String::from).collect(),
        },
    ))
}

fn parse_other_rule(input: &str) -> IResult<&str, AppArmorRule> {
    let (input, line) = take_while1(|c: char| c != '\n' && c != '}')(input)?;
    Ok((input, AppArmorRule::Other(line.trim().to_string())))
}

/// Emits `Landlock` rules from a parsed `AppArmor` profile.
///
/// Returns a list of warnings for rules that have no `Landlock` equivalent.
#[must_use]
pub fn emit_landlock_rules(profile: &Profile) -> (Vec<(PathBuf, LandlockAccess)>, Vec<String>) {
    let mut rules = Vec::new();
    let mut warnings = Vec::new();

    for rule in &profile.rules {
        match rule {
            AppArmorRule::FileRule {
                path,
                permissions,
            } => {
                let access = permissions.to_landlock_access();
                let pathbuf = PathBuf::from(path);
                rules.push((pathbuf, access));
            }
            AppArmorRule::NetworkRule { .. } => {
                warnings.push("Network rules have no Landlock equivalent".to_string());
            }
            AppArmorRule::CapabilityRule { capability } => {
                warnings.push(format!(
                    "Capability rule '{capability}' has no Landlock equivalent"
                ));
            }
            AppArmorRule::MountRule { .. } => {
                warnings.push("Mount rules have no Landlock equivalent".to_string());
            }
            AppArmorRule::UnmountRule { .. } => {
                warnings.push("Unmount rules have no Landlock equivalent".to_string());
            }
            AppArmorRule::PtraceRule { .. } => {
                warnings.push("Ptrace rules have no Landlock equivalent".to_string());
            }
            AppArmorRule::SignalRule { .. } => {
                warnings.push("Signal rules have no Landlock equivalent".to_string());
            }
            AppArmorRule::Other(text) => {
                warnings.push(format!(
                    "Unparsed rule has no Landlock equivalent: {text}"
                ));
            }
        }
    }

    (rules, warnings)
}

/// Landlock access flags equivalent.
#[derive(Debug, Clone, Default)]
pub struct LandlockAccess {
    /// Read access.
    pub read: bool,
    /// Write access.
    pub write: bool,
    /// Execute access.
    pub execute: bool,
}

impl FilePermissions {
    fn to_landlock_access(&self) -> LandlockAccess {
        LandlockAccess {
            read: self.read,
            write: self.write,
            execute: self.execute || self.execute_mmap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_profile() {
        let input = "/usr/bin/myapp {\n  /etc/ r,\n  /tmp/** rw,\n}";
        let profile = parse_profile(input).unwrap();
        assert_eq!(profile.name, "/usr/bin/myapp");
        assert_eq!(profile.rules.len(), 2);
    }

    #[test]
    fn parse_file_rule_with_permissions() {
        let input = "/test { /etc/ r, }";
        let profile = parse_profile(input).unwrap();
        match &profile.rules[0] {
            AppArmorRule::FileRule {
                path,
                permissions,
            } => {
                assert_eq!(path, "/etc/");
                assert!(permissions.read);
                assert!(!permissions.write);
            }
            _ => panic!("expected file rule"),
        }
    }

    #[test]
    fn parse_capability_rule() {
        let input = "/test { capability net_raw, }";
        let profile = parse_profile(input).unwrap();
        match &profile.rules[0] {
            AppArmorRule::CapabilityRule { capability } => {
                assert_eq!(capability, "net_raw");
            }
            _ => panic!("expected capability rule"),
        }
    }

    #[test]
    fn parse_network_rule() {
        let input = "/test { network inet stream, }";
        let profile = parse_profile(input).unwrap();
        eprintln!("Rules: {:?}", profile.rules);
        assert_eq!(profile.rules.len(), 1, "expected 1 rule");
        match &profile.rules[0] {
            AppArmorRule::NetworkRule {
                family,
                sock_type,
                ..
            } => {
                assert_eq!(family, "inet");
                assert_eq!(sock_type, "stream");
            }
            other => panic!("expected network rule, got {other:?}"),
        }
    }

    #[test]
    fn emit_landlock_with_warnings() {
        let input = "/test { /etc/ r, network inet stream, capability net_raw, }";
        let profile = parse_profile(input).unwrap();
        let (rules, warnings) = emit_landlock_rules(&profile);
        assert_eq!(rules.len(), 1, "expected 1 landlock rule from file rule");
        assert_eq!(warnings.len(), 2, "expected 2 warnings for network + capability");
    }

    #[test]
    fn file_permissions_parse() {
        let (_, perms) = FilePermissions::parse("rlk").unwrap();
        assert!(perms.read);
        assert!(!perms.write);
        assert!(perms.link);
        assert!(perms.lock);
    }
}

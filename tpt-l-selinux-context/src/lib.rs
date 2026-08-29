//! `SELinux` security context parser and manipulator.
//!
//! No `libselinux` dependency — pure Rust implementation.

#![deny(missing_docs)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]

use std::fmt;
use std::fs;
use thiserror::Error;
use tracing::debug;

/// Errors that can occur when parsing or manipulating `SELinux` contexts.
#[derive(Debug, Error)]
pub enum SelinuxError {
    /// The context string is malformed.
    #[error("malformed SELinux context: {0}")]
    MalformedContext(String),
    /// Failed to read the current process context.
    #[error("failed to read /proc/self/attr/current: {0}")]
    ReadFailed(std::io::Error),
}

/// A `SELinux` security context: `user:role:type:level`.
///
/// # Example
///
/// ```
/// use tpt_l_selinux_context::SecurityContext;
///
/// let ctx = SecurityContext::parse("system_u:system_r:init_t:s0").unwrap();
/// assert_eq!(ctx.user(), "system_u");
/// assert_eq!(ctx.role(), "system_r");
/// assert_eq!(ctx.type_(), "init_t");
/// assert_eq!(ctx.level(), "s0");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityContext {
    user: String,
    role: String,
    type_: String,
    level: String,
}

impl SecurityContext {
    /// Parses a `SELinux` context from its string representation.
    ///
    /// The format is `user:role:type:level` where `level` may contain
    /// additional colons (for MLS/MCS ranges).
    ///
    /// # Errors
    ///
    /// Returns `SelinuxError::MalformedContext` if the input has fewer than
    /// three colon-separated fields.
    pub fn parse(input: &str) -> Result<Self, SelinuxError> {
        let trimmed = input.trim();
        let parts: Vec<&str> = trimmed.splitn(4, ':').collect();

        if parts.len() < 3 {
            return Err(SelinuxError::MalformedContext(input.to_string()));
        }

        Ok(Self {
            user: parts[0].to_string(),
            role: parts[1].to_string(),
            type_: parts[2].to_string(),
            level: (*parts.get(3).unwrap_or(&"")).to_string(),
        })
    }

    /// Reads the current process's `SELinux` context from `/proc/self/attr/current`.
    ///
    /// # Errors
    ///
    /// Returns `SelinuxError::ReadFailed` if `/proc/self/attr/current` cannot
    /// be read, or `SelinuxError::MalformedContext` if the content is invalid.
    pub fn current_process() -> Result<Self, SelinuxError> {
        let raw = fs::read_to_string("/proc/self/attr/current")
            .map_err(SelinuxError::ReadFailed)?;
        debug!(context = raw.trim(), "read current SELinux context");
        Self::parse(&raw)
    }

    /// Returns the user field.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// Returns the role field.
    pub fn role(&self) -> &str {
        &self.role
    }

    /// Returns the type field.
    pub fn type_(&self) -> &str {
        &self.type_
    }

    /// Returns the level field (MLS/MCS range).
    pub fn level(&self) -> &str {
        &self.level
    }

    /// Returns the full context as a formatted string.
    pub fn as_str(&self) -> String {
        if self.level.is_empty() {
            format!("{}:{}:{}", self.user, self.role, self.type_)
        } else {
            format!("{}:{}:{}:{}", self.user, self.role, self.type_, self.level)
        }
    }
}

impl fmt::Display for SecurityContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_context() {
        let ctx = SecurityContext::parse("system_u:system_r:init_t:s0").unwrap();
        assert_eq!(ctx.user(), "system_u");
        assert_eq!(ctx.role(), "system_r");
        assert_eq!(ctx.type_(), "init_t");
        assert_eq!(ctx.level(), "s0");
    }

    #[test]
    fn parse_context_without_level() {
        let ctx = SecurityContext::parse("user_u:role_r:type_t").unwrap();
        assert_eq!(ctx.user(), "user_u");
        assert_eq!(ctx.role(), "role_r");
        assert_eq!(ctx.type_(), "type_t");
        assert_eq!(ctx.level(), "");
    }

    #[test]
    fn parse_context_with_mls_range() {
        let ctx = SecurityContext::parse("system_u:system_r:httpd_t:s0-s0:c0.c1023").unwrap();
        assert_eq!(ctx.user(), "system_u");
        assert_eq!(ctx.level(), "s0-s0:c0.c1023");
    }

    #[test]
    fn parse_malformed_context_fails() {
        let result = SecurityContext::parse("invalid");
        assert!(matches!(result, Err(SelinuxError::MalformedContext(_))));
    }

    #[test]
    fn display_formats_correctly() {
        let ctx = SecurityContext::parse("system_u:system_r:init_t:s0").unwrap();
        assert_eq!(ctx.to_string(), "system_u:system_r:init_t:s0");
    }

    #[test]
    fn display_without_level() {
        let ctx = SecurityContext::parse("user_u:role_r:type_t").unwrap();
        assert_eq!(ctx.to_string(), "user_u:role_r:type_t");
    }

    #[test]
    fn parse_strips_whitespace() {
        let ctx = SecurityContext::parse("  system_u:system_r:init_t:s0  \n").unwrap();
        assert_eq!(ctx.user(), "system_u");
    }
}

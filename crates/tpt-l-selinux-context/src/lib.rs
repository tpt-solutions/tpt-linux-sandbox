//! Parse and manipulate SELinux security contexts.
//!
//! Reads contexts from `/proc/self/attr/current` and `getfilecon(3)` via
//! standard file I/O. Does **not** link against `libselinux`.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_selinux_context::SecurityContext;
//!
//! let ctx = SecurityContext::current_process().unwrap();
//! println!("running as: {}", ctx.to_canonical());
//! ```

use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum SelinuxError {
    /// SELinux is not enabled or the context file does not exist.
    #[error("SELinux is not enabled on this system")]
    NotEnabled,
    /// Reading a context file failed.
    #[error("failed to read security context: {0}")]
    Read(#[from] std::io::Error),
    /// The context string does not match the expected `user:role:type[:level]` format.
    #[error("invalid security context format: {0:?}")]
    InvalidFormat(String),
}

/// A parsed SELinux security context (`user:role:type[:level]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityContext {
    /// SELinux user (e.g. `"system_u"`).
    pub user: String,
    /// SELinux role (e.g. `"system_r"`).
    pub role: String,
    /// SELinux type / domain (e.g. `"kernel_t"`).
    pub type_: String,
    /// Optional MLS/MCS level (e.g. `"s0"`).
    pub level: Option<String>,
}

impl SecurityContext {
    /// Parse a security context string of the form `user:role:type` or
    /// `user:role:type:level`.
    pub fn parse(ctx: &str) -> Result<Self, SelinuxError> {
        let trimmed = ctx.trim_end_matches('\0').trim();
        let parts: Vec<&str> = trimmed.splitn(4, ':').collect();
        if parts.len() < 3 || parts[0].is_empty() {
            return Err(SelinuxError::InvalidFormat(ctx.to_owned()));
        }
        Ok(SecurityContext {
            user: parts[0].to_owned(),
            role: parts[1].to_owned(),
            type_: parts[2].to_owned(),
            level: parts.get(3).filter(|s| !s.is_empty()).map(|s| s.to_string()),
        })
    }

    /// Read the SELinux security context of the calling process.
    pub fn current_process() -> Result<Self, SelinuxError> {
        let raw = std::fs::read_to_string("/proc/self/attr/current")
            .map_err(|_| SelinuxError::NotEnabled)?;
        Self::parse(&raw)
    }

    /// Format the context as its canonical colon-delimited string.
    pub fn to_canonical(&self) -> String {
        match &self.level {
            Some(l) => format!("{}:{}:{}:{}", self.user, self.role, self.type_, l),
            None => format!("{}:{}:{}", self.user, self.role, self.type_),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_three_part() {
        let ctx = SecurityContext::parse("unconfined_u:unconfined_r:unconfined_t").unwrap();
        assert_eq!(ctx.user, "unconfined_u");
        assert_eq!(ctx.role, "unconfined_r");
        assert_eq!(ctx.type_, "unconfined_t");
        assert!(ctx.level.is_none());
    }

    #[test]
    fn parse_four_part() {
        let ctx = SecurityContext::parse("system_u:system_r:kernel_t:s0").unwrap();
        assert_eq!(ctx.level.as_deref(), Some("s0"));
    }

    #[test]
    fn roundtrip() {
        let raw = "system_u:system_r:kernel_t:s0";
        let ctx = SecurityContext::parse(raw).unwrap();
        assert_eq!(ctx.to_canonical(), raw);
    }

    #[test]
    fn invalid_format_errors() {
        assert!(matches!(
            SecurityContext::parse("notacontext"),
            Err(SelinuxError::InvalidFormat(_))
        ));
    }
}

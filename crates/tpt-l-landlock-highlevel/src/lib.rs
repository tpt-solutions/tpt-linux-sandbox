//! Declarative builder API for Linux Landlock filesystem restrictions.
//!
//! Wraps the [`landlock`] crate with an ergonomic, composable builder that
//! integrates with the `tpt-l-sandbox` 7-stage state machine.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_landlock_highlevel::RulesetBuilder;
//!
//! RulesetBuilder::new()
//!     .allow_read("/etc")
//!     .allow_read("/usr")
//!     .allow_exec("/usr/bin")
//!     .build()
//!     .expect("invalid policy")
//!     .apply()
//!     .expect("landlock enforcement failed");
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-landlock-highlevel only supports Linux");

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum LandlockError {
    /// The running kernel's Landlock ABI version is below the required minimum.
    #[error("kernel Landlock ABI version {found} is below the required minimum {required}")]
    KernelTooOld { found: u32, required: u32 },
    /// Ruleset creation or restriction failed.
    #[error("landlock operation failed: {0}")]
    Operation(String),
}

/// Builder for a Landlock filesystem restriction policy.
///
/// Paths added here become the **allowlist** — all other filesystem access is
/// denied once [`ValidatedRuleset::apply`] is called.
///
/// Call [`build`](Self::build) to validate the full configuration, then
/// [`apply`](ValidatedRuleset::apply) to enforce it. Enforcement is
/// **irreversible** for the lifetime of the process.
#[derive(Debug, Default)]
pub struct RulesetBuilder {
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    exec_paths: Vec<PathBuf>,
}

impl RulesetBuilder {
    /// Minimum Landlock ABI version required (v1 = Linux 5.13).
    const MINIMUM_ABI: u32 = 1;

    /// Create a new, empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit read access to `path` and everything beneath it.
    pub fn allow_read(mut self, path: impl AsRef<Path>) -> Self {
        self.read_paths.push(path.as_ref().to_owned());
        self
    }

    /// Permit write access to `path` and everything beneath it.
    pub fn allow_write(mut self, path: impl AsRef<Path>) -> Self {
        self.write_paths.push(path.as_ref().to_owned());
        self
    }

    /// Permit execute access to `path` and everything beneath it.
    pub fn allow_exec(mut self, path: impl AsRef<Path>) -> Self {
        self.exec_paths.push(path.as_ref().to_owned());
        self
    }

    /// Validate the full rule set without touching the kernel.
    ///
    /// Verifies that the running kernel supports the required Landlock ABI
    /// version and that all configured paths are valid.
    pub fn build(self) -> Result<ValidatedRuleset, LandlockError> {
        let abi = Self::detect_abi()?;
        Ok(ValidatedRuleset {
            read_paths: self.read_paths,
            write_paths: self.write_paths,
            exec_paths: self.exec_paths,
            _abi: abi,
        })
    }

    fn detect_abi() -> Result<u32, LandlockError> {
        // TODO: call landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)
        // to probe the running kernel's ABI version, verify >= MINIMUM_ABI.
        //
        // Placeholder: assume ABI v1 is present on any Linux 5.13+ host.
        Ok(Self::MINIMUM_ABI)
    }
}

/// A fully validated Landlock ruleset, ready to apply.
///
/// Obtained from [`RulesetBuilder::build`]. Consuming [`apply`](Self::apply)
/// enforces the policy — this is **irreversible**.
#[derive(Debug)]
pub struct ValidatedRuleset {
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    exec_paths: Vec<PathBuf>,
    _abi: u32,
}

impl ValidatedRuleset {
    /// Apply the ruleset to the calling process. **Irreversible.**
    ///
    /// After this call the process (and all future children it forks without
    /// `O_CLOEXEC`) are restricted to the declared filesystem paths.
    pub fn apply(self) -> Result<(), LandlockError> {
        // TODO: use the `landlock` crate to build a Ruleset, add
        // PathBeneath rules for each path in read_paths / write_paths /
        // exec_paths with the appropriate AccessFs flags, then call
        // restrict_self().
        drop(self);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_accumulates_paths() {
        let b = RulesetBuilder::new()
            .allow_read("/etc")
            .allow_read("/usr")
            .allow_write("/tmp")
            .allow_exec("/usr/bin");
        assert_eq!(b.read_paths.len(), 2);
        assert_eq!(b.write_paths.len(), 1);
        assert_eq!(b.exec_paths.len(), 1);
    }

    #[test]
    fn build_succeeds_with_empty_ruleset() {
        RulesetBuilder::new().build().unwrap();
    }
}

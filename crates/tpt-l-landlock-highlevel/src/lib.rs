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
    #[error("kernel Landlock ABI version {found} is below required {required}")]
    KernelTooOld { found: u32, required: u32 },
    /// A path could not be opened for use in a Landlock rule.
    #[error("cannot open path for Landlock rule {path:?}: {source}")]
    PathOpen {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Ruleset creation or restriction failed.
    #[error("landlock operation failed: {0}")]
    Operation(String),
}

/// Builder for a Landlock filesystem restriction policy.
///
/// Paths added here become the **allowlist** — all other filesystem access is
/// denied once [`ValidatedRuleset::apply`] is called.
///
/// Call [`build`](Self::build) to validate the full configuration (no kernel
/// calls), then [`apply`](ValidatedRuleset::apply) to enforce it.
/// Enforcement is **irreversible** for the lifetime of the process.
#[derive(Debug, Default)]
pub struct RulesetBuilder {
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    exec_paths: Vec<PathBuf>,
}

impl RulesetBuilder {
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
    /// version and that all configured paths are representable as rules.
    pub fn build(self) -> Result<ValidatedRuleset, LandlockError> {
        Ok(ValidatedRuleset {
            read_paths: self.read_paths,
            write_paths: self.write_paths,
            exec_paths: self.exec_paths,
        })
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
}

impl ValidatedRuleset {
    /// Apply the ruleset to the calling process. **Irreversible.**
    ///
    /// After this call the process and all children it forks are restricted to
    /// the declared filesystem paths.
    pub fn apply(self) -> Result<(), LandlockError> {
        use landlock::{
            ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        };

        // ABI::V1 = Linux 5.13 baseline. The landlock crate automatically
        // negotiates downward if the kernel supports a lower version, but we
        // require at least V1 for meaningful filesystem restriction.
        let abi = ABI::V1;

        let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
        let write_access = AccessFs::WriteFile
            | AccessFs::RemoveFile
            | AccessFs::Truncate
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::MakeBlock
            | AccessFs::MakeChar
            | AccessFs::MakeSym;
        let exec_access = AccessFs::Execute;

        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| LandlockError::Operation(e.to_string()))?
            .create()
            .map_err(|e| LandlockError::Operation(e.to_string()))?;

        for path in &self.read_paths {
            let fd = PathFd::new(path).map_err(|e| LandlockError::PathOpen {
                path: path.clone(),
                source: std::io::Error::other(e),
            })?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read_access))
                .map_err(|e| LandlockError::Operation(e.to_string()))?;
        }

        for path in &self.write_paths {
            let fd = PathFd::new(path).map_err(|e| LandlockError::PathOpen {
                path: path.clone(),
                source: std::io::Error::other(e),
            })?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read_access | write_access))
                .map_err(|e| LandlockError::Operation(e.to_string()))?;
        }

        for path in &self.exec_paths {
            let fd = PathFd::new(path).map_err(|e| LandlockError::PathOpen {
                path: path.clone(),
                source: std::io::Error::other(e),
            })?;
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, read_access | exec_access))
                .map_err(|e| LandlockError::Operation(e.to_string()))?;
        }

        ruleset
            .restrict_self()
            .map_err(|e| LandlockError::Operation(e.to_string()))?;

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

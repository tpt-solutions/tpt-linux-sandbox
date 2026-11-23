//! Declarative builder API for Linux Landlock filesystem restrictions.
//!
//! Wraps the [`landlock`] crate with an ergonomic, composable builder that
//! integrates with the `tpt-l-sandbox` 7-stage state machine.
//!
//! # Kernel support
//!
//! Rules are requested for Landlock ABI v3 (Linux 6.2+, which adds `Refer` and
//! `Truncate`). The `landlock` crate uses best-effort compatibility, so on older
//! kernels the unsupported rights are dropped and the ruleset is only
//! *partially* enforced. Use [`RulesetBuilder::require_full_enforcement`] to
//! turn that into an error. TCP network rules (ABI v4) are not yet supported.
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
    KernelTooOld {
        /// The ABI version reported by the running kernel.
        found: u32,
        /// The minimum ABI version this crate requires.
        required: u32,
    },
    /// A path could not be opened for use in a Landlock rule.
    #[error("cannot open path for Landlock rule {path:?}: {source}")]
    PathOpen {
        /// The path that could not be opened.
        path: PathBuf,
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Ruleset creation or restriction failed.
    #[error("landlock operation failed: {0}")]
    Operation(String),
    /// Only part of the requested ruleset is enforced by this kernel, and the
    /// caller asked for full enforcement.
    #[error("Landlock partially enforced by this kernel and full enforcement was required")]
    PartiallyEnforced,
}

/// Builder for a Landlock filesystem restriction policy.
///
/// Paths added here become the **allowlist** — all other filesystem access is
/// denied once [`ValidatedRuleset::apply`] is called.
///
/// Call [`build`](Self::build) to validate the full configuration, then
/// [`apply`](ValidatedRuleset::apply) to enforce it. Enforcement is
/// **irreversible** for the lifetime of the process.
#[derive(Debug, Default, Clone)]
pub struct RulesetBuilder {
    read_paths: Vec<PathBuf>,
    write_paths: Vec<PathBuf>,
    exec_paths: Vec<PathBuf>,
    strict: bool,
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

    /// Fail [`apply`](ValidatedRuleset::apply) unless the kernel enforces the
    /// whole ruleset, rather than silently dropping unsupported rights.
    pub fn require_full_enforcement(mut self) -> Self {
        self.strict = true;
        self
    }

    /// Validate the rule set. Every configured path is opened once to confirm
    /// it exists and can be referenced; no restriction is applied yet.
    ///
    /// # Errors
    ///
    /// Returns [`LandlockError::PathOpen`] for the first path that cannot be
    /// opened.
    pub fn build(self) -> Result<ValidatedRuleset, LandlockError> {
        for path in self
            .read_paths
            .iter()
            .chain(&self.write_paths)
            .chain(&self.exec_paths)
        {
            landlock::PathFd::new(path).map_err(|e| LandlockError::PathOpen {
                path: path.clone(),
                source: std::io::Error::other(e),
            })?;
        }
        Ok(ValidatedRuleset {
            read_paths: self.read_paths,
            write_paths: self.write_paths,
            exec_paths: self.exec_paths,
            strict: self.strict,
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
    strict: bool,
}

impl ValidatedRuleset {
    /// Apply the ruleset to the calling process. **Irreversible.**
    ///
    /// After this call the process and all children it forks are restricted to
    /// the declared filesystem paths.
    ///
    /// # Errors
    ///
    /// Returns [`LandlockError::Operation`] if Landlock is not enforced at all,
    /// and [`LandlockError::PartiallyEnforced`] for partial enforcement when the
    /// builder required full enforcement.
    pub fn apply(self) -> Result<(), LandlockError> {
        use landlock::{
            ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
            RulesetStatus,
        };

        // Request ABI v3 rights (Refer, Truncate). The landlock crate's default
        // best-effort mode drops rights the running kernel does not know.
        let abi = ABI::V3;

        let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
        let write_access = AccessFs::WriteFile
            | AccessFs::RemoveFile
            | AccessFs::RemoveDir
            | AccessFs::Truncate
            | AccessFs::Refer
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

        let status = ruleset
            .restrict_self()
            .map_err(|e| LandlockError::Operation(e.to_string()))?;

        // The landlock crate reports an unsupported kernel as `Ok` with
        // `NotEnforced` rather than as an error. Treat that as a failure so
        // callers never believe a restriction is active when it is not.
        match status.ruleset {
            RulesetStatus::NotEnforced => Err(LandlockError::Operation(
                "Landlock is not enforced by this kernel; the ruleset was not applied".to_owned(),
            )),
            RulesetStatus::PartiallyEnforced if self.strict => {
                Err(LandlockError::PartiallyEnforced)
            }
            _ => Ok(()),
        }
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

    #[test]
    fn build_rejects_missing_path() {
        let err = RulesetBuilder::new()
            .allow_read("/definitely/not/a/real/path/tpt")
            .build()
            .unwrap_err();
        assert!(matches!(err, LandlockError::PathOpen { .. }));
    }

    #[test]
    fn strict_flag_is_carried_into_build() {
        let v = RulesetBuilder::new()
            .require_full_enforcement()
            .build()
            .unwrap();
        assert!(v.strict);
    }
}

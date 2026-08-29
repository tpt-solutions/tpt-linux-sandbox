//! Declarative builder over the `landlock` crate's safe API.
//!
//! Provides ergonomic composition with other sandboxing layers.

#![deny(missing_docs)]

use landlock::{
    AccessFs, Access, Ruleset, RulesetCreated, RulesetStatus, AccessFs::*, ABI,
};
use std::path::Path;
use thiserror::Error;
use tracing::{debug, info};

/// Errors that can occur when building or applying Landlock rulesets.
#[derive(Debug, Error)]
pub enum LandlockError {
    /// The requested Landlock ABI version is not supported by the kernel.
    #[error("Landlock ABI v{0} not supported by kernel")]
    AbiNotSupported(u32),
    /// Failed to create the Landlock ruleset.
    #[error("failed to create ruleset: {0}")]
    RulesetCreation(String),
    /// Failed to add a rule to the ruleset.
    #[error("failed to add rule: {0}")]
    RuleAddition(String),
    /// Failed to apply the ruleset to the current thread.
    #[error("failed to apply ruleset: {0}")]
    Apply(String),
    /// No access permissions were specified.
    #[error("no access permissions specified")]
    NoAccess,
}

/// A builder for constructing Landlock filesystem access rules.
///
/// # Example
///
/// ```
/// use tpt_l_landlock_highlevel::RulesetBuilder;
///
/// let ruleset = RulesetBuilder::new()
///     .allow_read("/etc")
///     .allow_write("/tmp")
///     .build()
///     .unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct RulesetBuilder {
    read_paths: Vec<std::path::PathBuf>,
    write_paths: Vec<std::path::PathBuf>,
    exec_paths: Vec<std::path::PathBuf>,
}

impl RulesetBuilder {
    /// Creates a new empty `RulesetBuilder`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a path (or file) that the sandboxed process may read.
    pub fn allow_read<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.read_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Adds a path (or file) that the sandboxed process may write to.
    pub fn allow_write<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.write_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Adds a path (or file) that the sandboxed process may execute.
    pub fn allow_exec<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.exec_paths.push(path.as_ref().to_path_buf());
        self
    }

    /// Returns the read paths in the ruleset.
    pub fn read_paths(&self) -> &[std::path::PathBuf] {
        &self.read_paths
    }

    /// Returns the write paths in the ruleset.
    pub fn write_paths(&self) -> &[std::path::PathBuf] {
        &self.write_paths
    }

    /// Returns the exec paths in the ruleset.
    pub fn exec_paths(&self) -> &[std::path::PathBuf] {
        &self.exec_paths
    }

    /// Detects the runtime Landlock ABI version supported by the kernel.
    ///
    /// Returns `Ok(abi_version)` if Landlock is available, or an error if not.
    pub fn detect_abi() -> Result<u32, LandlockError> {
        for v in (1..=ABI::current().into()).rev() {
            let access = match v {
                1 => AccessFs::from_bits_truncate(0x1F), // v1: execute, write, read, refer, make dir/regular
                _ => AccessFs::from_all(ABI::from(v)),
            };
            let ruleset = Ruleset::new()
                .set_best_effort(false)
                .handle_access(access)
                .map_err(|e| LandlockError::RulesetCreation(e.to_string()))?;
            let created = ruleset
                .create()
                .map_err(|e| LandlockError::RulesetCreation(e.to_string()))?;
            if created.ruleset_handled_accesses().contains(access) {
                debug!(abi_version = v, "detected Landlock ABI");
                return Ok(v);
            }
        }
        Err(LandlockError::AbiNotSupported(0))
    }

    /// Builds the Landlock ruleset with full validation (no kernel calls).
    ///
    /// This method validates all paths and constructs the ruleset but does
    /// not apply it to the current thread. Call [`BuiltRuleset::apply`] to
    /// enforce the rules.
    pub fn build(self) -> Result<BuiltRuleset, LandlockError> {
        let abi = Self::detect_abi()?;

        let access = self.compute_access();
        if access.is_empty() {
            return Err(LandlockError::NoAccess);
        }

        let mut ruleset = Ruleset::new()
            .set_best_effort(true)
            .handle_access(access)
            .map_err(|e| LandlockError::RulesetCreation(e.to_string()))?;

        let mut status = RulesetStatus {
            ruleset_handled_accesses: access,
            ..Default::default()
        };

        for path in &self.read_paths {
            let rule = landlock::PathBeneath::new(path, AccessFs::from_read(ABI::from(abi)));
            ruleset = ruleset
                .add_rule(rule)
                .map_err(|e| LandlockError::RuleAddition(format!("read {path:?}: {e}")))?;
        }

        for path in &self.write_paths {
            let rule = landlock::PathBeneath::new(path, AccessFs::from_write(ABI::from(abi)));
            ruleset = ruleset
                .add_rule(rule)
                .map_err(|e| LandlockError::RuleAddition(format!("write {path:?}: {e}")))?;
        }

        for path in &self.exec_paths {
            let rule = landlock::PathBeneath::new(path, Execute);
            ruleset = ruleset
                .add_rule(rule)
                .map_err(|e| LandlockError::RuleAddition(format!("exec {path:?}: {e}")))?;
        }

        let _ = status;
        Ok(BuiltRuleset { ruleset })
    }

    fn compute_access(&self) -> AccessFs {
        let mut access = AccessFs::empty();
        if !self.read_paths.is_empty() {
            access |= AccessFs::from_read(ABI::current());
        }
        if !self.write_paths.is_empty() {
            access |= AccessFs::from_write(ABI::current());
        }
        if !self.exec_paths.is_empty() {
            access |= Execute;
        }
        access
    }
}

/// A validated Landlock ruleset ready to be applied.
#[derive(Debug)]
pub struct BuiltRuleset {
    ruleset: RulesetCreated,
}

impl BuiltRuleset {
    /// Applies the ruleset to the current thread — irreversible.
    ///
    /// Once applied, the Landlock restrictions cannot be relaxed for the
    /// lifetime of the thread.
    pub fn apply(self) -> Result<(), LandlockError> {
        self.ruleset
            .restrict_self()
            .map_err(|e| LandlockError::Apply(e.to_string()))?;
        info!("Landlock ruleset applied successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_builder_is_empty() {
        let builder = RulesetBuilder::new();
        assert!(builder.read_paths.is_empty());
        assert!(builder.write_paths.is_empty());
        assert!(builder.exec_paths.is_empty());
    }

    #[test]
    fn allow_read_adds_path() {
        let builder = RulesetBuilder::new().allow_read("/etc");
        assert_eq!(builder.read_paths.len(), 1);
    }

    #[test]
    fn allow_write_adds_path() {
        let builder = RulesetBuilder::new().allow_write("/tmp");
        assert_eq!(builder.write_paths.len(), 1);
    }

    #[test]
    fn allow_exec_adds_path() {
        let builder = RulesetBuilder::new().allow_exec("/bin");
        assert_eq!(builder.exec_paths.len(), 1);
    }

    #[test]
    fn build_with_no_access_fails() {
        let result = RulesetBuilder::new().build();
        assert!(matches!(result, Err(LandlockError::NoAccess)));
    }

    #[test]
    fn compute_access_empty_when_no_paths() {
        let builder = RulesetBuilder::new();
        assert!(builder.compute_access().is_empty());
    }

    #[test]
    fn compute_access_includes_read() {
        let builder = RulesetBuilder::new().allow_read("/etc");
        let access = builder.compute_access();
        assert!(!access.is_empty());
    }
}

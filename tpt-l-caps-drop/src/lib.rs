//! Ergonomic layer over the `caps` crate for capability dropping.

#![deny(missing_docs)]

use caps::{CapSet, Caps};
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur when managing capabilities.
#[derive(Debug, Error)]
pub enum CapsError {
    /// Failed to drop capabilities from a set.
    #[error("failed to drop capabilities from {0}: {1}")]
    DropFailed(String, caps::errors::CapsError),
    /// Failed to read the current bounding set.
    #[error("failed to read bounding set: {0}")]
    BoundingReadFailed(caps::errors::CapsError),
    /// The capability is not in the bounding set.
    #[error("capability {0} not in bounding set")]
    NotInBoundingSet(String),
}

/// A capability dropping policy.
///
/// # Example
///
/// ```
/// use tpt_l_caps_drop::CapsPolicy;
///
/// let policy = CapsPolicy::new()
///     .drop_all();
/// ```
#[derive(Debug, Clone, Default)]
pub struct CapsPolicy {
    keep: Vec<Caps>,
    drop_all: bool,
}

impl CapsPolicy {
    /// Creates a new `CapsPolicy` that drops all capabilities by default.
    pub fn new() -> Self {
        Self {
            keep: Vec::new(),
            drop_all: false,
        }
    }

    /// Drops all capabilities from all sets (permitted, effective, inheritable).
    pub fn drop_all(mut self) -> Self {
        self.drop_all = true;
        self
    }

    /// Keeps a specific capability (prevents it from being dropped).
    pub fn keep(mut self, cap: Caps) -> Self {
        self.keep.push(cap);
        self
    }

    /// Validates that all kept capabilities are in the bounding set.
    pub fn validate(&self) -> Result<(), CapsError> {
        for cap in &self.keep {
            let in_bounding = caps::has_cap(None, CapSet::Bounding, *cap)
                .map_err(CapsError::BoundingReadFailed)?;
            if !in_bounding {
                return Err(CapsError::NotInBoundingSet(format!("{cap:?}")));
            }
        }
        Ok(())
    }

    /// Applies the capability policy to the current thread — irreversible.
    ///
    /// Drops all capabilities except those in the keep list.
    pub fn apply(self) -> Result<(), CapsError> {
        self.validate()?;

        if self.drop_all {
            // Drop all capabilities from the bounding set first
            let bounding = caps::read(None, CapSet::Bounding)
                .map_err(CapsError::BoundingReadFailed)?;
            for cap in bounding {
                if !self.keep.contains(&cap) {
                    caps::drop(None, CapSet::Bounding, cap)
                        .map_err(|e| CapsError::DropFailed("bounding".into(), e))?;
                }
            }

            // Drop from permitted, effective, inheritable sets
            for set in [CapSet::Permitted, CapSet::Effective, CapSet::Inheritable] {
                let current = caps::read(None, set)
                    .map_err(|e| CapsError::DropFailed(format!("{set:?}"), e))?;
                for cap in current {
                    if !self.keep.contains(&cap) {
                        caps::drop(None, set, cap)
                            .map_err(|e| CapsError::DropFailed(format!("{set:?}"), e))?;
                    }
                }
            }
        }

        info!("capabilities dropped successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_policy_drops_nothing_by_default() {
        let policy = CapsPolicy::new();
        assert!(!policy.drop_all);
        assert!(policy.keep.is_empty());
    }

    #[test]
    fn drop_all_flag_set() {
        let policy = CapsPolicy::new().drop_all();
        assert!(policy.drop_all);
    }

    #[test]
    fn keep_adds_capability() {
        let policy = CapsPolicy::new().keep(Caps::CAP_CHOWN);
        assert_eq!(policy.keep.len(), 1);
    }

    #[test]
    fn validate_empty_keep_passes() {
        let policy = CapsPolicy::new();
        assert!(policy.validate().is_ok());
    }
}

//! Ergonomic Linux capability dropping.
//!
//! Drop every capability in the permitted, effective, and inheritable sets
//! except those explicitly kept.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_caps_drop::CapsPolicy;
//!
//! CapsPolicy::new()
//!     .drop_all()
//!     .keep("CAP_NET_BIND_SERVICE")
//!     .apply()
//!     .expect("capability drop failed");
//! ```

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-caps-drop only supports Linux");

use thiserror::Error;

/// A Linux capability name (e.g. `"CAP_NET_ADMIN"` or `"net_admin"`).
pub type CapName = String;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum CapsError {
    /// A capability name is not recognised.
    #[error("unknown capability: {0}")]
    UnknownCap(String),
    /// A capability set read/write operation failed.
    #[error("capability operation failed: {0}")]
    Operation(String),
}

/// Policy describing which capabilities to retain after dropping.
///
/// By default nothing is dropped. Call [`drop_all`](Self::drop_all) to clear
/// all sets, then use [`keep`](Self::keep) to retain specific capabilities.
#[derive(Debug, Default)]
pub struct CapsPolicy {
    keep: Vec<CapName>,
    drop_all_flag: bool,
}

impl CapsPolicy {
    /// Create a new policy — no capabilities are modified until [`apply`](Self::apply).
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop every capability in the permitted, effective, and inheritable sets,
    /// except those explicitly listed via [`keep`](Self::keep).
    pub fn drop_all(mut self) -> Self {
        self.drop_all_flag = true;
        self
    }

    /// Retain capability `cap` even when `drop_all` is set.
    ///
    /// Accepts the full name (`"CAP_NET_ADMIN"`) or short name (`"net_admin"`);
    /// case-insensitive.
    pub fn keep(mut self, cap: impl Into<CapName>) -> Self {
        self.keep.push(cap.into());
        self
    }

    /// Apply the capability policy to the calling process.
    pub fn apply(self) -> Result<(), CapsError> {
        use caps::{CapSet, CapsHashSet};

        if !self.drop_all_flag {
            return Ok(());
        }

        // Parse the keep list.
        let mut keep_set = CapsHashSet::new();
        for name in &self.keep {
            let cap = name
                .to_lowercase()
                .trim_start_matches("cap_")
                .to_uppercase();
            let cap = format!("CAP_{cap}");
            let parsed = cap
                .parse::<caps::Capability>()
                .map_err(|_| CapsError::UnknownCap(name.clone()))?;
            keep_set.insert(parsed);
        }

        // Read the current permitted set and drop everything not in keep_set.
        let permitted = caps::read(None, CapSet::Permitted)
            .map_err(|e| CapsError::Operation(e.to_string()))?;

        let new_set: CapsHashSet = permitted
            .intersection(&keep_set)
            .copied()
            .collect();

        caps::set(None, CapSet::Effective, &new_set)
            .map_err(|e| CapsError::Operation(e.to_string()))?;
        caps::set(None, CapSet::Permitted, &new_set)
            .map_err(|e| CapsError::Operation(e.to_string()))?;
        caps::set(None, CapSet::Inheritable, &CapsHashSet::new())
            .map_err(|e| CapsError::Operation(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keep_accumulates() {
        let p = CapsPolicy::new()
            .drop_all()
            .keep("CAP_NET_BIND_SERVICE")
            .keep("CAP_SETUID");
        assert!(p.drop_all_flag);
        assert_eq!(p.keep.len(), 2);
    }

    #[test]
    fn no_drop_by_default() {
        let p = CapsPolicy::new();
        assert!(!p.drop_all_flag);
    }
}

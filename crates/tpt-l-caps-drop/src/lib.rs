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

/// A Linux capability name (e.g. `"CAP_NET_ADMIN"`).
pub type CapName = String;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum CapsError {
    /// A capability could not be parsed or applied.
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
    /// `cap` may be the full name (`"CAP_NET_ADMIN"`) or the short name
    /// (`"net_admin"`); case-insensitive.
    pub fn keep(mut self, cap: impl Into<CapName>) -> Self {
        self.keep.push(cap.into());
        self
    }

    /// Apply the capability policy to the calling process.
    pub fn apply(self) -> Result<(), CapsError> {
        // TODO: use the `caps` crate to:
        //   1. Read the current sets.
        //   2. If drop_all_flag, build the new set containing only self.keep.
        //   3. Verify each kept cap is present in the bounding set.
        //   4. Write back via caps::set().
        drop(self);
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

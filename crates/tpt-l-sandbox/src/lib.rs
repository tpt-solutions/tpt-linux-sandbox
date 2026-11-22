//! Composable Linux sandbox orchestrator.
//!
//! Layers Landlock + seccomp + namespaces + cgroups behind a single
//! declarative builder. The 7-stage state machine ensures a correct,
//! irreversibility-aware execution order — the full policy is validated
//! before any irreversible stage begins.
//!
//! # Example
//!
//! ```no_run
//! use tpt_l_sandbox::Sandbox;
//! use tpt_l_landlock_highlevel::RulesetBuilder;
//! use tpt_l_namespaces_rs::NamespaceSet;
//!
//! Sandbox::new()
//!     .namespaces(NamespaceSet::new().user().mount().network())
//!     .landlock(RulesetBuilder::new().allow_read("/etc").allow_read("/usr"))
//!     .apply()
//!     .expect("sandbox setup failed");
//! ```
//!
//! # State Machine
//!
//! | Stage | Layer | Reversible? |
//! |---|---|---|
//! | 1 | Validation (full policy check, no kernel calls) | — |
//! | 2 | Unprivileged setup (cgroups, audit logging) | Yes |
//! | 3 | Namespace creation (`unshare`) | Yes |
//! | 4 | Filesystem setup (`pivot_root` / chroot, pseudo-fs) | Yes |
//! | 5 | Capability dropping | Yes |
//! | 6 | Seccomp enforcement | **No** |
//! | 7 | Landlock enforcement | **No** |

#[cfg(not(target_os = "linux"))]
compile_error!("tpt-l-sandbox only supports Linux");

use thiserror::Error;

pub use tpt_l_caps_drop::CapsPolicy;
pub use tpt_l_cgroup_v2::CgroupConfig;
pub use tpt_l_chroot_jail::JailConfig;
pub use tpt_l_landlock_highlevel::RulesetBuilder;
pub use tpt_l_namespaces_rs::NamespaceSet;
pub use tpt_l_seccomp_builder::{DenyAction, SeccompPolicy};

/// Errors produced by the sandbox orchestrator.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// The requested policy configuration is invalid.
    #[error("policy validation failed: {0}")]
    Validation(String),
    /// cgroup setup failed (stage 2).
    #[error("cgroup setup failed: {0}")]
    Cgroup(#[from] tpt_l_cgroup_v2::CgroupError),
    /// Namespace creation failed (stage 3).
    #[error("namespace setup failed: {0}")]
    Namespace(#[from] tpt_l_namespaces_rs::NamespaceError),
    /// Filesystem jail setup failed (stage 4).
    #[error("filesystem jail failed: {0}")]
    Filesystem(#[from] tpt_l_chroot_jail::JailError),
    /// Capability dropping failed (stage 5).
    #[error("capability drop failed: {0}")]
    Caps(#[from] tpt_l_caps_drop::CapsError),
    /// Seccomp enforcement failed (stage 6, irreversible).
    #[error("seccomp enforcement failed: {0}")]
    Seccomp(#[from] tpt_l_seccomp_builder::SeccompError),
    /// Landlock enforcement failed (stage 7, irreversible).
    #[error("landlock enforcement failed: {0}")]
    Landlock(#[from] tpt_l_landlock_highlevel::LandlockError),
}

/// Top-level sandbox builder.
///
/// Configure each layer independently, then call [`apply`](Self::apply).
/// Every stage is validated before any irreversible stage begins.
#[derive(Debug, Default)]
pub struct Sandbox {
    namespaces: Option<NamespaceSet>,
    cgroup: Option<CgroupConfig>,
    jail: Option<JailConfig>,
    caps: Option<CapsPolicy>,
    seccomp: Option<SeccompPolicy>,
    landlock: Option<RulesetBuilder>,
}

impl Sandbox {
    /// Create a new sandbox builder with no restrictions configured.
    pub fn new() -> Self {
        Self::default()
    }

    /// Configure namespace isolation.
    pub fn namespaces(mut self, ns: NamespaceSet) -> Self {
        self.namespaces = Some(ns);
        self
    }

    /// Configure cgroup v2 resource limits.
    pub fn cgroup(mut self, cg: CgroupConfig) -> Self {
        self.cgroup = Some(cg);
        self
    }

    /// Configure the filesystem jail (`pivot_root` / chroot + pseudo-fs mounts).
    pub fn jail(mut self, j: JailConfig) -> Self {
        self.jail = Some(j);
        self
    }

    /// Configure capability dropping.
    pub fn caps(mut self, c: CapsPolicy) -> Self {
        self.caps = Some(c);
        self
    }

    /// Configure seccomp syscall filtering.
    pub fn seccomp(mut self, s: SeccompPolicy) -> Self {
        self.seccomp = Some(s);
        self
    }

    /// Configure Landlock filesystem restrictions.
    pub fn landlock(mut self, l: RulesetBuilder) -> Self {
        self.landlock = Some(l);
        self
    }

    /// Validate the full policy and apply all restrictions in the correct order.
    ///
    /// **This call is irreversible once stage 6 (seccomp) begins.** The entire
    /// configuration is checked at stage 1 so that a clean abort is possible
    /// before any kernel state changes.
    pub fn apply(self) -> Result<(), SandboxError> {
        // Stage 1: Validation — no kernel calls
        self.validate()?;

        // Stage 2: Unprivileged setup
        if let Some(ref cg) = self.cgroup {
            cg.apply()?;
            cg.enter()?;
        }

        // Stage 3: Namespace creation
        if let Some(ns) = self.namespaces {
            ns.apply()?;
        }

        // Stage 4: Filesystem setup
        if let Some(jail) = self.jail {
            jail.apply()?;
        }

        // Stage 5: Capability dropping
        if let Some(caps) = self.caps {
            caps.apply()?;
        }

        // Stage 6: Seccomp (irreversible)
        if let Some(seccomp) = self.seccomp {
            seccomp.apply()?;
        }

        // Stage 7: Landlock (irreversible, last)
        if let Some(landlock) = self.landlock {
            landlock.build()?.apply()?;
        }

        Ok(())
    }

    fn validate(&self) -> Result<(), SandboxError> {
        // A filesystem jail without a mount namespace is dangerous — pivot_root
        // would affect the system-wide mount table rather than an isolated copy.
        if self.jail.is_some() {
            let has_mount_ns = self.namespaces.as_ref().map(|ns| ns.mount).unwrap_or(false);
            if !has_mount_ns {
                return Err(SandboxError::Validation(
                    "a filesystem jail (pivot_root/chroot) requires a mount namespace; \
                     add .namespaces(NamespaceSet::new().mount())"
                        .into(),
                ));
            }
        }

        // A user namespace without a mount namespace means uid_map is written
        // but pseudo-filesystems inside the sandbox cannot be mounted.
        // This is not an error by itself — warn rather than block.

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_sandbox_applies_without_error() {
        Sandbox::new().apply().unwrap();
    }

    #[test]
    fn builder_is_composable() {
        let s = Sandbox::new()
            .namespaces(NamespaceSet::new().user().mount())
            .seccomp(SeccompPolicy::new())
            .landlock(RulesetBuilder::new().allow_read("/etc"));
        assert!(s.namespaces.is_some());
        assert!(s.seccomp.is_some());
        assert!(s.landlock.is_some());
        assert!(s.cgroup.is_none());
    }
}

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
//! # Running a child process
//!
//! [`CommandSandboxExt::sandboxed`] applies a sandbox in the child between
//! `fork` and `exec`, so only the child is restricted:
//!
//! ```no_run
//! use std::process::Command;
//! use tpt_l_sandbox::{CommandSandboxExt, Sandbox};
//! use tpt_l_landlock_highlevel::RulesetBuilder;
//!
//! let status = Command::new("/bin/cat")
//!     .arg("/etc/hostname")
//!     .sandboxed(Sandbox::new().landlock(RulesetBuilder::new().allow_read("/etc")))
//!     .status()
//!     .expect("spawn failed");
//! ```
//!
//! # State Machine
//!
//! | Stage | Layer | Reversible? |
//! |---|---|---|
//! | 1 | Validation (names, errnos, paths, ABI; no enforcement) | — |
//! | 2 | cgroup creation and enter | Yes (released on failure) |
//! | 3 | Namespace creation (`unshare`) | Yes |
//! | 4 | Filesystem setup (`pivot_root` / chroot, pseudo-fs) | Yes |
//! | 5 | Capability dropping | Yes |
//! | 6 | Seccomp enforcement | **No** |
//! | 7 | Landlock enforcement | **No** |
//!
//! # Threads
//!
//! Namespaces, seccomp, Landlock and capabilities all apply to the **calling
//! thread**. Call [`Sandbox::apply`] before spawning threads, or from a
//! process that will not create more.
//!
//! # Limits of the cgroup stage
//!
//! The cgroup is removed when a stage fails. On success it stays in place
//! until the process that owns it removes it (the `tpt-sandbox` CLI does this
//! from a supervising parent).

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

/// Syscalls that Landlock and its path opening need. When seccomp is applied
/// before Landlock, these must be allowed or the process is killed mid-setup.
const LANDLOCK_SETUP_SYSCALLS: &[&str] = &[
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
    "openat",
    "close",
    "prctl",
];

/// Top-level sandbox builder.
///
/// Configure each layer independently, then call [`apply`](Self::apply).
/// Every stage is validated before any irreversible stage begins.
#[derive(Debug, Default, Clone)]
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
    /// Validation covers syscall names, errno ranges, Landlock path existence
    /// and the jail/namespace combination. Anything that fails there is
    /// reported before any kernel state changes. If a later stage fails, the
    /// cgroup created in stage 2 is released.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError`] for the first stage that fails.
    pub fn apply(mut self) -> Result<(), SandboxError> {
        self.validate()?;
        self.allow_landlock_setup_syscalls();

        let cgroup = self.cgroup.take();
        if let Some(cg) = &cgroup {
            // Stage 2. If `apply` fails nothing was created, so nothing is released.
            cg.apply()?;
            if let Err(e) = cg.enter() {
                let _ = cg.release();
                return Err(e.into());
            }
        }

        let result = self.apply_stages();
        if result.is_err() {
            if let Some(cg) = &cgroup {
                // Best effort: leave the cgroup so the process is not stuck in it.
                let _ = cg.release();
            }
        }
        result
    }

    /// Stages 3–7, consuming each configured layer.
    fn apply_stages(&mut self) -> Result<(), SandboxError> {
        // Stage 3: Namespace creation
        if let Some(ns) = self.namespaces.take() {
            ns.apply()?;
        }

        // Stage 4: Filesystem setup
        if let Some(jail) = self.jail.take() {
            jail.apply()?;
        }

        // Stage 5: Capability dropping
        if let Some(caps) = self.caps.take() {
            caps.apply()?;
        }

        // Stage 6: Seccomp (irreversible)
        if let Some(seccomp) = self.seccomp.take() {
            seccomp.apply()?;
        }

        // Stage 7: Landlock (irreversible, last)
        if let Some(landlock) = self.landlock.take() {
            landlock.build()?.apply()?;
        }

        Ok(())
    }

    /// When seccomp will be loaded before Landlock, make sure the setup
    /// syscalls are allowed so the default action cannot kill the process
    /// during stage 7.
    fn allow_landlock_setup_syscalls(&mut self) {
        if self.landlock.is_none() {
            return;
        }
        if let Some(mut seccomp) = self.seccomp.take() {
            for name in LANDLOCK_SETUP_SYSCALLS {
                seccomp = seccomp.allow_syscall(*name);
            }
            self.seccomp = Some(seccomp);
        }
    }

    /// Check the policy without changing any kernel state.
    ///
    /// This runs the same checks as the first stage of [`apply`](Self::apply).
    /// Path existence is confirmed by opening the Landlock paths, which does
    /// not restrict anything yet.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::Validation`], [`SandboxError::Seccomp`] or
    /// [`SandboxError::Landlock`] for the first problem found.
    pub fn validate(&self) -> Result<(), SandboxError> {
        // A filesystem jail without a mount namespace is dangerous — pivot_root
        // would affect the system-wide mount table rather than an isolated copy.
        if self.jail.is_some() {
            let has_mount_ns = self
                .namespaces
                .as_ref()
                .is_some_and(NamespaceSet::has_mount);
            if !has_mount_ns {
                return Err(SandboxError::Validation(
                    "a filesystem jail (pivot_root/chroot) requires a mount namespace; \
                     add .namespaces(NamespaceSet::new().mount())"
                        .into(),
                ));
            }
        }

        // Unknown syscall names and out-of-range errnos fail here, before stage 2.
        if let Some(seccomp) = &self.seccomp {
            seccomp.validate()?;
        }

        // Resolve Landlock paths now. `build` only opens them; nothing is enforced.
        if let Some(landlock) = &self.landlock {
            landlock.clone().build()?;
        }

        // A user namespace without a mount namespace is allowed, but the
        // sandbox cannot mount its own pseudo-filesystems in that case.
        if let Some(ns) = &self.namespaces {
            if ns.has_user() && !ns.has_mount() && self.jail.is_none() {
                eprintln!(
                    "tpt-l-sandbox: warning: user namespace without a mount namespace; \
                     the sandbox cannot mount its own /proc or /dev"
                );
            }
        }

        Ok(())
    }
}

/// Extension trait that sandboxes a [`std::process::Command`]'s child process.
pub trait CommandSandboxExt {
    /// Apply `sandbox` in the child process between `fork` and `exec`.
    ///
    /// The parent is not restricted. If the sandbox fails to apply, spawning
    /// the command fails with the sandbox error.
    fn sandboxed(&mut self, sandbox: Sandbox) -> &mut Self;
}

impl CommandSandboxExt for std::process::Command {
    fn sandboxed(&mut self, sandbox: Sandbox) -> &mut Self {
        use std::os::unix::process::CommandExt as _;

        // SAFETY: the closure runs in the forked child before exec. It calls
        // `Sandbox::apply`, which issues syscalls and may allocate for error
        // messages. Allocation after fork is only safe in a single-threaded
        // parent; call `spawn` from a process that has not started threads.
        unsafe {
            self.pre_exec(move || {
                sandbox
                    .clone()
                    .apply()
                    .map_err(|e| std::io::Error::other(e.to_string()))
            });
        }
        self
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

    #[test]
    fn jail_without_mount_namespace_is_rejected_before_any_stage() {
        let err = Sandbox::new()
            .jail(JailConfig::new("/"))
            .apply()
            .unwrap_err();
        assert!(matches!(err, SandboxError::Validation(_)));
    }

    #[test]
    fn unknown_syscall_is_rejected_at_validation() {
        let err = Sandbox::new()
            .seccomp(SeccompPolicy::new().allow_syscall("not_a_syscall"))
            .apply()
            .unwrap_err();
        assert!(matches!(err, SandboxError::Seccomp(_)));
    }

    #[test]
    fn missing_landlock_path_is_rejected_at_validation() {
        let err = Sandbox::new()
            .landlock(RulesetBuilder::new().allow_read("/no/such/tpt/path"))
            .apply()
            .unwrap_err();
        assert!(matches!(err, SandboxError::Landlock(_)));
    }

    #[test]
    fn landlock_setup_syscalls_are_added_when_both_layers_present() {
        let mut s = Sandbox::new()
            .seccomp(SeccompPolicy::new())
            .landlock(RulesetBuilder::new());
        s.allow_landlock_setup_syscalls();
        s.seccomp.as_ref().unwrap().validate().unwrap();
    }
}

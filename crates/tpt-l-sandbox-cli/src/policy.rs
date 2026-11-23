//! Policy model: built-in profiles, policy files, merging, and AppArmor import.
//!
//! A policy is the same TOML schema whether it comes from a built-in profile
//! (`--profile`), a file (`--policy`), an AppArmor profile (`--from-apparmor`)
//! or command-line flags. Later sources extend lists and override scalars.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

/// Names accepted by `--profile` and `--print-profile`.
pub const PRESET_NAMES: &[&str] = &[
    "strict",
    "build",
    "network-client",
    "maintainer-script",
    "untrusted-python",
    "untrusted-node",
];

/// The policy file JSON Schema, embedded so `--print-schema` works offline.
/// The copy lives in this crate so it ships in the published package; a test
/// keeps it identical to `schemas/policy.schema.json` at the repository root.
pub const SCHEMA_TEXT: &str = include_str!("../schema/policy.schema.json");

/// Where editors can fetch the schema. Written as the first line of
/// `--print-profile` output so Taplo and VS Code associate the file with it.
pub const SCHEMA_URL: &str = "https://raw.githubusercontent.com/TPT-Solutions/tpt-linux-sandbox/master/schemas/policy.schema.json";

/// The embedded TOML text for a built-in profile.
pub fn preset_text(name: &str) -> Option<&'static str> {
    Some(match name {
        "strict" => include_str!("../profiles/strict.toml"),
        "build" => include_str!("../profiles/build.toml"),
        "network-client" => include_str!("../profiles/network-client.toml"),
        "maintainer-script" => include_str!("../profiles/maintainer-script.toml"),
        "untrusted-python" => include_str!("../profiles/untrusted-python.toml"),
        "untrusted-node" => include_str!("../profiles/untrusted-node.toml"),
        _ => return None,
    })
}

/// A complete sandbox policy.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Policy {
    /// Paths the command may read.
    pub allow_read: Vec<PathBuf>,
    /// Paths the command may read and write.
    pub allow_write: Vec<PathBuf>,
    /// Paths the command may execute from.
    pub allow_exec: Vec<PathBuf>,
    /// Grant read and exec on standard system directories (default `true`).
    pub system_paths: Option<bool>,
    /// Give the command its own network namespace with no external access.
    pub no_network: bool,
    /// Drop all Linux capabilities before exec.
    pub drop_caps: bool,
    /// Memory limit in bytes (cgroup `memory.max`).
    pub memory_limit: Option<u64>,
    /// CPU quota as a percentage of one core, 1–100.
    pub cpu_quota: Option<u32>,
    /// Maximum number of processes and threads (cgroup `pids.max`).
    pub pids_limit: Option<u32>,
    /// Use this directory as the new root (pivot_root / chroot).
    pub new_root: Option<PathBuf>,
    /// Working directory for the command (inside `new_root` if one is set).
    pub cwd: Option<PathBuf>,
    /// Seccomp mode: `enforce` (default), `log`, or `off`.
    pub seccomp: Option<String>,
    /// Environment variables to pass through in addition to the defaults.
    pub pass_env: Vec<String>,
    /// Run the command in its own PID namespace (default `true`).
    pub pid_namespace: Option<bool>,
    /// Isolate abstract Unix sockets and signals from the host (default `true`).
    pub isolate_ipc: Option<bool>,
    /// TCP ports the command may bind (Linux 6.7+).
    pub allow_tcp_bind: Vec<u16>,
    /// TCP ports the command may connect to (Linux 6.7+).
    pub allow_tcp_connect: Vec<u16>,
}

impl Policy {
    /// Load a built-in profile by name.
    pub fn from_preset(name: &str) -> Result<Self> {
        let text = preset_text(name).with_context(|| {
            format!(
                "unknown profile {name:?}; available: {}",
                PRESET_NAMES.join(", ")
            )
        })?;
        toml::from_str(text).with_context(|| format!("built-in profile {name:?} is invalid"))
    }

    /// Load a policy file.
    pub fn from_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read policy file {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("invalid policy file {}", path.display()))
    }

    /// Build a policy from an AppArmor profile's file rules.
    ///
    /// Rules are mapped to read, write and exec grants. Glob patterns are
    /// widened to their directory, because Landlock grants whole subtrees;
    /// the warnings name every widened or unmapped rule.
    pub fn from_apparmor(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read AppArmor profile {}", path.display()))?;
        let profile = tpt_l_apparmor_parser::AppArmorProfile::parse(&text)
            .with_context(|| format!("cannot parse AppArmor profile {}", path.display()))?;

        let mut policy = Self::default();
        for rule in profile.landlock_rules() {
            let Some(target) = glob_to_directory(&rule.path_pattern) else {
                eprintln!(
                    "tpt-sandbox: warning: AppArmor path {:?} cannot be mapped; not granted",
                    rule.path_pattern
                );
                continue;
            };
            if rule.path_pattern.contains('*') {
                eprintln!(
                    "tpt-sandbox: warning: AppArmor glob {:?} widened to {}",
                    rule.path_pattern,
                    target.display()
                );
            }
            let perms = &rule.permissions;
            if perms.read {
                policy.allow_read.push(target.clone());
            }
            if perms.write {
                policy.allow_write.push(target.clone());
            }
            if perms.execute {
                policy.allow_exec.push(target);
            }
        }
        for rule in profile.unmapped_rules() {
            eprintln!("tpt-sandbox: warning: AppArmor rule not enforced: {rule:?}");
        }
        Ok(policy)
    }

    /// Merge `other` into `self`. Lists are extended; booleans are OR-ed;
    /// scalar options are replaced when `other` sets them.
    pub fn merge(&mut self, other: Self) {
        self.allow_read.extend(other.allow_read);
        self.allow_write.extend(other.allow_write);
        self.allow_exec.extend(other.allow_exec);
        self.pass_env.extend(other.pass_env);
        self.allow_tcp_bind.extend(other.allow_tcp_bind);
        self.allow_tcp_connect.extend(other.allow_tcp_connect);
        if other.pid_namespace.is_some() {
            self.pid_namespace = other.pid_namespace;
        }
        if other.isolate_ipc.is_some() {
            self.isolate_ipc = other.isolate_ipc;
        }
        self.no_network |= other.no_network;
        self.drop_caps |= other.drop_caps;
        if other.system_paths.is_some() {
            self.system_paths = other.system_paths;
        }
        if other.memory_limit.is_some() {
            self.memory_limit = other.memory_limit;
        }
        if other.cpu_quota.is_some() {
            self.cpu_quota = other.cpu_quota;
        }
        if other.pids_limit.is_some() {
            self.pids_limit = other.pids_limit;
        }
        if other.new_root.is_some() {
            self.new_root = other.new_root;
        }
        if other.cwd.is_some() {
            self.cwd = other.cwd;
        }
        if other.seccomp.is_some() {
            self.seccomp = other.seccomp;
        }
    }

    /// Whether the command gets its own PID namespace (default on).
    pub fn pid_namespace(&self) -> bool {
        self.pid_namespace.unwrap_or(true)
    }

    /// Whether abstract sockets and signals are isolated (default on).
    pub fn isolate_ipc(&self) -> bool {
        self.isolate_ipc.unwrap_or(true)
    }

    /// Whether the standard system directories are granted.
    pub fn system_paths(&self) -> bool {
        self.system_paths.unwrap_or(true)
    }

    /// Reject values that would otherwise be silently changed later.
    pub fn validate(&self) -> Result<()> {
        if self.memory_limit == Some(0) {
            bail!(
                "memory limit must be greater than 0 (--memory-limit or memory_limit in the policy file)"
            );
        }
        if let Some(quota) = self.cpu_quota {
            if !(1..=100).contains(&quota) {
                bail!(
                    "CPU quota must be between 1 and 100 (percent), got {quota} (--cpu-quota or cpu_quota in the policy file)"
                );
            }
        }
        if self.pids_limit == Some(0) {
            bail!(
                "process limit must be greater than 0 (--pids-limit or pids_limit in the policy file)"
            );
        }
        if let Some(mode) = &self.seccomp {
            if !matches!(mode.as_str(), "enforce" | "log" | "off") {
                bail!(
                    "unknown seccomp mode {mode:?}; use enforce, log or off (--seccomp or seccomp in the policy file)"
                );
            }
        }
        Ok(())
    }

    /// Make every path absolute by resolving it against `base`.
    pub fn resolve_paths(&mut self, base: &Path) {
        // Join relative paths onto `base` and drop `.` components, so the
        // effective policy reads cleanly (`/work/.` becomes `/work`).
        let fix = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base
                    .join(&*p)
                    .components()
                    .filter(|c| !matches!(c, std::path::Component::CurDir))
                    .collect();
            }
        };
        self.allow_read.iter_mut().for_each(fix);
        self.allow_write.iter_mut().for_each(fix);
        self.allow_exec.iter_mut().for_each(fix);
        if let Some(root) = &mut self.new_root {
            fix(root);
        }
        // The command starts in the invoking directory unless `cwd` says
        // otherwise. Inside a --new-root jail the host directory usually does
        // not exist, so the jail's `/` is the default there.
        let default_cwd = if self.new_root.is_some() {
            PathBuf::from("/")
        } else {
            base.to_path_buf()
        };
        fix(self.cwd.get_or_insert(default_cwd));
    }
}

/// Turn an AppArmor path pattern into the directory Landlock should grant.
/// Returns `None` for patterns with character classes or variables left over.
fn glob_to_directory(pattern: &str) -> Option<PathBuf> {
    let trimmed = pattern
        .strip_suffix("/**")
        .or_else(|| pattern.strip_suffix("/*"))
        .unwrap_or(pattern);
    if trimmed.contains(['*', '?', '[', '{', '@']) {
        return None;
    }
    let trimmed = if trimmed.is_empty() { "/" } else { trimmed };
    Some(PathBuf::from(trimmed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_presets_parse() {
        for name in PRESET_NAMES {
            let p = Policy::from_preset(name).unwrap_or_else(|e| panic!("{name}: {e:#}"));
            p.validate().unwrap_or_else(|e| panic!("{name}: {e:#}"));
        }
    }

    #[test]
    fn embedded_schema_matches_repository_copy() {
        // Runs only in the repository checkout; the packaged crate has no
        // `schemas/` directory above it.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/policy.schema.json");
        if let Ok(text) = std::fs::read_to_string(&root) {
            assert_eq!(
                SCHEMA_TEXT, text,
                "crates/tpt-l-sandbox-cli/schema/policy.schema.json is out of date; copy it from schemas/"
            );
        }
    }

    #[test]
    fn unknown_preset_is_an_error() {
        assert!(Policy::from_preset("nope").is_err());
    }

    #[test]
    fn unknown_field_is_rejected() {
        let r: Result<Policy, _> = toml::from_str("allow_reed = []");
        assert!(r.is_err());
    }

    #[test]
    fn merge_extends_lists_and_overrides_scalars() {
        let mut base = Policy {
            allow_read: vec![PathBuf::from("/a")],
            memory_limit: Some(10),
            ..Policy::default()
        };
        base.merge(Policy {
            allow_read: vec![PathBuf::from("/b")],
            memory_limit: Some(20),
            no_network: true,
            ..Policy::default()
        });
        assert_eq!(base.allow_read.len(), 2);
        assert_eq!(base.memory_limit, Some(20));
        assert!(base.no_network);
    }

    #[test]
    fn validate_rejects_bad_values() {
        assert!(
            Policy {
                memory_limit: Some(0),
                ..Policy::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Policy {
                cpu_quota: Some(0),
                ..Policy::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Policy {
                cpu_quota: Some(101),
                ..Policy::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Policy {
                pids_limit: Some(0),
                ..Policy::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            Policy {
                seccomp: Some("maybe".into()),
                ..Policy::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn glob_mapping() {
        assert_eq!(
            glob_to_directory("/usr/lib/**"),
            Some(PathBuf::from("/usr/lib"))
        );
        assert_eq!(glob_to_directory("/tmp/*"), Some(PathBuf::from("/tmp")));
        assert_eq!(
            glob_to_directory("/etc/hosts"),
            Some(PathBuf::from("/etc/hosts"))
        );
        assert_eq!(glob_to_directory("/a/[ab]"), None);
        assert_eq!(glob_to_directory("@{HOME}/x"), None);
    }

    #[test]
    fn relative_paths_resolve_against_base() {
        let mut p = Policy {
            allow_write: vec![PathBuf::from(".")],
            ..Policy::default()
        };
        p.resolve_paths(Path::new("/work"));
        assert_eq!(p.allow_write[0], PathBuf::from("/work"));
    }
}

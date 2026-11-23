# tpt-linux-sandbox

Composable Linux sandboxing in Rust — Landlock, seccomp, namespaces, and cgroups behind a single declarative API, plus a CLI (`tpt-sandbox`) for running one command in a sandbox.

[![CI](https://github.com/TPT-Solutions/tpt-linux-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/TPT-Solutions/tpt-linux-sandbox/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](NOTICE)

---

## Overview

`tpt-linux-sandbox` is a Rust workspace that fills the gap between raw Linux sandboxing primitives and a usable, composable API. Safe wrappers for Landlock, seccomp/BPF, and Linux namespaces exist individually. This workspace layers them together with:

- A **declarative builder** (`Sandbox::new().landlock(...).apply()`) describing policy, not syscalls
- A **strict, irreversibility-aware order**: the whole policy is checked before any irreversible step runs
- A **pure-Rust CLI** (`tpt-sandbox`) as an alternative to bwrap and firejail, with built-in profiles, policy files, a diagnostic mode and a learning mode

**Platform:** Linux only. Minimum kernel 5.13 (Landlock ABI 1). See the [kernel matrix](docs/kernel-matrix.md).

---

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/TPT-Solutions/tpt-linux-sandbox/master/install.sh | sh
```

Other options: `cargo binstall tpt-l-sandbox-cli`, or `cargo install --path crates/tpt-l-sandbox-cli` from a checkout. Then run `tpt-sandbox --doctor` to check the machine.

---

## Quick start

```sh
# Read /etc only; system directories are readable and executable by default
tpt-sandbox --allow-read /etc -- cat /etc/hostname

# A built-in profile: no network, no capabilities, syscall allowlist
tpt-sandbox --profile untrusted-python --allow-read . -- python3 script.py

# See the effective policy without running anything
tpt-sandbox --profile build --dry-run

# Learn a starter policy from a run (runs the command unsandboxed under strace)
tpt-sandbox --learn -- ./my-tool --flag
```

Profiles: `strict`, `build`, `network-client`, `maintainer-script`, `untrusted-python`, `untrusted-node`. Print one with `tpt-sandbox --print-profile <name>`.

Full guide: [docs/quick-start.md](docs/quick-start.md). Recipes: [docs/policy-cookbook.md](docs/policy-cookbook.md).

---

## Documentation

| Document | What it covers |
|---|---|
| [docs/quick-start.md](docs/quick-start.md) | install, first runs, exit codes |
| [docs/policy-cookbook.md](docs/policy-cookbook.md) | recipes for common workloads |
| [docs/kernel-matrix.md](docs/kernel-matrix.md) | kernel features used and minimum versions |
| [docs/troubleshooting.md](docs/troubleshooting.md) | userns, cgroup delegation, WSL2, seccomp kills |
| [docs/threat-model.md](docs/threat-model.md) | what each layer protects against, and what it does not |
| [schemas/policy.schema.json](schemas/policy.schema.json) | JSON Schema for policy files |

Examples: each library crate has a runnable `examples/` program (`cargo run -p tpt-l-sandbox --example sandboxed_command`). Templates for GitHub Actions, systemd, Docker and devcontainers are in [templates/](templates/). A composite GitHub Action is in [action.yml](action.yml).

---

## Crates

| Crate | Description |
|---|---|
| `tpt-l-landlock-highlevel` | Declarative builder over the `landlock` crate |
| `tpt-l-seccomp-builder` | DSL for seccomp BPF allow/deny policies, with a general-purpose base profile |
| `tpt-l-namespaces-rs` | Safe wrappers for `unshare(2)`: user, mount, PID, network |
| `tpt-l-cgroup-v2` | cgroup v2 CPU, memory, I/O and process-count limits |
| `tpt-l-caps-drop` | Capability dropping (bounding, ambient, permitted, effective, inheritable) with `no_new_privs` |
| `tpt-l-chroot-jail` | `pivot_root` with private mounts, and pseudo-filesystem setup |
| `tpt-l-apparmor-parser` | AppArmor profile parser; emits Landlock rules (portable) |
| `tpt-l-selinux-context` | Parse and read SELinux security contexts (portable) |
| `tpt-l-audit-logger` | Async reader for the kernel audit subsystem (Tokio) |
| `tpt-l-sandbox` | Orchestrator: 7-stage state machine, plus a `Command` extension |
| `tpt-l-sandbox-cli` | CLI binary: `tpt-sandbox [OPTIONS] -- <command>` |

`tpt-l-audit-logger` is a standalone reader. The orchestrator does not use it yet.

---

## State machine

`Sandbox::apply()` runs stages in a fixed order. Stage 1 checks the whole configuration before anything changes:

| Stage | Layer | Reversible? |
|---|---|---|
| 1 | Validation: syscall names, errno range, Landlock paths, jail and namespace rules (no enforcement) | — |
| 2 | cgroup creation and entry (released if a later stage fails) | Yes |
| 3 | Namespace creation (`unshare`) | Yes |
| 4 | Filesystem setup (`pivot_root`, pseudo-filesystems) | Yes |
| 5 | Capability dropping | Yes |
| 6 | Seccomp enforcement | **No** |
| 7 | Landlock enforcement | **No** |

Namespaces, seccomp, Landlock and capabilities apply to the calling thread. Call `apply` before starting threads.

---

## Build and test

```sh
cargo test --workspace                 # Linux
cargo test --workspace -- --include-ignored   # also runs the forked-child regression tests
cargo check                            # macOS and Windows: only the portable crates
```

The sandbox tests need unprivileged user namespaces. On Ubuntu 24.04 you may need `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`; see [troubleshooting](docs/troubleshooting.md).

Known gaps and planned work are tracked in [todo.md](todo.md).

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.

Copyright 2026 TPT Solutions.

# tpt-linux-sandbox

Composable Linux sandboxing in Rust — Landlock, seccomp, namespaces, and cgroups behind a single declarative API.

[![CI](https://github.com/TPT-Solutions/tpt-linux-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/TPT-Solutions/tpt-linux-sandbox/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](NOTICE)

---

## Overview

`tpt-linux-sandbox` is a Rust workspace that fills the gap between raw Linux sandboxing primitives and a usable, composable API. Safe wrappers for Landlock, seccomp/BPF, and Linux namespaces already exist individually — this workspace layers them together with:

- A **declarative builder** (`Sandbox::new().allow_read("/etc").apply()`) describing policy, not syscalls
- A **strict, irreversibility-aware execution order** so a partially-applied configuration is never possible
- A **pure-Rust CLI** (`tpt-l-sandbox-cli`) as an alternative to bwrap / firejail

**Minimum kernel:** Linux 5.13 (Landlock ABI v1)

---

## Crates

| Crate | Description |
|---|---|
| `tpt-l-landlock-highlevel` | Declarative builder over the `landlock` crate |
| `tpt-l-seccomp-builder` | DSL for seccomp BPF allow/deny syscall policies |
| `tpt-l-namespaces-rs` | Safe wrappers for `unshare(2)` — user, mount, PID, network |
| `tpt-l-cgroup-v2` | cgroup v2 CPU / memory / I/O limits |
| `tpt-l-caps-drop` | Capability dropping via the `caps` crate |
| `tpt-l-chroot-jail` | `pivot_root` + pseudo-filesystem setup |
| `tpt-l-apparmor-parser` | AppArmor profile parser; emits Landlock rules |
| `tpt-l-selinux-context` | Parse/manipulate SELinux security contexts |
| `tpt-l-audit-logger` | Async reader for the kernel audit subsystem (Tokio) |
| `tpt-l-sandbox` | Orchestrator: 7-stage state machine combining all layers |
| `tpt-l-sandbox-cli` | CLI binary: `tpt-sandbox [OPTIONS] -- <command>` |

---

## State Machine

`Sandbox::apply()` enforces a strict order. No irreversible stage begins until the full configuration has been validated:

| Stage | Layer | Reversible? |
|---|---|---|
| 1 | Validation (full policy check, no kernel calls) | — |
| 2 | Unprivileged setup (cgroups, audit logging) | Yes |
| 3 | Namespace creation (`unshare`) | Yes |
| 4 | Filesystem setup (`pivot_root` / chroot, pseudo-fs) | Yes |
| 5 | Capability dropping | Yes |
| 6 | Seccomp enforcement | **No** |
| 7 | Landlock enforcement | **No** |

---

## Quick Start

```sh
# Read /etc, block everything else
tpt-sandbox --allow-read /etc -- cat /etc/hostname

# Isolated network, memory limit, custom root
tpt-sandbox --no-network --memory-limit 134217728 --new-root /path/to/rootfs -- /bin/sh
```

---

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.

Copyright 2026 TPT Solutions.

# tpt-linux-sandbox

Dual-licensed MIT OR Apache-2.0 · Copyright TPT Solutions · Rust 2024 · MSRV 1.82

Composable Linux sandboxing primitives: Landlock + seccomp + namespaces + cgroups, layered behind one declarative API with a correct, enforced ordering.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  tpt-l-sandbox-cli                   │
│              (CLI frontend, clap-based)              │
├─────────────────────────────────────────────────────┤
│                   tpt-l-sandbox                      │
│            (Orchestrator / State Machine)            │
├──────────┬──────────┬──────────┬────────────────────┤
│ Landlock │ Seccomp  │Namespaces│  Cgroups           │
│(fs rules)│(syscall  │(isolation)│ (resource limits)  │
│          │ filters) │          │                    │
├──────────┼──────────┼──────────┴────────────────────┤
│ Caps     │ Chroot   │ AppArmor  │ SELinux │ Audit   │
│ (drop)   │ (jail)   │ (parser)  │(context)│(logger) │
└──────────┴──────────┴───────────┴─────────┴─────────┘
```

## State Machine

| Stage | Operation | Reversible | Description |
|-------|-----------|------------|-------------|
| 1 | Validation | yes | Parse & validate entire policy before any kernel calls |
| 2 | Cgroup setup | yes | Create cgroup hierarchy and enter it |
| 3 | Namespace creation | no | `unshare(CLONE_NEW*)` |
| 4 | Filesystem jail | no | `pivot_root` + pseudo-fs mounts |
| 5 | Capability drop | no | Drop bounding capabilities |
| 6 | Seccomp enforcement | **no** | `seccomp_load` BPF filters |
| 7 | Landlock enforcement | **no** | Apply Landlock ruleset |

## Crates

| Crate | Purpose |
|-------|---------|
| `tpt-l-landlock-highlevel` | Declarative Landlock builder |
| `tpt-l-seccomp-builder` | Seccomp BPF policy DSL |
| `tpt-l-namespaces-rs` | Safe `unshare`/`clone3` wrappers |
| `tpt-l-cgroup-v2` | cgroup v2 hierarchy management |
| `tpt-l-caps-drop` | Capability bounding set control |
| `tpt-l-chroot-jail` | `pivot_root` + pseudo-fs mounting |
| `tpt-l-apparmor-parser` | AppArmor profile parser |
| `tpt-l-selinux-context` | SELinux context parser |
| `tpt-l-audit-logger` | Kernel audit netlink reader |
| `tpt-l-sandbox` | Orchestrator library |
| `tpt-l-sandbox-cli` | CLI frontend |

## Usage

```rust
use tpt_l_sandbox::Sandbox;

Sandbox::new()
    .allow_read("/etc")
    .allow_write("/tmp")
    .no_network()
    .memory_limit(256 * 1024 * 1024)
    .apply()
    .exec(&["cat", "/etc/hostname"])?;
```

## License

Dual-licensed under MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.

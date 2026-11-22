# tpt-l-landlock-highlevel

[![crates.io](https://img.shields.io/crates/v/tpt-l-landlock-highlevel.svg)](https://crates.io/crates/tpt-l-landlock-highlevel)
[![docs.rs](https://docs.rs/tpt-l-landlock-highlevel/badge.svg)](https://docs.rs/tpt-l-landlock-highlevel)

A declarative builder for Linux [Landlock](https://landlock.io) filesystem
restrictions. Describe which paths may be read, written, or executed, validate
the policy without touching the kernel, then enforce it on the current process.

The crate wraps the [`landlock`](https://crates.io/crates/landlock) crate. It is
the filesystem layer of the [`tpt-l-sandbox`](../tpt-l-sandbox) orchestrator, and
it can also be used on its own.

## Features

- `RulesetBuilder` with `allow_read`, `allow_write`, and `allow_exec`.
- `build()` validates the policy with **no kernel calls**, so configuration
  errors are reported before any irreversible step.
- `ValidatedRuleset::apply()` enforces the policy on the calling process.
- Negotiated Landlock ABI: the crate requests ABI V1 as a baseline and the
  `landlock` crate handles downward negotiation on older kernels.

## Requirements

- Linux **5.13 or newer** with Landlock enabled in the kernel
  (`CONFIG_SECURITY_LANDLOCK`) and in the active LSM list.
- No elevated privileges. Landlock is designed for unprivileged processes.
- Rust 1.85 or newer.

## Installation

```toml
[dependencies]
tpt-l-landlock-highlevel = "0.1"
```

## Quick start

```rust,no_run
use tpt_l_landlock_highlevel::RulesetBuilder;

RulesetBuilder::new()
    .allow_read("/etc")
    .allow_read("/usr")
    .allow_exec("/usr/bin")
    .build()
    .expect("invalid policy")
    .apply()
    .expect("landlock enforcement failed");
```

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `RulesetBuilder::new()` | fn | Empty policy. |
| `allow_read(path)` | method | Grant read and directory-listing access under `path`. |
| `allow_write(path)` | method | Grant read plus write, create, remove, and truncate access under `path`. |
| `allow_exec(path)` | method | Grant read plus execute access under `path`. |
| `build(self)` | method | Validate the policy. No kernel calls. |
| `ValidatedRuleset::apply(self)` | method | Enforce the policy irreversibly. |
| `LandlockError` | enum | `PathOpen`, `Operation`, and validation errors. |

## Behaviour and limitations

- **Irreversible.** Once `apply` succeeds, the restriction cannot be lifted for
  the process or its descendants. Plan the full policy before calling it.
- **Write implies read.** `allow_write` and `allow_exec` also grant read access
  to the same path.
- **Paths must exist at apply time.** Each path is opened to create a Landlock
  rule inside `apply`, so a missing path fails with `LandlockError::PathOpen`.
  `build` does not check the filesystem.
- **Path-based, not inode-based.** Rules attach to the directory or file the
  path resolves to when `apply` runs. Later renames or bind mounts can change
  what a path refers to.
- **Filesystem only.** Landlock does not restrict network access, signals, or
  syscalls in this crate. Use `tpt-l-seccomp-builder` for syscalls.
- **Kernel-dependent.** On kernels without Landlock, `apply` returns an error
  rather than silently running unrestricted.

## Testing

```sh
cargo test -p tpt-l-landlock-highlevel
```

The unit tests cover builder accumulation and building an empty ruleset. They
do not enforce a ruleset, so they do not restrict the test process.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

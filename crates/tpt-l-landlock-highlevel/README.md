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
- TCP port rules: `allow_tcp_bind` and `allow_tcp_connect` (ABI 4, Linux 6.7+).
  Once a port is listed, other ports of that kind are denied.
- `isolate_abstract_sockets_and_signals` (ABI 6, Linux 6.12+), which scopes
  abstract Unix sockets and signals to the Landlock domain.
- `under_root` re-anchors the granted paths under a new root, so a ruleset can be
  checked before a `pivot_root`.
- `require_full_enforcement` makes `apply` fail unless the kernel enforces the
  whole ruleset.
- Negotiated Landlock ABI: the crate requests ABI V1 as a baseline and the
  `landlock` crate handles downward negotiation on older kernels.

## Requirements

- Linux **5.13 or newer** with Landlock enabled in the kernel
  (`CONFIG_SECURITY_LANDLOCK`) and in the active LSM list. Port rules need 6.7 or
  newer, and abstract socket and signal scoping needs 6.12 or newer.
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
| `allow_tcp_bind(port)` | method | Permit binding a TCP socket to `port` (ABI 4). |
| `allow_tcp_connect(port)` | method | Permit connecting a TCP socket to `port` (ABI 4). |
| `isolate_abstract_sockets_and_signals()` | method | Scope abstract sockets and signals (ABI 6). |
| `under_root(root)` | method | Re-anchor granted paths under `root`, for checks before a `pivot_root`. |
| `require_full_enforcement()` | method | Fail `apply` unless the kernel enforces every right. |
| `build(self)` | method | Validate the policy. No kernel calls. |
| `ValidatedRuleset::apply(self)` | method | Enforce the policy irreversibly. |
| `LandlockError` | enum | `PathOpen`, `Operation`, and validation errors. |

## Behaviour and limitations

- **Irreversible.** Once `apply` succeeds, the restriction cannot be lifted for
  the process or its descendants. Plan the full policy before calling it.
  `ValidatedRuleset::apply` returns an error if the kernel does not enforce the
  ruleset; it does not run unrestricted.
- **Write implies read.** `allow_write` and `allow_exec` also grant read access
  to the same path.
- **Paths must exist.** `build` opens each configured path once to confirm it
  exists, and `apply` opens them again to create the rules. A missing path fails
  with `LandlockError::PathOpen` at `build`, before anything is enforced.
- **Path-based, not inode-based.** Rules attach to the directory or file the
  path resolves to when `apply` runs. Later renames or bind mounts can change
  what a path refers to.
- **Filesystem, TCP ports and IPC only.** Landlock does not restrict syscalls in
  this crate, and it does not filter hosts or addresses, only TCP ports. Use
  `tpt-l-seccomp-builder` for syscalls.
- **Port rules are strict.** Once a port is listed, other ports of that kind are
  denied. On kernels before 6.7, `apply` fails rather than dropping the rule.
- **IPC scoping is opt-in here.** Without `isolate_abstract_sockets_and_signals`,
  abstract sockets and signals are not restricted. `tpt-sandbox` enables it by
  default and drops it on older kernels.
- **Kernel-dependent.** On kernels without Landlock, `apply` returns an error
  rather than silently running unrestricted. A ruleset the kernel only partly
  enforces is also an error when `require_full_enforcement` is set.

## Testing

```sh
cargo test -p tpt-l-landlock-highlevel
```

The unit tests cover builder accumulation and building an empty ruleset. They
do not enforce a ruleset, so they do not restrict the test process. Forked-child
tests enforce rulesets in the child, to check the filesystem allowlist and that
abstract socket scoping holds across processes.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

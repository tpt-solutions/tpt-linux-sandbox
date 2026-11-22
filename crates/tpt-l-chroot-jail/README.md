# tpt-l-chroot-jail

[![crates.io](https://img.shields.io/crates/v/tpt-l-chroot-jail.svg)](https://crates.io/crates/tpt-l-chroot-jail)
[![docs.rs](https://docs.rs/tpt-l-chroot-jail/badge.svg)](https://docs.rs/tpt-l-chroot-jail)

Set up a filesystem jail for the calling process. The crate prepares a new root
directory, mounts the pseudo-filesystems a program usually expects, and switches
root into it, using `pivot_root(2)` where possible and `chroot(2)` as a fallback.

## Features

- `JailConfig::new(new_root)` chooses the directory that becomes `/`.
- `mount_proc()` mounts `proc` at `/proc` inside the jail.
- `mount_dev_minimal()` provides a minimal `/dev`.
- `mount_sys_ro()` mounts `sysfs` at `/sys` read-only.
- `apply()` pivots into the new root, falling back to `chroot(2)` with a
  warning on stderr when `pivot_root` is unavailable.

## Requirements

- Linux.
- Root or equivalent capabilities (`CAP_SYS_ADMIN`) to mount and pivot. Use
  inside a mount namespace (see [`tpt-l-namespaces-rs`](../tpt-l-namespaces-rs))
  so mounts stay private to the process.
- `new_root` must exist and be a directory before `apply` is called.
- Rust 1.85 or newer.

## Installation

```toml
[dependencies]
tpt-l-chroot-jail = "0.1"
```

## Quick start

```rust,no_run
use tpt_l_chroot_jail::JailConfig;

JailConfig::new("/path/to/rootfs")
    .mount_proc()
    .mount_dev_minimal()
    .mount_sys_ro()
    .apply()
    .expect("jail setup failed");
```

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `JailConfig::new(path)` | fn | Start a jail rooted at `path`. |
| `mount_proc(self)` | method | Mount `proc` inside the jail. |
| `mount_dev_minimal(self)` | method | Provide a minimal `/dev`. |
| `mount_sys_ro(self)` | method | Mount `sysfs` read-only. |
| `apply(self)` | method | Pivot or chroot into the jail. |
| `JailError` | enum | `pivot_root`, `chroot`, and mount failures. |

## Behaviour and limitations

- **Prefers `pivot_root`.** `pivot_root(2)` is harder to escape than
  `chroot(2)`. The fallback is used only when `pivot_root` fails, and it is
  logged to stderr because it is weaker.
- **Mount namespace strongly recommended.** Without a private mount namespace,
  the mounts and the pivot affect the host's mount table. The
  [`tpt-l-sandbox`](../tpt-l-sandbox) orchestrator enforces this ordering;
  direct users must do it themselves.
- **Not a full container.** The jail changes the root directory only. It does
  not limit resources, drop capabilities, or filter syscalls. Combine it with
  the other crates in this workspace.
- **Irreversible for the process.** After `apply` the process cannot leave the
  jail without privileges it has already dropped.
- **Paths are caller-supplied.** The crate does not sanitise the contents of
  `new_root`.

## Testing

```sh
cargo test -p tpt-l-chroot-jail
```

The unit tests check the builder flags and that a nonexistent root fails
immediately. Mount and pivot behaviour is not exercised by the unit tests
because it needs privileges; test it in an isolated environment.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

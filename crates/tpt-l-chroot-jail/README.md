# tpt-l-chroot-jail

[![crates.io](https://img.shields.io/crates/v/tpt-l-chroot-jail.svg)](https://crates.io/crates/tpt-l-chroot-jail)
[![docs.rs](https://docs.rs/tpt-l-chroot-jail/badge.svg)](https://docs.rs/tpt-l-chroot-jail)

Set up a filesystem jail for the calling process. The crate prepares a new root
directory, mounts the pseudo-filesystems a program usually expects, and switches
root into it, using `pivot_root(2)` where possible and `chroot(2)` as a fallback.

## Features

- `JailConfig::new(new_root)` chooses the directory that becomes `/`.
- `mount_proc()` mounts `proc` at `/proc` inside the jail.
- `mount_dev_minimal()` provides a minimal `/dev`: a `tmpfs` holding bind-mounted
  device nodes.
- `mount_sys_ro()` mounts `sysfs` at `/sys` read-only.
- `apply()` makes the mount tree private, then pivots into the new root.
- `allow_chroot_fallback()` opts in to `chroot(2)` when `pivot_root` is
  unavailable. It is off by default.
- `root()` returns the directory that becomes `/`.

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
| `allow_chroot_fallback(self)` | method | Permit `chroot(2)` when `pivot_root` is unavailable. Off by default. |
| `root(&self)` | method | The directory that becomes `/`. |
| `apply(self)` | method | Pivot into the jail, or chroot if the fallback is allowed. |
| `JailError` | enum | `pivot_root`, `chroot`, and mount failures. |

## Behaviour and limitations

- **Prefers `pivot_root`.** `pivot_root(2)` is harder to escape than
  `chroot(2)`. `chroot` is used only when `allow_chroot_fallback()` is set and
  `pivot_root` fails, and the fallback is logged to stderr.
- **Mount namespace strongly recommended.** The crate makes the mount tree
  private before the pivot, but that only keeps the host's mount table unchanged
  when the process is also in its own mount namespace. The
  [`tpt-l-sandbox`](../tpt-l-sandbox) orchestrator enforces this ordering;
  direct users must do it themselves.
- **Symlinks are refused in mount points.** Every path component below the new
  root must be a real directory or file, not a symlink. A symlink in an
  intermediate directory could otherwise redirect a mount or a creation to the
  host.
- **Mount-point errors are not ignored.** A mount or unmount failure is returned
  as an error.
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

The unit tests check the builder flags, that a nonexistent root fails
immediately, and symlink refusal in mount-point paths. A forked-child test pivots
into a root filesystem inside a user and mount namespace, so it needs unprivileged
user namespaces. The `enter_jail` example shows the same setup.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

# tpt-l-namespaces-rs

[![crates.io](https://img.shields.io/crates/v/tpt-l-namespaces-rs.svg)](https://crates.io/crates/tpt-l-namespaces-rs)
[![docs.rs](https://docs.rs/tpt-l-namespaces-rs/badge.svg)](https://docs.rs/tpt-l-namespaces-rs)

Safe, builder-style wrappers around `unshare(2)` for creating Linux namespaces.
Choose the namespaces you want, then call `apply` once. The crate handles the
`CLONE_NEW*` flags and, for user namespaces, the UID and GID mappings.

## Features

- `NamespaceSet` builder with `user`, `mount`, `pid`, and `network` options.
- `apply` calls `unshare(2)` with the combined flags in a single system call.
- For user namespaces, writes `/proc/self/uid_map` and `/proc/self/gid_map` so
  the process maps to UID and GID 0 inside the namespace while remaining
  unprivileged outside it.
- `has_mount` reports whether a mount namespace was requested, so higher-level
  code can check ordering rules.
- An empty set is valid and `apply` does nothing for it.

## Requirements

- Linux. The crate uses `unshare(2)`, `/proc/self/uid_map`, and `/proc/self/gid_map`.
- Unprivileged user namespaces enabled in the kernel for rootless use
  (`kernel.unprivileged_userns_clone` on some distributions, or
  `user.max_user_namespaces` > 0). Without `.user()` in the same set, the
  mount, PID, and network namespaces need `CAP_SYS_ADMIN`.
- Rust 1.85 or newer.

## Installation

```toml
[dependencies]
tpt-l-namespaces-rs = "0.1"
```

## Quick start

```rust,no_run
use tpt_l_namespaces_rs::NamespaceSet;

NamespaceSet::new()
    .user()
    .mount()
    .network()
    .apply()
    .expect("namespace setup failed");
```

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `NamespaceSet::new()` | fn | Empty set; nothing is unshared until a namespace is added. |
| `user(self)` | method | Request a user namespace (with UID/GID mapping). |
| `mount(self)` | method | Request a mount namespace. |
| `has_mount(&self)` | method | `true` if a mount namespace was requested. |
| `pid(self)` | method | Request a PID namespace. |
| `network(self)` | method | Request a network namespace (loopback only). |
| `apply(self)` | method | Call `unshare(2)` with the requested flags. |
| `NamespaceError` | enum | Errors from `unshare` or the UID/GID mapping. |

## Behaviour and limitations

- **Calling process only.** `apply` affects the calling process. Its children
  inherit the namespaces.
- **PID namespace applies to children.** As with `unshare(2)`, the calling
  process stays in its original PID namespace; only the processes it forks
  afterwards are created inside the new one.
- **Single-threaded requirement for user namespaces.** The kernel refuses
  `CLONE_NEWUSER` from a multi-threaded process. Call `apply` before starting
  any threads, including threads started by a runtime such as `tokio`.
- **UID mapping is fixed.** The mapping is `0 <current uid>` (and the matching
  GID). Other ranges are not configurable.
- **Mount namespace is not populated.** Creating a mount namespace does not
  mount anything. Use [`tpt-l-chroot-jail`](../tpt-l-chroot-jail) or your own
  mounts for filesystem setup.
- **Irreversible for the process.** The process cannot leave a namespace it has
  entered; it can only exit or create children.

## Testing

```sh
cargo test -p tpt-l-namespaces-rs
```

The unit tests cover builder flags and the empty set. They do not call
`unshare`, so they run without privileges.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

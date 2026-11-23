# tpt-l-caps-drop

[![crates.io](https://img.shields.io/crates/v/tpt-l-caps-drop.svg)](https://crates.io/crates/tpt-l-caps-drop)
[![docs.rs](https://docs.rs/tpt-l-caps-drop/badge.svg)](https://docs.rs/tpt-l-caps-drop)

Ergonomic Linux capability dropping. Start from "drop everything" and list the
few capabilities the process still needs. The crate then reduces the process's
bounding, ambient, permitted, effective and inheritable capability sets to that
keep list.

It is a small, explicit alternative to hand-written `capset(2)` and `prctl(2)`
calls. Dropping from the bounding set means that `execve(2)` cannot restore the
dropped capabilities.

## Features

- `CapsPolicy::new()` builds an empty policy. It changes nothing on its own.
- `drop_all()` opts in to dropping every capability not in the keep list.
- `keep(cap)` adds a capability to retain. Full (`CAP_NET_ADMIN`) and short
  (`net_admin`) names are both accepted, case-insensitively.
- `apply()` drops the capabilities outside the keep list from the bounding set,
  clears the ambient set, reduces the permitted, effective and inheritable sets,
  locks the securebits so root gets no implicit capabilities on `exec`, and sets
  `no_new_privs`.
- `keep` without `drop_all` is an error (`CapsError::KeepWithoutDrop`), so a
  forgotten `drop_all` cannot pass silently.
- Unknown capability names return `CapsError::UnknownCap` instead of being
  ignored. The whole keep list is checked before any change is made.

## Requirements

- Linux only.
- Dropping the bounding set needs `CAP_SETPCAP`. Without it, `apply` returns an
  error that names the failing step, unless the bounding set already matches the
  keep list.
- Retaining a capability is only possible if the process already holds it.
- Rust 1.85 or newer.

## Installation

```toml
[dependencies]
tpt-l-caps-drop = "0.1"
```

## Quick start

```rust,no_run
use tpt_l_caps_drop::CapsPolicy;

CapsPolicy::new()
    .drop_all()
    .keep("CAP_NET_BIND_SERVICE")
    .apply()
    .expect("capability drop failed");
```

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `CapsPolicy` | struct | Builder for the capability policy. |
| `CapsPolicy::new()` | fn | Empty policy; `apply` is a no-op unless `drop_all` is set. |
| `drop_all(self)` | method | Enable dropping of all capabilities not kept. |
| `keep(self, cap)` | method | Retain one capability. Accepts `impl Into<CapName>`. |
| `apply(self)` | method | Enforce the policy on the calling process. |
| `CapName` | type alias | `String`. |
| `CapsError` | enum | `UnknownCap`, `KeepWithoutDrop` and `Operation` errors. |

## Behaviour and limitations

- **Calling process only.** `apply` changes the capability sets of the calling
  process. Threads and child processes created before the call keep their
  capabilities.
- **Keep without drop is an error.** Calling `keep` without `drop_all` returns
  `CapsError::KeepWithoutDrop`. A policy with neither does nothing.
- **Keep list is validated.** Every name in the keep list is parsed before any
  change is made, so a typo fails the whole call.
- **Securebits are locked.** Once applied, the process cannot re-enable the
  root-like behaviour of securebits, and it cannot raise ambient capabilities.
- **Irreversible within the process.** Dropped capabilities cannot be regained
  by the process.

## Testing

```sh
cargo test -p tpt-l-caps-drop
```

The unit tests cover the default (no-op) policy, the `KeepWithoutDrop` error,
unknown names and accumulation of the keep list. A forked-child test applies a
`drop_all` policy, so the test process itself keeps its capabilities. The
`drop_caps` example runs the policy for a real process.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

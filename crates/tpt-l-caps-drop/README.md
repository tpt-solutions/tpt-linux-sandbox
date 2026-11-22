# tpt-l-caps-drop

[![crates.io](https://img.shields.io/crates/v/tpt-l-caps-drop.svg)](https://crates.io/crates/tpt-l-caps-drop)
[![docs.rs](https://docs.rs/tpt-l-caps-drop/badge.svg)](https://docs.rs/tpt-l-caps-drop)

Ergonomic Linux capability dropping. Start from "drop everything" and list the
few capabilities the process still needs. The crate then reduces the process's
permitted and effective capability sets to that keep list.

It is a small, explicit alternative to hand-written `capset(2)` calls. It
changes the permitted, effective, and inheritable sets of the calling thread,
and leaves the bounding set alone.

## Features

- `CapsPolicy::new()` builds an empty policy that drops nothing.
- `drop_all()` opts in to dropping every capability not in the keep list.
- `keep(cap)` adds a capability to retain. Full (`CAP_NET_ADMIN`) and short
  (`net_admin`) names are both accepted, case-insensitively.
- `apply()` intersects the permitted set with the keep set, sets the effective
  and permitted sets to the result, and clears the inheritable set.
- Unknown capability names return `CapsError::UnknownCap` instead of being
  ignored.

## Requirements

- Linux only.
- No special privilege to drop capabilities. Retaining capabilities is only
  possible if the process already holds them.
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
| `CapsError` | enum | `UnknownCap` and `Operation` errors. |

## Behaviour and limitations

- **Calling process only.** `apply` changes the capability sets of the calling
  process. Threads and child processes created before the call keep their
  capabilities.
- **No-op without `drop_all`.** A policy that only lists `keep` entries does
  nothing. This is deliberate: an explicit `drop_all` is required before any
  capability is removed.
- **Keep list is validated.** Every name in the keep list is parsed before any
  change is made, so a typo fails the whole call.
- **Irreversible within the process.** Dropped capabilities cannot be regained
  by the process.

## Testing

```sh
cargo test -p tpt-l-caps-drop
```

The unit tests cover the default (no-op) policy and accumulation of the keep
list. They do not call `apply`, so they run without changing the test
process's capabilities.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

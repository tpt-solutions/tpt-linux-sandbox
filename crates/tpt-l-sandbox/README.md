# tpt-l-sandbox

[![crates.io](https://img.shields.io/crates/v/tpt-l-sandbox.svg)](https://crates.io/crates/tpt-l-sandbox)
[![docs.rs](https://docs.rs/tpt-l-sandbox/badge.svg)](https://docs.rs/tpt-l-sandbox)

A composable sandbox orchestrator for Linux. It combines the other crates in
this workspace behind one builder: cgroup limits, namespaces, a filesystem jail,
capability dropping, a seccomp filter, and a Landlock filesystem policy. The
stages run in a fixed order that puts the irreversible steps last, after the
whole policy has been validated.

## Features

- One `Sandbox` builder for all layers. Each layer is optional.
- **Validation before any kernel call.** Configuration problems are reported
  before the process changes.
- Fixed, documented stage order (below), with the two irreversible stages last.
- Re-exports the layer types, so one dependency is enough for common use:
  `NamespaceSet`, `CgroupConfig`, `JailConfig`, `CapsPolicy`, `SeccompPolicy`,
  `DenyAction`, and `RulesetBuilder`.

## Requirements

- Linux. Each enabled layer has its own requirements, listed in its crate
  README:
  - [`tpt-l-cgroup-v2`](../tpt-l-cgroup-v2): unified cgroup v2 mount and write access.
  - [`tpt-l-namespaces-rs`](../tpt-l-namespaces-rs): unprivileged user namespaces for rootless use.
  - [`tpt-l-chroot-jail`](../tpt-l-chroot-jail): `CAP_SYS_ADMIN` and a mount namespace.
  - [`tpt-l-seccomp-builder`](../tpt-l-seccomp-builder): seccomp-BPF; x86_64 syscall names only.
  - [`tpt-l-landlock-highlevel`](../tpt-l-landlock-highlevel): Linux 5.13+ with Landlock enabled.
- Rust 1.85 or newer.

## Installation

```toml
[dependencies]
tpt-l-sandbox = "0.1"
```

## Quick start

```rust,no_run
use tpt_l_sandbox::{NamespaceSet, RulesetBuilder, Sandbox};

Sandbox::new()
    .namespaces(NamespaceSet::new().user().mount().network())
    .landlock(RulesetBuilder::new().allow_read("/etc").allow_read("/usr"))
    .apply()
    .expect("sandbox setup failed");
```

## Stage order

`Sandbox::apply` runs these stages in order. Only configured layers do anything.

| Stage | Layer | Reversible? |
|---|---|---|
| 1 | Validation (policy checks, no kernel calls) | n/a |
| 2 | Cgroup creation and limits | Yes |
| 3 | Namespace creation (`unshare`) | Yes |
| 4 | Filesystem jail (`pivot_root`, or `chroot` fallback) | Yes |
| 5 | Capability dropping | Yes |
| 6 | Seccomp filter | **No** |
| 7 | Landlock ruleset | **No** |

Stages 6 and 7 run last so that every reversible stage has finished before the
irreversible ones take effect. If stage 7 fails after stage 6 succeeded, the
process keeps the seccomp filter; `apply` does not undo it.

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `Sandbox::new()` | fn | Empty sandbox; `apply` does nothing until layers are added. |
| `namespaces(self, NamespaceSet)` | method | Stage 3. |
| `cgroup(self, CgroupConfig)` | method | Stage 2. |
| `jail(self, JailConfig)` | method | Stage 4. |
| `caps(self, CapsPolicy)` | method | Stage 5. |
| `seccomp(self, SeccompPolicy)` | method | Stage 6. |
| `landlock(self, RulesetBuilder)` | method | Stage 7. |
| `apply(self)` | method | Run all configured stages. |
| `SandboxError` | enum | Validation or per-layer errors. |

## Behaviour and limitations

- **Validation rejects an unsafe jail.** A filesystem jail without a mount
  namespace is rejected, because `pivot_root` would otherwise change the host's
  mount table.
- **A user namespace without a mount namespace is accepted silently.** The code
  comment describes this as a warning, but no warning is printed. Add `.mount()`
  to the namespace set if you need pseudo-filesystems inside the sandbox.
- **Partial application is possible.** If a stage fails, earlier stages have
  already taken effect. For example, a cgroup created in stage 2 remains when
  stage 4 fails. `apply` does not roll back earlier stages.
- **Irreversible stages are last.** Seccomp and Landlock cannot be removed once
  applied, so anything that must run after them (logging, cleanup) must run
  before `apply` or be permitted by the policy.
- **Process-wide effect.** Every stage affects the calling process and the
  processes it forks afterwards. Run `apply` in a process dedicated to the work
  you want sandboxed.
- **Layer limitations apply.** For example, seccomp name lookup is x86_64-only,
  and Landlock does not restrict network access. See each layer's README.

## Testing

```sh
cargo test -p tpt-l-sandbox
```

The unit tests check that the builder composes and that an empty sandbox
applies without error. The full stack needs privileges and kernel features, so
end-to-end checks are in [`tpt-l-sandbox-cli`](../tpt-l-sandbox-cli).

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

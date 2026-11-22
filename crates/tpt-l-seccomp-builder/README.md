# tpt-l-seccomp-builder

[![crates.io](https://img.shields.io/crates/v/tpt-l-seccomp-builder.svg)](https://crates.io/crates/tpt-l-seccomp-builder)
[![docs.rs](https://docs.rs/tpt-l-seccomp-builder/badge.svg)](https://docs.rs/tpt-l-seccomp-builder)

A high-level builder for seccomp-BPF syscall filters. Start from a default-deny
policy, list the syscalls the process needs, and apply the filter. The BPF
program is compiled with [`seccompiler`](https://crates.io/crates/seccompiler)
and loaded irreversibly with `seccomp(2)`.

## Features

- `SeccompPolicy` builder with `allow_syscall`, `deny_syscall`, and
  `default_action`.
- Default-deny: unless a default action is set, any syscall that is not
  allowed is killed (`DenyAction::Kill`).
- `DenyAction` chooses the response: `Kill` (SIGSYS), `Errno(n)` (return an
  error code), or `Log` (allow the call and log it).
- Unknown syscall names return `SeccompError::UnknownSyscall` at `apply` time,
  before anything is loaded.
- `apply` compiles and installs the filter for the calling process.

## Requirements

- Linux with seccomp-BPF support (`CONFIG_SECCOMP_FILTER`), which is standard
  on current distributions.
- **x86_64 only in this release.** The syscall-name table covers x86_64 alone.
  On other architectures every name resolves as unknown. See *Limitations*.
- No privileges are needed to install a filter, but `no_new_privs` must be
  set, which `apply` takes care of as part of loading the filter.
- Rust 1.85 or newer.

## Installation

```toml
[dependencies]
tpt-l-seccomp-builder = "0.1"
```

## Quick start

```rust,no_run
use tpt_l_seccomp_builder::{DenyAction, SeccompPolicy};

SeccompPolicy::new()
    .default_action(DenyAction::Errno(libc::EPERM))
    .allow_syscall("read")
    .allow_syscall("write")
    .allow_syscall("exit_group")
    .apply()
    .expect("seccomp enforcement failed");
```

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `SeccompPolicy::new()` | fn | Default-deny policy with `DenyAction::Kill`. |
| `default_action(self, action)` | method | Response for syscalls that are not allowed. |
| `allow_syscall(self, name)` | method | Permit a syscall by name. |
| `deny_syscall(self, name, action)` | method | Record an explicit deny entry (see *Limitations*). |
| `apply(self)` | method | Compile and load the filter. Irreversible. |
| `DenyAction` | enum | `Kill`, `Errno(i32)`, `Log`. |
| `SeccompError` | enum | `UnknownSyscall`, `Compile`, and `Load` errors. |

## Behaviour and limitations

- **Irreversible.** Once loaded, the filter cannot be removed from the process.
  Children inherit it.
- **Explicit denies are not per-syscall yet.** `deny_syscall` checks that the
  name is known, but the entry is not turned into a distinct rule. A denied
  syscall receives the policy's `default_action`. Use `default_action` to
  choose the response for all non-allowed calls.
- **x86_64 syscall table only.** Other architectures are unsupported until
  their tables are added.
- **Small syscall table.** Only the syscalls in the built-in table can be named.
  Calls outside it cannot be used in `allow_syscall` and must be added to the
  crate. Check the table in `src/lib.rs` before relying on a specific name.
- **Argument filtering is not provided.** Rules match on syscall number only.
- **Filter ordering.** Filters are cumulative: applying a second filter adds a
  restriction on top of the first. It cannot widen the first.

## Testing

```sh
cargo test -p tpt-l-seccomp-builder
```

The unit tests check rule recording, the default-action override, and that
common syscalls resolve on x86_64. They do not install a filter, so the test
process is not restricted.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

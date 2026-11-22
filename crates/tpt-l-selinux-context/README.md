# tpt-l-selinux-context

[![crates.io](https://img.shields.io/crates/v/tpt-l-selinux-context.svg)](https://crates.io/crates/tpt-l-selinux-context)
[![docs.rs](https://docs.rs/tpt-l-selinux-context/badge.svg)](https://docs.rs/tpt-l-selinux-context)

Parse and format SELinux security contexts without linking `libselinux`. The
crate reads the current process's context from `/proc/self/attr/current` and
splits context strings of the form `user:role:type[:level]`.

It is a parsing and inspection library. It does not consult or modify the
loaded SELinux policy, and it does not change labels on files or processes.

## Features

- `SecurityContext::parse` for three- or four-part context strings. Leading
  and trailing whitespace is ignored.
- `SecurityContext::current_process` reads the calling process's context.
- `to_canonical` formats the context back to its `user:role:type[:level]` form.
- Public fields `user`, `role`, `type_`, and `level` for direct access.
- `SelinuxError` for malformed input and read failures.

## Requirements

- Linux with SELinux enabled for `current_process`. The file
  `/proc/self/attr/current` exists only when a security module is active.
- `parse` and `to_canonical` work on any platform.
- Rust 1.85 or newer.

## Installation

```toml
[dependencies]
tpt-l-selinux-context = "0.1"
```

## Quick start

```rust,no_run
use tpt_l_selinux_context::SecurityContext;

let ctx = SecurityContext::current_process()?;
println!("running as: {}", ctx.to_canonical());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Parsing a context string:

```rust
use tpt_l_selinux_context::SecurityContext;

let ctx = SecurityContext::parse("system_u:system_r:httpd_t:s0")?;
assert_eq!(ctx.type_, "httpd_t");
assert_eq!(ctx.level.as_deref(), Some("s0"));
# Ok::<(), tpt_l_selinux_context::SelinuxError>(())
```

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `SecurityContext` | struct | `user`, `role`, `type_`, and optional `level`. |
| `SecurityContext::parse(&str)` | fn | Parse a three- or four-part context. |
| `SecurityContext::current_process()` | fn | Read `/proc/self/attr/current` and parse it. |
| `to_canonical(&self)` | method | Format as `user:role:type[:level]`. |
| `SelinuxError` | enum | Parse and I/O errors. |

## Behaviour and limitations

- **Syntax only.** Values are not checked against any policy. An unknown type
  such as `made_up_t` parses successfully.
- **Field names.** The type field is `type_` because `type` is a Rust keyword.
- **Current process only.** `current_process` reports the caller's context. It
  cannot read another process's label.
- **Four-part contexts keep the level verbatim.** The level is stored as the
  text after the third colon and is not normalised.
- **No labelling.** The crate does not set labels on files, sockets, or
  processes.

## Testing

```sh
cargo test -p tpt-l-selinux-context
```

The unit tests cover three- and four-part parsing, invalid input, and a
parse-to-canonical round trip. They do not require SELinux.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

# tpt-l-audit-logger

[![crates.io](https://img.shields.io/crates/v/tpt-l-audit-logger.svg)](https://crates.io/crates/tpt-l-audit-logger)
[![docs.rs](https://docs.rs/tpt-l-audit-logger/badge.svg)](https://docs.rs/tpt-l-audit-logger)

An async reader for the Linux kernel audit subsystem. It opens a `NETLINK_AUDIT`
socket, subscribes to the audit read-log multicast group, and delivers parsed
records as typed events over a `tokio` channel.

Use it to observe audit activity from your own process, for example to log
sandbox violations or to feed events into monitoring.

## Features

- `subscribe(buffer)` returns a `tokio::sync::mpsc::Receiver<AuditEvent>`.
- A background blocking task reads the netlink socket. It stops when the
  receiver is dropped.
- `AuditEvent::parse` turns a raw `key=value` audit body into `(key, value)`
  pairs. Quoted values with spaces, such as `key="some value"`, stay intact.
- Errors distinguish a permission failure (`AuditError::PermissionDenied`)
  from other socket errors.

## Requirements

- Linux only. The crate depends on `NETLINK_AUDIT`.
- The `CAP_AUDIT_READ` capability, or root, is required to receive audit
  records.
- A `tokio` runtime, since `subscribe` is `async` and the reader runs on
  `spawn_blocking`.
- Rust 1.85 or newer.

## Installation

```toml
[dependencies]
tpt-l-audit-logger = "0.1"
tokio = { version = "1", features = ["full"] }
```

## Quick start

```rust,no_run
#[tokio::main]
async fn main() -> Result<(), tpt_l_audit_logger::AuditError> {
    let mut rx = tpt_l_audit_logger::subscribe(128).await?;

    while let Some(event) = rx.recv().await {
        println!("audit type={} fields={:?}", event.record_type, event.fields);
    }
    Ok(())
}
```

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `subscribe(buffer)` | async fn | Open the audit socket and return a receiver of events. |
| `AuditEvent` | struct | `record_type: u32` and `fields: Vec<(String, String)>`. |
| `AuditEvent::parse(record_type, body)` | fn | Parse a `key=value` body. Usable without a socket. |
| `AuditRecordType` | type alias | `u32`, the kernel audit message type. |
| `AuditError` | enum | Errors from opening, binding, or reading the socket. |

## Behaviour and limitations

- **Read-only.** The crate receives records; it does not send them or change
  audit rules.
- **Parsing is string-based.** Each record is split into `key=value` pairs.
  Hex-encoded fields and the record's own `type=` prefix are not interpreted
  further.
- **Backpressure.** The channel is bounded by `buffer`. If the consumer falls
  behind, the reader waits on the channel rather than discarding records; size
  `buffer` for your expected burst rate.
- **Lifetime.** The reader stops when the receiver is dropped. There is no
  separate shutdown handle.
- **Privileges.** Without `CAP_AUDIT_READ` the call returns
  `AuditError::PermissionDenied`.

## Testing

```sh
cargo test -p tpt-l-audit-logger
```

The unit tests cover empty bodies, simple records, and quoted values. They do
not open a netlink socket, so they run without privileges.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

# Changelog

All notable changes to `tpt-l-audit-logger` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `subscribe(buffer)` to receive kernel audit records over `NETLINK_AUDIT`
  as `AuditEvent` values on a bounded `tokio` channel.
- `AuditEvent` with `record_type` and `fields`, and `AuditEvent::parse` for
  `key=value` bodies.
- `AuditError`, including `PermissionDenied` when `CAP_AUDIT_READ` is missing.
- Forked-child subscribe test, which skips without `CAP_AUDIT_READ`.
- The `tail_audit` example. It exits 1 when the subscription cannot be opened,
  and 0 when the stream ends normally.

### Changed

- The reader stops when the receiver is dropped.
- `subscribe` documents that it needs a running Tokio runtime.

### Fixed

- Build against `libc` 0.2.189: `sockaddr_nl` is zero-initialised and its
  fields set directly, because `libc` keeps `nl_pad` private.
- Quote-aware field tokenising, so `key="some value"` parses as one field
  instead of splitting at the space.
- The netlink reader reads each message without a misaligned reference cast,
  parses every message in a datagram rather than only the first, and ignores
  messages whose sender is not the kernel.
- Socket read errors are surfaced instead of being ignored.

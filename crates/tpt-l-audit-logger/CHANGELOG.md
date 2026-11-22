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

### Fixed

- Build against `libc` 0.2.189: `sockaddr_nl` is zero-initialised and its
  fields set directly, because `libc` keeps `nl_pad` private.
- Quote-aware field tokenising, so `key="some value"` parses as one field
  instead of splitting at the space.

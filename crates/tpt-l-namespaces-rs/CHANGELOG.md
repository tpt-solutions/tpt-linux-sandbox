# Changelog

All notable changes to `tpt-l-namespaces-rs` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `NamespaceSet` builder with `user`, `mount`, `pid`, and `network`.
- `apply` using `unshare(2)`, with UID/GID mapping for user namespaces.
- `NamespaceSet::has_user` and `NamespaceSet::has_mount` for read-only
  inspection of the requested namespaces.
- `NamespaceError` for unshare and mapping failures, including `MultiThreaded`
  and `ThreadCount`.
- `Default` and `Clone` derives on `NamespaceSet`.
- Unit tests for builder flags and the empty set.
- A forked-child regression test for user-namespace creation.

### Fixed

- The UID and GID are read before `unshare`. They were read after it, when they
  showed the overflow id, so the UID map write used the wrong id.
- A user namespace requested from a multi-threaded process returns
  `NamespaceError::MultiThreaded` instead of a bare `EINVAL`.
- The crate documentation states that `unshare(2)` affects only the calling
  thread, and that the PID namespace applies to children.

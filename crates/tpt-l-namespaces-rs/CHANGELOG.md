# Changelog

All notable changes to `tpt-l-namespaces-rs` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `NamespaceSet` builder with `user`, `mount`, `pid`, and `network`.
- `apply` using `unshare(2)`, with UID/GID mapping for user namespaces.
- `NamespaceSet::has_mount` for read-only inspection of the mount namespace
  request.
- `NamespaceError` for unshare and mapping failures.
- `Default` and `Clone` derives on `NamespaceSet`.
- Unit tests for builder flags and the empty set.

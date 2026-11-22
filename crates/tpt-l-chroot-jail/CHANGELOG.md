# Changelog

All notable changes to `tpt-l-chroot-jail` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `JailConfig` builder with `mount_proc`, `mount_dev_minimal`, and
  `mount_sys_ro`.
- `apply` using `pivot_root(2)`, with a stderr-logged `chroot(2)` fallback.
- `JailError` for pivot, chroot, and mount failures.
- Unit tests for builder flags and nonexistent-root handling.

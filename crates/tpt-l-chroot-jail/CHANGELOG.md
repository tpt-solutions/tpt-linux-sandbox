# Changelog

All notable changes to `tpt-l-chroot-jail` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `JailConfig` builder with `mount_proc`, `mount_dev_minimal`, and
  `mount_sys_ro`.
- `JailConfig::allow_chroot_fallback` and `JailConfig::root`.
- `JailError` for pivot, chroot, and mount failures.
- Unit tests for builder flags, nonexistent-root handling, and symlinks in
  mount-point paths, including an intermediate symlink.
- Forked-child test that pivots into a rootfs inside a user and mount namespace,
  and the `enter_jail` example.

### Changed

- `apply` makes the mount tree private before `pivot_root`.
- `chroot(2)` is opt-in. It is used only when `allow_chroot_fallback` is set and
  `pivot_root` fails. It was previously used without asking.
- `mount_dev_minimal` provides a `tmpfs` `/dev` with bind-mounted device nodes,
  mounted `nodev`.

### Fixed

- Symlinks are refused in every component of a mount-point path below the new
  root, not only the last one. A symlink in an intermediate directory could
  redirect creation and mounts to the host.

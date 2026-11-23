# Changelog

All notable changes to `tpt-l-caps-drop` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `CapsPolicy` builder with `new`, `drop_all`, `keep`, and `apply`.
- Case-insensitive acceptance of full and short capability names.
- `CapsError` with `UnknownCap`, `KeepWithoutDrop` and `Operation` variants.
- Unit tests for the default policy, keep-list accumulation and the
  `KeepWithoutDrop` error, and a forked-child test for a `drop_all` policy.
- The `drop_caps` example.

### Changed

- `apply` drops the bounding set as well as the permitted, effective and
  inheritable sets, so `execve(2)` cannot restore dropped capabilities.
- `apply` clears the ambient set, locks the securebits and sets `no_new_privs`.
- `keep` without `drop_all` returns `CapsError::KeepWithoutDrop` instead of doing
  nothing.
- The whole keep list is validated before any capability is changed.

### Fixed

- `prctl(2)` calls pass all five arguments. The wrapper passed only the option
  and three values, so release builds failed the ambient and `no_new_privs`
  steps with `EINVAL`.
- Errors name the step that failed (bounding drop, securebits, ambient set, ...).
- The `drop_caps` example reports a missing privilege and exits 1 instead of
  panicking.

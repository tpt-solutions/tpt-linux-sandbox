# Changelog

All notable changes to `tpt-l-landlock-highlevel` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `RulesetBuilder` with `allow_read`, `allow_write`, and `allow_exec`.
- `build` for validation, returning `ValidatedRuleset`. It opens each path once
  to confirm it exists, and makes no other kernel calls.
- `ValidatedRuleset::apply` for irreversible Landlock enforcement.
- `allow_tcp_bind` and `allow_tcp_connect` port rules (Landlock ABI 4). Once a
  port is listed, other ports of that kind are denied. Applying port rules on a
  kernel without ABI 4 fails.
- `isolate_abstract_sockets_and_signals` (Landlock ABI 6), best-effort.
- `under_root` to re-anchor granted paths under a new root, so a ruleset can be
  checked before a `pivot_root`.
- `require_full_enforcement` to make `apply` fail unless the kernel enforces the
  whole ruleset.
- `LandlockError` for path, validation, and kernel failures.
- Unit tests for builder accumulation and empty rulesets.
- A forked-child regression test for the filesystem allowlist, and a forked-child
  test that abstract socket scoping holds across processes.
- The `readonly_etc` example.

### Changed

- The `build` step rejects a missing path with `LandlockError::PathOpen`, instead
  of waiting for `apply`.
- Access rights use the Landlock ABI 3 set, including `Refer` and `Truncate`, and
  `RemoveDir` for write access.

### Fixed

- `apply` now returns an error when the kernel does not enforce the ruleset.
  Previously the `landlock` crate's `Ok(NotEnforced)` status was ignored, so
  the process ran unrestricted without any signal.
- Port rules fail on kernels without ABI 4 instead of being silently dropped.
- Build against `landlock` 0.4.7: use `AccessFs::Truncate`, the name in that
  release. `TruncateFile` does not exist.
- Wrap `PathFdError` in `io::Error` for `LandlockError::PathOpen`, so the
  public variant keeps its `std::io::Error` source type.

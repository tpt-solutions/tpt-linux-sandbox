# Changelog

All notable changes to `tpt-l-selinux-context` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `SecurityContext` with `user`, `role`, `type_`, and `level` fields.
- `SecurityContext::parse` for three- and four-part context strings.
- `SecurityContext::current_process` reading `/proc/self/attr/current`.
- `to_canonical` for formatting a context.
- `SelinuxError` for malformed contexts and read failures.
- Unit tests for parsing, invalid input, empty levels, and round-tripping.

### Fixed

- `current_process` distinguishes a missing `/proc/self/attr/current` (no
  security module active) from one that exists but cannot be read.
- Malformed fields are rejected during parsing.
- An empty level is rejected rather than accepted as an empty string.

# Changelog

All notable changes to `tpt-l-apparmor-parser` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `AppArmorProfile::parse` for single-profile AppArmor source text.
- `Rule` enum with `File`, `Network`, and `Other` variants.
- `FilePermissions` with `read`, `write`, `execute`, and `link` flags.
- `AppArmorProfile::landlock_rules` to map file rules to `LandlockFileRule`.
- `AppArmorProfile::unmapped_rules` to list rules with no Landlock equivalent.
- `@{VAR} = value...` variable definitions, expanded in path patterns.
- `AppArmorError` for parse failures.
- Unit tests and a compiled doc example.

### Fixed

- Nested and unterminated profiles are rejected rather than parsed partially.
- `deny` rules never produce a grant.
- Quoted paths are accepted, and permission characters are checked strictly.

### Documentation

- `#include` is recorded as `Rule::Other` and is not followed, so its contents
  are not part of the translation.

# tpt-l-apparmor-parser

[![crates.io](https://img.shields.io/crates/v/tpt-l-apparmor-parser.svg)](https://crates.io/crates/tpt-l-apparmor-parser)
[![docs.rs](https://docs.rs/tpt-l-apparmor-parser/badge.svg)](https://docs.rs/tpt-l-apparmor-parser)

A pure-Rust parser and validator for AppArmor profiles. It reads the profile
syntax, extracts file and network rules, and translates file rules into
Landlock-compatible path rules where a direct mapping exists.

The crate does **not** link against `libapparmor` or require AppArmor to be
enabled on the host. It is a text-processing library: it can be used on any
platform to inspect, validate, or convert profiles.

## Features

- Parse a single AppArmor profile (`/path/to/binary { ... }`) into a typed
  [`AppArmorProfile`].
- Extract file rules with their permission bits (`r`, `w`, `x`, `l`) into
  [`Rule::File`] values.
- Extract network rules (`network inet stream,` and similar) into
  [`Rule::Network`] values.
- Preserve any rule the parser does not understand as [`Rule::Other`], so
  diagnostic tooling can report it instead of silently dropping it.
- Convert file rules to [`LandlockFileRule`] values via
  [`AppArmorProfile::landlock_rules`].

## Requirements

- Rust 1.85 or newer (see the workspace `rust-version`).
- No system libraries and no runtime privileges. The crate performs no
  system calls.
- Landlock enforcement (applied by a consumer such as
  [`tpt-l-landlock-highlevel`](../tpt-l-landlock-highlevel)) requires Linux
  5.13 or newer. Parsing itself has no kernel requirement.

## Installation

```toml
[dependencies]
tpt-l-apparmor-parser = "0.1"
```

## Quick start

```rust
use tpt_l_apparmor_parser::AppArmorProfile;

let src = r#"
    /usr/bin/firefox {
      /etc/firefox/** r,
      /tmp/** rw,
    }
"#;

let profile = AppArmorProfile::parse(src)?;
println!("profile: {}", profile.name);

for rule in &profile.rules {
    println!("{rule:?}");
}

// Only file rules with a Landlock equivalent are returned here.
for lrule in profile.landlock_rules() {
    println!("landlock: {} -> {:?}", lrule.path_pattern, lrule.permissions);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## API overview

| Item | Kind | Purpose |
|---|---|---|
| `AppArmorProfile` | struct | A parsed profile: `name` and `rules`. |
| `AppArmorProfile::parse(&str)` | fn | Parse profile source text. |
| `AppArmorProfile::landlock_rules(&self)` | fn | Map file rules to Landlock-compatible rules. |
| `Rule` | enum | `File`, `Network`, or `Other(String)`. |
| `FilePermissions` | struct | `read`, `write`, `execute`, `link` flags. Implements `Default`. |
| `LandlockFileRule` | struct | `path_pattern` plus `permissions`. |
| `AppArmorError` | enum | Errors returned by `parse`. |

## Behaviour and limitations

- **Glob patterns are not expanded.** `LandlockFileRule::path_pattern` holds
  the AppArmor pattern (for example `/tmp/**`) unchanged. Landlock works on
  concrete paths, so the caller must resolve globs to real paths before
  building a ruleset.
- **Only single profiles are handled.** Include directives and multiple
  profiles in one file are not processed.
- **Unmapped rules are reported, not enforced.** Anything without a Landlock
  equivalent (for example, some capability or signal rules) appears as
  `Rule::Other` or is omitted from `landlock_rules`. Treat the output as a
  partial translation, not a faithful reproduction of the AppArmor policy.
- **No enforcement.** This crate never confines a process. Pair it with a
  Landlock or seccomp enforcement crate to apply restrictions.

## Testing

```sh
cargo test -p tpt-l-apparmor-parser
```

The suite contains unit tests for permission parsing, profile naming, file and
network rules, and empty input, plus a compiled doc test.

## Minimum supported Rust version

Rust 1.85, inherited from the workspace.

## License

Licensed under either of [MIT](../../LICENSE-MIT) or [Apache-2.0](../../LICENSE-APACHE), at your option.

Part of the [tpt-linux-sandbox](https://github.com/TPT-Solutions/tpt-linux-sandbox) workspace.

# tpt-linux-sandbox — Todo

> Dual-licensed MIT OR Apache-2.0 · Copyright TPT Solutions · Rust 2024 · MSRV 1.82
> GitHub: https://github.com/TPT-Solutions/tpt-linux-sandbox
> Crate prefix: `tpt-l-*`

---

## Phase 1: Workspace Scaffold

- [x] `Cargo.toml` — workspace root with all 11 members, `[workspace.package]`, `[workspace.dependencies]`
- [x] `LICENSE-MIT`
- [x] `LICENSE-APACHE`
- [x] `NOTICE` — TPT Solutions copyright notice
- [x] `rust-toolchain.toml` — pin stable channel, MSRV 1.85
- [x] `.github/workflows/ci.yml` — `cargo test`, `cargo clippy` on ubuntu-latest
- [x] `README.md` — overview, architecture diagram, state machine table
- [x] Crate skeleton `Cargo.toml` files (all 11 crates)
- [x] Crate skeleton `src/lib.rs` / `src/main.rs` files (all 11 crates)

---

## Phase 2: Core Sandboxing Primitives

### `tpt-l-landlock-highlevel`
- [x] `RulesetBuilder` with `.allow_read()`, `.allow_write()`, `.allow_exec()`
- [x] `.build()` — full validation, no kernel calls
- [ ] Runtime Landlock ABI version detection (≥ v1 / Linux 5.13) — stub present, needs `landlock` crate wiring
- [ ] `.apply()` — irreversible enforcement via `landlock` crate — stub present, needs implementation

### `tpt-l-seccomp-builder`
- [x] `SeccompPolicy` with `.allow_syscall()`, `.deny_syscall()`, `.default_action()`
- [x] Default-deny policy; explicit allowlist approach
- [ ] BPF compilation via `seccompiler` — stub present, needs implementation
- [ ] `.apply()` — irreversible `seccomp_load` — stub present, needs implementation

### `tpt-l-namespaces-rs`
- [x] `NamespaceSet` builder: `.user()`, `.mount()`, `.pid()`, `.network()`
- [ ] `unshare(2)` call with correct `CLONE_NEW*` flags — stub present, needs `nix` wiring
- [ ] UID/GID mapping for user namespaces (`/proc/self/uid_map`, `gid_map`) — stub present

---

## Phase 3: Resource & Access Control

### `tpt-l-cgroup-v2`
- [x] `CgroupConfig` builder: `.cpu_quota()`, `.memory_limit()`, `.io_weight()`
- [ ] Create `/sys/fs/cgroup/<name>/` hierarchy — stub present, needs `fs::create_dir_all`
- [ ] Write `cpu.max`, `memory.max`, `io.weight` control files — stub present
- [ ] `.enter()` — write PID to `cgroup.procs` — stub present
- [ ] `.destroy()` — rmdir cleanup — stub present

### `tpt-l-caps-drop`
- [x] `CapsPolicy` builder: `.drop_all()`, `.keep(cap)`
- [ ] Bounding set validation before dropping — stub present, needs `caps` crate wiring
- [ ] `.apply()` via `caps` crate (permitted, effective, inheritable sets) — stub present

### `tpt-l-chroot-jail`
- [x] `JailConfig` builder: `.new_root()`, `.mount_proc()`, `.mount_dev_minimal()`, `.mount_sys_ro()`
- [ ] `pivot_root(2)` implementation — stub present, needs `nix` wiring
- [ ] `chroot(2)` fallback with logged warning — stub present
- [ ] Pseudo-filesystem mounting (`/proc`, minimal `/dev`, `/sys` read-only) — stub present

---

## Phase 4: Policy Analysis & Auditing

### `tpt-l-apparmor-parser`
- [ ] AppArmor profile textual format parser → typed AST (pure Rust, `nom` or hand-rolled) — stub present
- [x] Landlock rule emitter for filesystem rules with a direct mapping (`landlock_rules()`)
- [x] Warning for rules with no Landlock equivalent

### `tpt-l-selinux-context`
- [x] `SecurityContext` struct (`user:role:type:level`)
- [x] `SecurityContext::parse()` from string
- [x] `SecurityContext::current_process()` from `/proc/self/attr/current`
- [x] No `libselinux` dependency

### `tpt-l-audit-logger`
- [ ] Open `NETLINK_AUDIT` raw socket — stub present, needs `libc::socket` wiring
- [ ] Bind and receive kernel audit netlink messages — stub present
- [x] Parse records into typed `AuditEvent { record_type, fields }` (`AuditEvent::parse`)
- [x] `subscribe(buffer)` async fn returning `mpsc::Receiver<AuditEvent>` (Tokio)

---

## Phase 5: Sandbox Orchestrator Library (`tpt-l-sandbox`)

- [x] `Sandbox::new()` top-level builder with per-layer setter methods
- [x] 7-stage state machine in `Sandbox::apply()`:
  1. Validation (no kernel calls)
  2. Cgroup setup + enter
  3. Namespace creation
  4. Filesystem jail (pivot_root / chroot + pseudo-fs)
  5. Capability dropping
  6. Seccomp enforcement *(irreversible)*
  7. Landlock enforcement *(irreversible, last)*
- [ ] Full policy validation — `validate()` stub present, invalid-combination logic needed
- [x] Clear, descriptive error messages on invalid combinations (`SandboxError` variants)

---

## Phase 6: CLI (`tpt-l-sandbox-cli`)

- [x] `clap` argument definitions: `--allow-read`, `--allow-write`, `--no-network`, `--memory-limit`, `--cpu-quota`, `--new-root`, `--drop-caps`
- [x] Map CLI flags → `Sandbox` builder calls
- [x] `exec(2)` the child command after `sandbox.apply()`
- [x] Non-zero exit with descriptive `eprintln!` on any error

---

## Phase 7: Tests, Docs & CI Polish

- [x] Unit tests: `tpt-l-landlock-highlevel` (builder, validation)
- [x] Unit tests: `tpt-l-seccomp-builder` (policy construction)
- [x] Unit tests: `tpt-l-namespaces-rs` (flag bitmask logic)
- [x] Unit tests: `tpt-l-cgroup-v2` (config builder, path construction)
- [x] Unit tests: `tpt-l-caps-drop` (policy builder)
- [x] Unit tests: `tpt-l-chroot-jail` (config builder)
- [x] Unit tests: `tpt-l-apparmor-parser` (parse → AST round-trips)
- [x] Unit tests: `tpt-l-selinux-context` (parse / format)
- [x] Unit tests: `tpt-l-audit-logger` (record parsing)
- [x] Unit tests: `tpt-l-sandbox` (state machine ordering, validation errors)
- [ ] Integration test: `tpt-l-sandbox-cli --allow-read /etc -- cat /etc/hostname` succeeds
- [ ] Integration test: `tpt-l-sandbox-cli --allow-read /etc -- cat /tmp/secret` fails/blocked
- [ ] `#![deny(missing_docs)]` workspace-wide
- [ ] Rustdoc for all public APIs
- [ ] `clippy::pedantic` lint pass clean
- [ ] `cargo deny` config — license audit + dependency advisory check
- [ ] crates.io publish metadata (`keywords`, `categories`, `description`) for all 11 crates

---

## Open Questions (from spec §5)

- [ ] Define default syscall/filesystem allowlist for maintainer-script execution (tpt-deb-toolkit integration)
- [ ] Confirm minimum kernel version matrix for all Landlock ruleset features actually used

# tpt-linux-sandbox — Todo

> Dual-licensed MIT OR Apache-2.0 · Copyright TPT Solutions · Rust 2024 · MSRV 1.85
> GitHub: https://github.com/TPT-Solutions/tpt-linux-sandbox
> Crate prefix: `tpt-l-*`

Status key: `[x]` done · `[ ]` not done (reason given) · **verified** = ran in a privileged or unprivileged Linux container (Docker, kernel 6.18, 22 test suites, 108 tests with ignored tests included) · **checked** = type-checked and clippy-clean for Linux, not run.

---

## Phase 1: Workspace Scaffold

- [x] `Cargo.toml` — workspace root with all 11 members, `[workspace.package]`, `[workspace.dependencies]`
- [x] `LICENSE-MIT`
- [x] `LICENSE-APACHE`
- [x] `NOTICE` — TPT Solutions copyright notice
- [x] `rust-toolchain.toml` — pin stable channel
- [x] `.github/workflows/ci.yml` — see Phase 9
- [x] `README.md` — rewritten to match the code (Phase 10)
- [x] Crate skeleton `Cargo.toml` files (all 11 crates)
- [x] Crate skeleton `src/lib.rs` / `src/main.rs` files (all 11 crates)

---

## Phase 2: Core Sandboxing Primitives

### `tpt-l-landlock-highlevel`
- [x] `RulesetBuilder` with `.allow_read()`, `.allow_write()`, `.allow_exec()`
- [x] `.build()` — opens every path to confirm it exists (no enforcement); **checked, verified** via tests
- [x] ABI handling: requests ABI v3 rights (`Refer`, `Truncate`); best-effort on older kernels — **checked**
- [x] `require_full_enforcement()` — opt-in error on partial enforcement — **checked**
- [x] `.apply()` — irreversible enforcement; `RemoveDir` added to write rights — **verified** (CLI integration tests)
- [ ] ABI 4 (TCP bind/connect) — not started; needs a network rule API and kernel 6.7+

### `tpt-l-seccomp-builder`
- [x] `SeccompPolicy` with `.allow_syscall()`, `.deny_syscall()`, `.default_action()`
- [x] `deny_syscall` is enforced: each deny action goes into its own filter loaded before the allowlist — **checked** (not run: the deny path itself has no runtime test)
- [x] `Errno` range validated (1–4095) — **verified** (unit test)
- [x] Syscall table expanded (~135 names); every name confirmed against `libc` for x86_64 and aarch64 — **checked**
- [x] `base_profile()` — general-purpose allowlist; `ptrace` returns EPERM — **verified** (forked-child test)
- [x] `validate()` — resolves names before any irreversible stage — **verified**
- [ ] riscv64 and other architecture tables — not added (aarch64 uses the shared table; riscv64 is not compiled or tested)

### `tpt-l-namespaces-rs`
- [x] `NamespaceSet` builder: `.user()`, `.mount()`, `.pid()`, `.network()`
- [x] `unshare(2)` with correct `CLONE_NEW*` flags
- [x] **uid/gid read before `unshare`** — fixes the `uid_map` write — **verified** (forked-child test, root and unprivileged)
- [x] `MultiThreaded` error for user namespaces from a multi-threaded process — **verified** (unit test on thread counting)
- [x] PID namespace documented as children-only; `clone3` claim removed
- [ ] PID namespace with fork and an init reaper — not started; the CLI does not use it

---

## Phase 3: Resource & Access Control

### `tpt-l-cgroup-v2`
- [x] `CgroupConfig` builder: `.cpu_quota()`, `.memory_limit()`, `.io_weight()`, `.pids_limit()`, `.name()`
- [x] Name validated: one path component, no `/`, `..` or NUL — **verified** (unit tests)
- [x] `mkdir` (no reuse of stale directories); `AlreadyExists` reported
- [x] Only missing controllers are written to `cgroup.subtree_control` — **verified**: the memory test skips in a container where memory is not delegated
- [x] `memory.swap.max = 0` with the memory limit; `pids.max` — **checked**
- [x] `.enter()`, `.destroy()`, `.release()` (moves the process out, then removes the group)
- [x] Cgroup removed on failure and after the CLI child exits — **checked**

### `tpt-l-caps-drop`
- [x] `CapsPolicy` builder: `.drop_all()`, `.keep(cap)`
- [x] Bounding set dropped first; ambient cleared; securebits locked; inheritable cleared; `no_new_privs` set — **verified** (forked-child test, root and unprivileged)
- [x] `keep()` without `drop_all()` is an error — **verified** (unit test)

### `tpt-l-chroot-jail`
- [x] `JailConfig` builder: `.new_root()`, `.mount_proc()`, `.mount_dev_minimal()`, `.mount_sys_ro()`
- [x] Mount tree made private before any mount or pivot — **checked**
- [x] `pivot_root(".", ".put_old")` after entering the new root — **checked**
- [x] `chroot` fallback is opt-in (`allow_chroot_fallback()`) — **checked**
- [x] `/dev` is a tmpfs with bind-mounted `null`, `zero`, `random`, `urandom`, `tty` only — **checked**
- [x] Symlinks refused when creating mount points — **verified** (unit test)
- [x] Proc mounted `nosuid,nodev,noexec`; `umount` failure is fatal — **checked**
- [ ] Runtime tests of the full jail (needs a rootfs and mount namespace in CI)

---

## Phase 4: Policy Analysis & Auditing

### `tpt-l-apparmor-parser`
- [x] AppArmor parser → typed AST (hand-rolled)
- [x] Nested profiles rejected; unterminated or unexpected braces rejected — **verified** (unit tests)
- [x] Several rules per line; quoted paths (with `#` and spaces); `@{VAR}` expansion; undefined variables rejected — **verified**
- [x] `deny` rules never become grants — **verified**
- [x] `networkfoo` is not a network rule; unknown permission characters rejected — **verified**
- [x] No `eprintln!` in library code; `unmapped_rules()` returns the rules that were not converted
- [x] `landlock_rules()` — Landlock rules for file rules with a direct mapping
- [x] Example: `cargo run -p tpt-l-apparmor-parser --example convert_profile`

### `tpt-l-selinux-context`
- [x] `SecurityContext` struct (`user:role:type[:level]`)
- [x] Parse rejects empty fields, whitespace and control characters — **verified**
- [x] `current_process()` distinguishes a missing attr file (`NotEnabled`) from a read error (`Read`)
- [x] Docs no longer claim `getfilecon` support

### `tpt-l-audit-logger`
- [x] `NETLINK_AUDIT` socket; bind to the audit group; `EPERM` mapped to `PermissionDenied`
- [x] Sender checked (`nl_pid == 0`); `MSG_TRUNC` detects truncated datagrams
- [x] Netlink header read unaligned (the old reference cast was undefined behaviour)
- [x] Every netlink message in a datagram parsed, with `NLMSG_ALIGN`; malformed lengths stop the scan — **verified** (unit tests)
- [x] Receive errors delivered through the channel; reader stops within ~0.5 s of the receiver being dropped
- [x] `subscribe` returns `Result<AuditEvent, AuditError>` items (API change)
- [ ] Live test against the kernel audit stream (needs `CAP_AUDIT_READ` in CI)

---

## Phase 5: Sandbox Orchestrator Library (`tpt-l-sandbox`)

- [x] `Sandbox::new()` builder with per-layer setter methods (`Clone`)
- [x] 7-stage order in `apply()`; cgroup released if a later stage fails
- [x] `validate()` (public) runs before any stage: jail/mount rule, seccomp names and errnos, Landlock paths — **verified**
- [x] Landlock setup syscalls are allowed automatically when seccomp is applied first — **checked**
- [x] Warning for user namespaces without a mount namespace (documented before, now printed)
- [x] `CommandSandboxExt::sandboxed()` — sandbox a child process between fork and exec — **checked**, used by the example
- [x] Audit logger is not wired in; README now says so (the old claim was removed)

---

## Phase 6: CLI (`tpt-l-sandbox-cli`)

- [x] Flags: `--allow-read`, `--allow-write`, `--allow-exec`, `--no-system-paths`, `--no-network`, `--memory-limit`, `--cpu-quota`, `--pids-limit`, `--new-root`, `--cwd`, `--drop-caps`, `--seccomp`, `--pass-env`, `--json`
- [x] Fork before any restriction: the child applies the sandbox and execs; the parent waits, removes the cgroup, and reports the exit — **verified**
- [x] Exit reporting: signals, SIGSYS (seccomp) and SIGKILL (memory) explained; `--json` event — **verified**
- [x] Child: clears the environment — **verified** (integration test); `setsid` and closing descriptors 3+ — **checked** (no runtime test)
- [x] Argument values validated, not clamped (`--cpu-quota`, `--memory-limit`, `--pids-limit`) — **verified**
- [x] Integration tests check output and exit status; negative tests assert that setup succeeded — **verified** (root and unprivileged)
- [x] Seccomp enforced by default (base profile); `--seccomp log` and `off` available — **verified** (log mode smoke test)

---

## Phase 7: Tests, Docs & CI Polish

- [x] Unit tests for every library crate and for the CLI policy and tools modules — **verified**
- [x] Forked-child regression tests (ignored by default, run with `--include-ignored`): namespaces, caps, seccomp — **verified**
- [x] Integration tests: `cat /etc/hostname` succeeds; `cat /tmp/secret` fails with EACCES; `--no-network` blocks connect; memory limit kills (skipped without memory delegation); `mount` blocked after `--drop-caps`; env scrubbing; JSON exit; validation; dry-run; print-profile — **verified**
- [x] `missing_docs` warn — `[workspace.lints.rust]`
- [x] `unsafe_op_in_unsafe_fn` warn — `[workspace.lints.rust]`
- [x] `clippy::pedantic` warn, with four deliberate allows (builder `must_use`, boolean structs, `# Errors` sections, doc prose) — **checked**: clippy with `-D warnings` is clean on Linux
- [x] Rustdoc for public APIs; examples for the main crates (see Phase 10)
- [x] `cargo deny` config — `deny.toml`; run by CI (not run locally)
- [x] Publish metadata (`keywords`, `categories`, `description`, `version` on path dependencies)

---

## Phase 8: Correctness Fixes (from platform review, 2026-11-23)

> Found by source reading. Each item below has a regression test or a note on how it was checked.

- [x] **namespaces-rs** — uid/gid read before `unshare` — **verified**
- [x] **sandbox-cli** — `--allow-exec` added; system directories grant read and exec by default — **verified** (the command runs)
- [x] **sandbox-cli tests** — assertions check output and exit codes; `--no-network` test tries a real connect — **verified**
- [x] **caps-drop** — bounding, ambient, securebits, `no_new_privs`; `keep()` without `drop_all()` is an error — **verified**
- [x] **chroot-jail** — `MS_PRIVATE` before `pivot_root` — **checked**
- [x] **chroot-jail** — `chroot` fallback is opt-in — **checked**
- [x] **chroot-jail** — `devtmpfs` replaced with tmpfs and bind-mounted device nodes — **checked**
- [x] **chroot-jail** — mount and create errors are reported; symlinks refused; `proc` flags; `.put_old` removal failure is fatal — **checked**
- [x] **cgroup-v2** — name validated — **verified**
- [x] **cgroup-v2** — `subtree_control` (missing controllers only); `pids.max`; `memory.swap.max`; no reuse of stale directories — **verified** (behaviour under delegation; memory test skipped here)
- [x] **cgroup lifecycle** — `release()` on failure and CLI cleanup after the child exits — **checked**
- [x] **seccomp-builder** — `deny_syscall` enforced — **checked**
- [x] **seccomp-builder** — `Errno` validated — **verified**
- [x] **seccomp-builder** — syscall table expanded; aarch64 covered by the shared table — **checked**
- [x] **seccomp-builder** — `landlock_*` syscalls allowed when seccomp runs first — **checked**
- [x] **seccomp (CLI)** — default is the base allowlist (`enforce`) — **verified**: Python starts and runs under it in the container
- [x] **sandbox `validate()`** — syscall names, errnos, Landlock paths, jail rule, before stage 2 — **verified**
- [x] **landlock-highlevel** — `PartiallyEnforced` rejected only with `require_full_enforcement()`; ABI v3 rights; `RemoveDir` — **checked**
- [x] **sandbox-cli hygiene** — `close_range`, env scrub with `--pass-env`, `setsid`, working directory; invalid limits rejected — **verified**
- [x] **audit-logger** — unaligned read; multi-message datagrams; sender check; errors surfaced; `EPERM` mapped — **verified** (parser tests; live stream not tested)
- [x] **apparmor-parser** — nested profiles, unterminated blocks, multi-rule lines, `@{VAR}`, no `eprintln!`, `networkfoo`, unknown permission characters — **verified**
- [x] **threading** — documented in the crate docs; `MultiThreaded` error for user namespaces — **verified**
- [x] **selinux-context** — permission-denied vs not-enabled distinguished; empty fields rejected — **verified**
- [x] **sandbox docs** — audit-logger claim and stage-2 rollback claim corrected in README and CHANGELOG

---

## Phase 9: Housekeeping & CI

- [x] Portable build: `default-members` lists the portable crates, so `cargo check` works on Windows and macOS — **checked** on Windows (the Linux crates still need `--workspace` on Linux). This is used instead of gating every crate with `cfg`.
- [x] `version = "0.1.0"` on every path dependency; `apparmor-parser`, `selinux-context` in `[workspace.dependencies]`
- [x] `homepage` — not added: `repository` already provides the link; `cargo` warned that `homepage` duplicated it
- [ ] `exclude` / `include` for package contents — not needed at this size; revisit before publishing
- [x] `unsafe_op_in_unsafe_fn` lint
- [x] CI: `cargo deny check` job (`EmbarkStudios/cargo-deny-action@v2`) — configured, not run
- [x] CI: MSRV job (1.85, `cargo check --workspace --all-targets`) — configured, not run; some dependency releases may need a newer compiler
- [x] CI: docs job (`cargo doc` with `-D warnings`) — configured, not run
- [x] CI: unprivileged test job (userns enabled via sysctl on Ubuntu 24.04) and privileged (root) job — configured, not run; both pass locally in the container
- [x] CI: clippy with `--all-targets -D warnings` — clean locally
- [x] CI: macOS and Windows `cargo check` of the portable crates — configured, not run
- [x] Forked-child tests for namespaces, caps and seccomp
- [ ] Forked-child tests for cgroup, jail and Landlock apply — not done; these need a dedicated environment
- [x] Negative-input tests: cgroup name, Errno range, nested and unterminated AppArmor, multi-rule lines, malformed and multipart netlink, symlink mount point
- [x] Table test: every syscall name is unique (`table_names_are_unique`)
- [x] Release workflow (`.github/workflows/release.yml`): static musl binaries for x86_64 and aarch64 on version tags — configured, not run
- [ ] Publish crates to crates.io in dependency order — **excluded at your request**

---

## Phase 10: Adoption — Presets, Examples, Docs, Packaging

### Profiles & policy files
- [x] `--profile <name>` with six built-in TOML profiles: `strict`, `build`, `network-client`, `maintainer-script`, `untrusted-python`, `untrusted-node` — **verified** (parsed in unit tests; `--print-profile` in integration tests)
- [x] `--policy <file>` with the same schema; `schemas/policy.schema.json` (JSON Schema) — **verified** (deserialization rejects unknown fields)
- [x] Deviation: `tpt-sandbox init --profile <name>` was planned as a subcommand. The CLI has a trailing command, so it uses `--print-profile <name> > file` instead.

### Examples & templates
- [x] Examples (`cargo run -p <crate> --example <name>`), compiled by `cargo test` — **verified** to compile; `sandboxed_command` was also run. Not run: `readonly_etc`, `base_profile` and `enter_namespaces` (they change the calling process), `tail_audit` (needs `CAP_AUDIT_READ`), `drop_caps`, `limited_group`, `convert_profile`
- [ ] Example for `tpt-l-chroot-jail` — needs a rootfs path; not added
- [x] `templates/` — GitHub Actions workflow, systemd unit with `Delegate=yes`, Dockerfile, devcontainer
- [x] Policy cookbook — `docs/policy-cookbook.md`

### Docs
- [x] `docs/quick-start.md`
- [x] `docs/kernel-matrix.md` — minimum kernel versions from kernel documentation; not measured on hardware
- [x] `docs/troubleshooting.md` — userns (Ubuntu 24.04), cgroup delegation, WSL2, seccomp kills, exit codes
- [x] `docs/threat-model.md` — what each layer does and does not protect against

### Distribution
- [x] `cargo-binstall` metadata in the CLI manifest; install script `install.sh` — **checked** (shell syntax only)
- [x] `.deb` metadata (`cargo-deb`) in the CLI manifest — not built
- [x] Nix flake (`flake.nix`) — **untested**: written without access to Nix
- [x] Docker image — `templates/Dockerfile`; not built
- [x] One-line install in the README

---

## Phase 11: Usability & Innovation

- [x] `--doctor` — kernel, WSL, user namespaces, AppArmor userns restriction, Landlock LSM, seccomp actions, cgroup controllers, SELinux context — **verified** (output checked in the container)
- [x] `--learn` — runs the command under `strace` and prints a draft policy — **partly verified**: the missing-`strace` error path is tested; the parsing is unit-tested; a full run needs `strace` installed
- [x] `--dry-run` / `--explain` — prints the effective policy per layer, with warnings — **verified**
- [x] `--json` — exit event with the reason for signals — **verified**
- [ ] Landlock denials reported as an event — not possible from the supervising parent; needs the audit logger wired into the CLI
- [x] `--from-apparmor <file>` — maps file rules; warns on widened globs and unmapped rules — **verified** (smoke test)
- [x] SELinux — `--doctor` reports the process context; the sandbox does not yet check or set contexts
- [x] `std::process::Command` extension (`CommandSandboxExt::sandboxed`) — **checked**
- [ ] `build.rs` helper — not built; the `Command` extension covers the same use
- [x] GitHub Action (`action.yml`) — composite action that installs the binary and runs a command — configured, not run
- [ ] Landlock ABI 4 (TCP) and ABI 6 (scoped signals and abstract sockets) — not started

---

## Open Questions (from spec §5)

- [x] Default syscall and filesystem allowlist for maintainer scripts — proposed as the `maintainer-script` profile (read `/etc`, `/usr`, `/var/lib/dpkg`; write `/var/lib/dpkg` and `/etc`; no network, no capabilities; base syscall allowlist). **Needs review** against tpt-deb-toolkit's real scripts.
- [x] Minimum kernel version matrix — `docs/kernel-matrix.md`. Based on kernel documentation, not measured.

---

## Not verified yet (run before relying on it)

- CI workflows (`ci.yml`, `release.yml`) have not run on GitHub.
- `install.sh`, the composite action, and the `.deb` and binstall metadata have not been run end to end.
- Nix flake: untested.
- aarch64 and riscv64: only the aarch64 syscall names were checked against `libc`; nothing was compiled or run for those targets.
- Live audit-log stream and full chroot jail: not run.

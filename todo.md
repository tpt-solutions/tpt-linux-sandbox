# tpt-linux-sandbox — Todo

> Dual-licensed MIT OR Apache-2.0 · Copyright TPT Solutions · Rust 2024 · MSRV 1.85
> GitHub: https://github.com/TPT-Solutions/tpt-linux-sandbox
> Crate prefix: `tpt-l-*`

Status key: `[x]` done · `[ ]` not done (reason given) · **verified** = ran in a Linux container (privileged root and unprivileged UID 1000, kernel 6.18, debug and release builds; 22 test suites, all ignored tests included) · **checked** = type-checked and clippy-clean for the target (Linux x86_64, aarch64, riscv64), not run.

---

## Phase 1: Workspace Scaffold

- [x] `Cargo.toml` — workspace root with all 11 members, `[workspace.package]`, `[workspace.dependencies]`
- [x] `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE`
- [x] `rust-toolchain.toml` — pin stable channel
- [x] `.github/workflows/ci.yml` — see Phase 9
- [x] `README.md` — rewritten to match the code (Phase 10)
- [x] Crate skeletons (all 11 crates)

---

## Phase 2: Core Sandboxing Primitives

### `tpt-l-landlock-highlevel`
- [x] `RulesetBuilder` with `.allow_read()`, `.allow_write()`, `.allow_exec()`
- [x] `.build()` — opens every path to confirm it exists (no enforcement) — **verified** (unit test)
- [x] ABI v3 filesystem rights (`Refer`, `Truncate`), `RemoveDir`; best-effort on older kernels — **verified** (CLI tests)
- [x] `require_full_enforcement()` — opt-in error on partial enforcement — **checked**
- [x] **ABI 4 — TCP bind and connect port rules** (`allow_tcp_bind`, `allow_tcp_connect`). Explicit port rules are a hard requirement: on kernels before 6.7, `apply` fails with a clear error — **verified** (denial test on 6.18)
- [x] **ABI 6 — scoped abstract Unix sockets and signals** (`isolate_abstract_sockets_and_signals`), best-effort, on by default in the CLI — **verified**: a sandboxed child cannot connect to an abstract socket the unrestricted parent listens on; a control without the scope connects (so the refusal is caused by the scope). Kernel 6.18.
- [x] Forked-child regression test: the allowlist holds for a child — **verified** (root and unprivileged)
- [ ] ABI 5 (ioctl on devices) — not added; no use case in the CLI yet

### `tpt-l-seccomp-builder`
- [x] `SeccompPolicy` with `.allow_syscall()`, `.deny_syscall()`, `.default_action()`
- [x] `deny_syscall` enforced: each deny action goes into its own filter loaded before the allowlist — **checked** (the deny path itself has no runtime test)
- [x] `Errno` range validated (1–4095) — **verified** (unit test)
- [x] Syscall table (~135 names); every name confirmed against `libc` for x86_64, aarch64 and riscv64 — **checked** (`cargo check` and clippy for aarch64 and riscv64)
- [x] **riscv64**: `renameat` does not exist there, so the shared table uses `renameat2` and adds `renameat` only where it exists — **checked**
- [x] `base_profile()` — general-purpose allowlist; `ptrace` returns EPERM — **verified** (forked-child test)
- [x] `validate()` — resolves names before any irreversible stage — **verified**

### `tpt-l-namespaces-rs`
- [x] `NamespaceSet` builder: `.user()`, `.mount()`, `.pid()`, `.network()`
- [x] `unshare(2)` with correct `CLONE_NEW*` flags
- [x] **uid/gid read before `unshare`** — fixes the `uid_map` write — **verified** (forked-child test, root and unprivileged)
- [x] `MultiThreaded` error for user namespaces from a multi-threaded process — **verified** (unit test on thread counting)
- [x] PID namespace: children-only, documented; the CLI forks once more so the command is PID 1 (see Phase 6). Reaping of orphans is left to the command, as with any init process — **verified** (`pid = 1` integration test)

---

## Phase 3: Resource & Access Control

### `tpt-l-cgroup-v2`
- [x] `CgroupConfig` builder: `.cpu_quota()`, `.memory_limit()`, `.io_weight()`, `.pids_limit()`, `.name()`
- [x] Name validated: one path component, no `/`, `..` or NUL — **verified** (unit tests)
- [x] `mkdir` (no reuse of stale directories); `AlreadyExists` reported — **verified**
- [x] Only missing controllers are written to `cgroup.subtree_control` — **verified**
- [x] `memory.swap.max = 0` with the memory limit; `pids.max` — **checked**
- [x] `.enter()`, `.destroy()`, `.release()` — **verified** (forked-child create, enter, release test, root; skips when the user cannot create cgroups)

### `tpt-l-caps-drop`
- [x] `CapsPolicy` builder: `.drop_all()`, `.keep(cap)`
- [x] Bounding dropped first; ambient cleared; securebits locked; inheritable cleared; `no_new_privs` set — **verified** (forked-child test, root and unprivileged)
- [x] **Fixed a release-only bug**: `prctl(2)` takes five arguments and the wrapper passed four, so `PR_CAP_AMBIENT` failed with EINVAL in release builds. Errors now name the failing step — **verified** (release suite)
- [x] `keep()` without `drop_all()` is an error — **verified** (unit test)

### `tpt-l-chroot-jail`
- [x] `JailConfig` builder: `.new_root()`, `.mount_proc()`, `.mount_dev_minimal()`, `.mount_sys_ro()`, `.allow_chroot_fallback()`
- [x] Mount tree made private before any mount or pivot; `pivot_root(".", ".put_old")` — **verified** (forked-child pivot test, root and unprivileged)
- [x] `chroot` fallback is opt-in — **checked**
- [x] `/dev` is a tmpfs with bind-mounted `null`, `zero`, `random`, `urandom`, `tty` only — **checked**
- [x] Symlinks refused when creating mount points — **verified** (unit test)
- [x] Proc mounted `nosuid,nodev,noexec`; `umount` failure is fatal — **checked**

---

## Phase 4: Policy Analysis & Auditing

### `tpt-l-apparmor-parser`
- [x] AppArmor parser → typed AST (hand-rolled); portable (builds on every platform) — **verified**
- [x] Nested profiles rejected; unterminated or unexpected braces rejected — **verified**
- [x] Several rules per line; quoted paths (with `#` and spaces); `@{VAR}` expansion; undefined variables rejected — **verified**
- [x] `deny` rules never become grants — **verified**
- [x] `networkfoo` is not a network rule; unknown permission characters rejected — **verified**
- [x] No `eprintln!` in library code; `unmapped_rules()` returns the rules not converted
- [x] Example: `cargo run -p tpt-l-apparmor-parser --example convert_profile` — **checked** (compiled)

### `tpt-l-selinux-context`
- [x] `SecurityContext` parse; rejects empty fields, whitespace and control characters — **verified**
- [x] `current_process()` distinguishes a missing attr file (`NotEnabled`) from a read error — **verified** (via `--doctor` on a non-SELinux system)

### `tpt-l-audit-logger`
- [x] `NETLINK_AUDIT` socket; bind to the audit group; `EPERM` mapped to `PermissionDenied`
- [x] Sender checked (`nl_pid == 0`); `MSG_TRUNC` detects truncated datagrams
- [x] Netlink header read unaligned; every message in a datagram parsed with `NLMSG_ALIGN`; malformed lengths stop the scan — **verified** (unit tests)
- [x] Receive errors delivered through the channel; reader stops within ~0.5 s of the receiver being dropped
- [x] `subscribe` returns `Result<AuditEvent, AuditError>` items (API change)
- [x] Live subscription test — **verified**: subscribes as root; as an unprivileged user it reports a skip (no `CAP_AUDIT_READ`)
- [x] Example for the live stream — `tail_audit` **verified**: as root it subscribes and streams (no events seen in 4 s; the container has no audit rules); unprivileged it exits with the missing-privilege message

---

## Phase 5: Sandbox Orchestrator Library (`tpt-l-sandbox`)

- [x] `Sandbox::new()` builder with per-layer setter methods (`Clone`)
- [x] 7-stage order in `apply()`; cgroup released if a later stage fails
- [x] `validate()` (public) before any stage: jail/mount rule, seccomp names and errnos, Landlock paths — **verified**
- [x] Landlock setup syscalls allowed automatically when seccomp is applied first — **verified** (CLI runs)
- [x] Warning for user namespaces without a mount namespace
- [x] `CommandSandboxExt::sandboxed()` — sandbox a child process between fork and exec — **verified** (`sandboxed_command` example run)
- [x] Audit logger is not wired in; README says so

---

## Phase 6: CLI (`tpt-l-sandbox-cli`)

- [x] Flags: `--allow-read`, `--allow-write`, `--allow-exec`, `--no-system-paths`, `--no-network`, `--memory-limit`, `--cpu-quota`, `--pids-limit`, `--new-root`, `--cwd`, `--drop-caps`, `--seccomp`, `--pass-env`, `--json`, `--dry-run`, `--doctor`, `--learn`, `--print-profile`, `--from-apparmor`
- [x] **PID namespace by default**: the command is PID 1 of its own namespace. The namespace-creating process forks once more and relays the exit status; signal deaths are explained by the relay (it cannot re-raise a signal, because `tgkill` is not in the allowlist) — **verified** (`cli_runs_command_as_pid_one_by_default`, `cli_share_pids_keeps_host_pid_space`)
- [x] **IPC isolation by default** (`--share-ipc` turns it off) — **checked** (applied on 6.18)
- [x] **TCP port rules**: `--allow-tcp-bind`, `--allow-tcp-connect` — **verified** (`cli_tcp_allowlist_denies_other_ports`: connect to port 9 is denied with EACCES)
- [x] Fork before any restriction; the parent waits, removes the cgroup, and reports the exit — **verified**
- [x] Exit reporting: signals, SIGSYS and SIGKILL explained; `--json` event — **verified**
- [x] Child: environment cleared — **verified**; `setsid` and closing descriptors 3+ — **checked** (no runtime test)
- [x] Argument values validated, not clamped — **verified**
- [x] Integration tests check output and exit status; negative tests assert setup succeeded — **verified** (root and unprivileged)
- [x] Seccomp enforced by default (base profile); `--seccomp log` and `off` — **verified**
- [x] **Built-in profiles no longer set cgroup limits**, because limits need delegation and made `--profile strict` fail on most machines — **verified** (`--profile strict` runs in a container without delegation)

---

## Phase 7: Tests, Docs & CI Polish

- [x] Unit tests for every library crate and the CLI policy and tools modules — **verified**
- [x] Forked-child regression tests (ignored by default, run with `--include-ignored`): namespaces, caps, seccomp, cgroup, jail, Landlock — **verified** (root and unprivileged; skips where a privilege is missing, and says so)
- [x] Integration tests: hostname read; `/tmp` read denied; `--no-network` blocks connect; memory limit kills (skipped without a usable cgroup); `mount` blocked after `--drop-caps`; env scrubbing; `--pass-env`; JSON exit; validation; dry-run; print-profile; unknown profile; PID 1; `--share-pids`; TCP port denial — **verified**
- [x] `missing_docs` and `unsafe_op_in_unsafe_fn` warn — `[workspace.lints.rust]`
- [x] `clippy::pedantic` warn, with four deliberate allows (builder `must_use`, boolean structs, `# Errors` sections, doc prose) — **checked**: clean with `-D warnings` on x86_64, aarch64 and riscv64
- [x] Rustdoc for public APIs; examples for the main crates (Phase 10)
- [x] `cargo deny` config — `deny.toml`; CI job configured, not run
- [x] Publish metadata (`keywords`, `categories`, `description`, `version` on path dependencies)

---

## Phase 8: Correctness Fixes (from platform review, 2026-11-23)

> Found by source reading. Each item has a regression test or a note on how it was checked.

- [x] **namespaces-rs** — uid/gid read before `unshare` — **verified**
- [x] **sandbox-cli** — `--allow-exec`; system directories grant read and exec by default — **verified**
- [x] **sandbox-cli tests** — assertions check output and exit codes; `--no-network` tries a real connect — **verified**
- [x] **caps-drop** — bounding, ambient, securebits, `no_new_privs`; `keep()` without `drop_all()` is an error — **verified**; release-build EINVAL fixed (see Phase 3)
- [x] **chroot-jail** — private mounts before `pivot_root`; opt-in `chroot`; tmpfs `/dev`; symlink-safe mount points — **verified** (pivot test) / **checked**
- [x] **cgroup-v2** — name validated; `subtree_control` (missing controllers only); `pids.max`; `memory.swap.max`; no reuse of stale directories — **verified**
- [x] **cgroup lifecycle** — `release()` on failure and CLI cleanup after the child exits — **verified**
- [x] **seccomp-builder** — `deny_syscall` enforced — **checked**; `Errno` validated — **verified**; table expanded and checked on three architectures — **checked**
- [x] **seccomp-builder** — `landlock_*` syscalls allowed when seccomp runs first — **verified**
- [x] **seccomp (CLI)** — default is the base allowlist — **verified**
- [x] **sandbox `validate()`** — before stage 2 — **verified**
- [x] **landlock-highlevel** — `PartiallyEnforced` rejected only with `require_full_enforcement()`; ABI v3 rights; `RemoveDir`; **port rules fail on kernels without ABI 4** — **verified**
- [x] **sandbox-cli hygiene** — `close_range`, env scrub with `--pass-env`, `setsid`, working directory; invalid limits rejected — **verified**
- [x] **audit-logger** — unaligned read; multi-message datagrams; sender check; errors surfaced; `EPERM` mapped — **verified**
- [x] **apparmor-parser** — nested profiles, unterminated blocks, multi-rule lines, `@{VAR}`, no `eprintln!`, `networkfoo`, unknown permission characters — **verified**
- [x] **threading** — documented; `MultiThreaded` error for user namespaces — **verified**
- [x] **selinux-context** — permission-denied vs not-enabled distinguished; empty fields rejected — **verified**
- [x] **sandbox docs** — audit-logger and stage-2 rollback claims corrected

---

## Phase 9: Housekeeping & CI

- [x] Portable build: `default-members` lists the portable crates — **checked** on Windows
- [x] `version = "0.1.0"` on every path dependency; `apparmor-parser`, `selinux-context` in `[workspace.dependencies]`
- [x] `homepage` — not added: `repository` already provides the link
- [x] `exclude` / `include` — **checked** with `cargo package --list` for `tpt-l-sandbox` and `tpt-l-sandbox-cli`: the package lists contain only the crate's files, and the CLI includes the profiles it embeds. No rule is needed.
- [x] `unsafe_op_in_unsafe_fn` lint
- [x] CI: `cargo deny check` job — configured, not run
- [x] CI: MSRV job (1.85) — configured, not run; some dependency releases may need a newer compiler
- [x] CI: docs job (`cargo doc` with `-D warnings`) — configured, not run
- [x] CI: unprivileged test job (userns sysctl on Ubuntu 24.04) and privileged (root) job — configured, not run; both pass locally in the container
- [x] CI: clippy with `--all-targets -D warnings` — clean locally
- [x] CI: macOS and Windows `cargo check` of the portable crates — configured, not run
- [x] `.github/workflows/ci.yml` and `release.yml` parse as YAML — **verified**
- [x] Forked-child tests for namespaces, caps, seccomp, cgroup, jail and Landlock — **verified**
- [x] Negative-input tests: cgroup name, Errno range, nested and unterminated AppArmor, multi-rule lines, malformed and multipart netlink, symlink mount point
- [x] Table test: every syscall name is unique
- [x] Release workflow (`release.yml`): static musl binaries for x86_64 and aarch64 on version tags — configured, not run
- [ ] Publish crates to crates.io in dependency order — **excluded at your request**

---

## Phase 10: Adoption — Presets, Examples, Docs, Packaging

### Profiles & policy files
- [x] `--profile <name>` with six built-in TOML profiles — **verified**; they set no cgroup limits, so they work without delegation
- [x] `--policy <file>` with the same schema; `schemas/policy.schema.json` — **verified** (parses; deserialization rejects unknown fields)
- [x] Schema covers `pid_namespace`, `isolate_ipc`, `allow_tcp_bind`, `allow_tcp_connect`
- [x] Deviation: `init --profile` became `--print-profile <name> > file`, because the CLI has a trailing command

### Examples & templates
- [x] Examples for the eight main crates (`cargo run -p <crate> --example <name>`) — **verified** to compile; **run**: `sandboxed_command`, `enter_jail` (root and unprivileged)
- [x] `chroot-jail` example: `enter_jail` — **verified**
- [x] All examples now **run**, as root and as UID 1000: `readonly_etc` (denies `/tmp` writes), `base_profile`, `convert_profile`, `enter_namespaces` (uid 0 inside), `sandboxed_command`, `enter_jail`, `tail_audit`. `drop_caps` runs as root and reports the missing privilege as UID 1000 (its docs say to use `unshare -Ur`). `limited_group` now explains the missing cgroup delegation instead of panicking.
- [x] `templates/` — GitHub Actions workflow, systemd unit with `Delegate=yes`, Dockerfile, devcontainer
- [x] Policy cookbook — `docs/policy-cookbook.md`

### Docs
- [x] `docs/quick-start.md`
- [x] `docs/kernel-matrix.md` — ABI 4 and ABI 6 rows now describe what the CLI uses; minimums from kernel documentation, not measured
- [x] `docs/troubleshooting.md`
- [x] `docs/threat-model.md` — updated for the PID namespace, IPC isolation and TCP rules

### Distribution
- [x] **`.deb`** — built with `cargo deb` in a container. Asset paths for the binary and profiles are correct. Dependency: `libc6 (>= 2.39)`, from the build machine's glibc. **verified**
- [x] `cargo-binstall` metadata in the CLI manifest — the `pkg-url` and `bin-dir` match the release workflow's archive names; the remote download is not run — **checked**
- [x] `install.sh` — `sh -n` syntax check passes — **checked**; the download is not run (no release yet)
- [x] **GitHub Action** command step simulated locally with the strict profile — **verified**; the action itself has not run on GitHub
- [ ] Nix flake (`flake.nix`) — **untested**: Nix is not available here
- [ ] Docker image — `templates/Dockerfile` downloads a release that does not exist yet, so it cannot be built until `v0.1.0` is released
- [x] One-line install in the README

---

## Phase 11: Usability & Innovation

- [x] `--doctor` — kernel, WSL, user namespaces, AppArmor userns restriction, Landlock LSM, seccomp actions, cgroup controllers (per controller), SELinux context — **verified**
- [x] `--learn` — runs the command under `strace` and prints a draft policy — **partly verified**: the missing-`strace` error path is tested; parsing is unit-tested; a full run needs `strace`
- [x] `--dry-run` / `--explain` — shows namespaces (including pid), IPC, TCP rules, per-layer policy — **verified**
- [x] `--json` — exit event with the reason for signals — **verified**
- [ ] Landlock denials reported as events — **not done, by recommendation**: the supervising parent cannot see Landlock denials; they need the audit stream and `CAP_AUDIT_READ`. Revisit if audit-based reporting is wanted.
- [x] `--from-apparmor <file>` — maps file rules; warns on widened globs and unmapped rules — **verified**
- [x] SELinux — `--doctor` reports the process context; the sandbox does not check or set contexts. Sufficient for the current scope.
- [x] `std::process::Command` extension (`CommandSandboxExt::sandboxed`) — **verified** (example)
- [ ] `build.rs` helper — **not built, by recommendation**: `CommandSandboxExt` covers the same use without a build step
- [x] GitHub Action (`action.yml`) — **verified** locally (command step); not run on GitHub
- [x] Landlock ABI 4 (TCP) — see Phase 2
- [x] Landlock ABI 6 (scoped abstract sockets and signals) — see Phase 2

---

## Phase 12: Review Follow-ups (2026-11-23)

> From a source-reading review. Status key as above. Line numbers are approximate. Verification: the Linux crates were built and tested in WSL Ubuntu 24.04 (kernel 6.18) as root, with `cargo clippy -D warnings` and `cargo test --workspace -- --include-ignored` passing. The unprivileged run and the delegated-cgroup run were **not** done; CI workflows and `install.sh` have **not** run.

### Tier 1: adoption blockers
- [x] **Child cwd defaults to the invoking directory** (`policy.rs` `resolve_paths`; `main.rs`) — **verified** (`cli_command_starts_in_invoking_directory`). Inside `--new-root` the default is `/`. Doc examples now pass `--allow-read .` because the profile does not grant the cwd.
- [~] **Near-empty environment** — **partly done**: unset `--pass-env` names now warn (**verified**); `build` profile grants `/tmp` writes (**checked**). HOME/TMPDIR are still not passed through — open, since passing HOME exposes the host home directory.
- [x] **GitHub Action works out of the box** (`action.yml`) — default profile `build`, new `workdir` and `version` inputs, `sudo -n` step that warns instead of hiding failures. **Not run** on GitHub. `relax-apparmor-userns` stays on by default, since runners need it.
- [ ] **Install paths disagree and need a published release** (README, quick-start, devcontainer, Dockerfile, CLI README) — needs a `v0.1.0` release; requires your decision on publishing.

### Tier 1: correctness bugs
- [x] **cgroup created under the caller's own cgroup** (`cgroup-v2/src/lib.rs`) — `/proc/self/cgroup` is read at construction; `apply` falls back to the cgroupfs root only when the caller's cgroup refuses controllers (EBUSY, "no internal processes"). **verified** as root (memory-limit test uses the fallback); parsing unit-tested. **Delegated unprivileged run not done.**
- [x] **Supervisor forwards SIGHUP/SIGINT/SIGTERM and kills the namespace on parent death** (`main.rs`) — the cgroup is now created before fork, so the supervisor removes it. **verified** (`cli_forwards_sigterm_to_the_command`). The relay cannot forward signals itself (`kill` is not in the seccomp allowlist); it dies by the signal and `PR_SET_PDEATHSIG` ends the namespace.
- [x] **cgroup leak on error paths** — the supervisor removes the cgroup after a failed wait; `apply` removes the directory when a limit write fails — **checked** (code path; no test for the failing write).
- [x] **Landlock rules checked under `--new-root`** (`landlock-highlevel` `under_root`; `sandbox` `validate`) — **checked**. A missing path now fails in validation, before seccomp. The error text is still a long nested chain (see the follow-up below).
- [x] **`--learn` log in a private directory** (`tools.rs`) — `create_dir` refuses existing paths, including symlinks — **verified** (unit tests for parsing; the strace run itself was not executed here, since `strace` is not installed).

### Tier 2: smaller fixes and doc sync
- [x] `/dev` tmpfs `nodev` — **checked** (the pivot test passes, but it does not exercise device nodes).
- [x] Mount-point symlink check covers every path component (`chroot-jail`, `ensure_dir`/`ensure_file` take the jail root) — **verified** (intermediate-symlink unit test; pivot test as root)
- [x] `close_range` fallback uses the open-file limit — **checked**
- [x] `subscribe()` documents that it needs a Tokio runtime — docs only.
- [x] `selinux-context` rejects an empty level; the dead filter is removed — **verified** (`parse_rejects_empty_level`)
- [x] Docs: exit codes (1 = failure, 2 = usage, and `--doctor` 1 on warnings) — docs in CLI README and quick-start.
- [x] `--doctor`: Refer 5.19 and Truncate 6.2 listed separately; TCP (6.7) and IPC (6.12) rows; `strace` check; exit 1 on warnings — **verified** (run in WSL).
- [x] `--dry-run` says IPC isolation is requested and best-effort; runs the sandbox `validate()` — **verified**.
- [x] Profiles: `untrusted-python` comment fixed; `maintainer-script` spec reference removed; the two untrusted profiles note their shared baseline. Duplicates are kept on purpose.
- [x] Validation errors say where a value can come from (flag or policy file) — **checked**.
- [x] `--learn` writes `allow_write` for open flags with write intent; handles escaped quotes — **verified** (unit tests).

### Tier 3: CI, release, supply chain
- [x] MSRV job runs `cargo +1.85` (the toolchain file pins stable); `--locked` added to CI — **not run** on GitHub. Two `cargo +1.85` details are unverified: whether `dtolnay/rust-toolchain@1.85` installs the toolchain by that name.
- [x] Actions pinned to commit SHAs (resolved with `git ls-remote`); `permissions: contents: read` at top level; release write permission moved to the job — **not run**. The `dtolnay` action is pinned to a snapshot of its `stable` branch.
- [x] Silent skips fail the root job: the job runs with `--nocapture` and fails on any `skipping:` line — **not run on GitHub**; locally the root run has no skips.
- [~] Release: tag-vs-version check (**not run**) and `checksum: sha256` so the release publishes `.sha256` files (**not run**; check the action's output name on the first real release). Provenance attestation not added.
- [x] `install.sh`: version pin via `TPT_SANDBOX_VERSION`, SHA-256 verification, fails closed if the checksum is missing — **checked** (`sh -n`); not run against a release.
- [ ] Dockerfile: checksum verification, pinned version, digest-pinned base image; Docker build and hadolint jobs
- [ ] Nix flake: `flake.lock` and a CI job, or remove until tested
- [x] Portable job renamed to say what it checks — **not run**.
- [~] Test gaps: `--policy` missing file, `--seccomp off|log`, `--pids-limit 0`, command-not-found exit 127 — **verified** (new integration tests). Still open: `doctor()` text output and the `--learn` flow beyond the strace-missing path.

### Tier 4: automation
- [x] `.github/dependabot.yml` for cargo and github-actions — **checked** (YAML written; not validated by GitHub).
- [ ] `release-plz` or cargo-release + git-cliff for versions and changelog
- [ ] `justfile`/xtask with `just ci`; `.pre-commit-config.yaml`
- [x] `rust-toolchain.toml` installs clippy and rustfmt — **checked**

### Tier 5: features
- [ ] `tpt-sandbox check <policy>` — schema and path validation without a command (S)
- [ ] `--print-schema` and `#:schema` header in `--print-profile` for Taplo/VS Code (S)
- [ ] Shell completions and man pages (clap_complete, clap_mangen), shipped in the `.deb` (S)
- [x] `--doctor --json` (S) — one JSON object on stdout with `checks` and `exit_code` — **verified** (integration test; WSL output)
- [x] `--memory-limit` accepts K, M and G suffixes — **verified** (`size_tests`, and the memory test passes as root)
- [ ] `--learn -o file`; complete TOML output (S-M) — `allow_write` is now emitted, but there is no `-o`
- [ ] Explain denials: re-run under strace, list EACCES paths and the grant that covers each (M)
- [ ] Toolchain profiles (`cargo`, `node`, `python-venv`) with `$HOME`/`$PWD` expansion in policy files (M)
- [ ] Profile sharing: user profile directory, `--profile <path>` (M)

### Adoption: examples and templates
- [ ] CLI recipes in `docs/recipes/`: Python venv, npm install, cargo build under `~/.cargo`, make/gcc, offline untrusted script, CI step with workdir
- [ ] CI job that runs every documented recipe command as a smoke test
- [ ] "First five minutes" path: `--doctor` → `--dry-run` → `--learn` → save policy → `check`
- [ ] Schema association (VS Code, Taplo) in quick-start
- [~] Quick Start examples now include `--allow-read .`; they have not been run on a clean machine

### Step-by-step follow-up (2026-11-23, second pass)

- [x] **Unprivileged run** — all test binaries as `nobody` (not UID 1000: no new account was created): every suite passes; cgroup and memory tests skip with their stated reasons. **verified**
- [x] **Delegated cgroup, root** (`systemd-run --scope -p Delegate=yes`) — **verified**; a memory-limited command runs in `…/tpt-sandbox-<pid>` with `memory.max` set.
- [x] **Delegated cgroup, non-root** (`systemd-run --wait -p User=nobody -p Delegate=yes`) — the cgroup unit tests pass. The CLI memory test skips, because the harness shares the cgroup. **Found and fixed:** the supervisor used the cgroupfs root after the own-cgroup path failed. A process alone in its delegated cgroup now moves into `tpt-sandbox-host` and succeeds (checked by hand). Limitation kept on purpose: a cgroup that holds other processes cannot enable controllers without moving them, and we do not move other processes. The error now names the caller's cgroup.
- [x] **`--new-root` error names the missing path** — **verified** (`cli_new_root_without_system_directories_explains_itself`)
- [x] **Doctor checks the caller's cgroup** — **verified** (run in WSL)
- [x] **Step 2, static checks** — YAML parses for `ci.yml`, `release.yml`, `dependabot.yml`, `action.yml`; `sh -n` passes for `install.sh` and the smoke script. `actionlint` and `shellcheck` are not installed, so those were not run. **Still open:** GitHub has not run the workflows.
- [x] **Step 4, recipes** — `docs/recipes/` (index plus Python venv, Cargo, C with make, untrusted script, CI step) and `scripts/recipes-smoke.sh`, which runs the recipe commands. Run in WSL: **all pass**. The CI step is wired into the unprivileged job; not run on GitHub. Not smoke-tested: `pip install`, `cargo build`, `cargo test`, the CI action.
- [x] **Step 5, `--check-policy FILE`** — **verified** (two integration tests). Flag rather than `check` subcommand, because a subcommand clashes with the trailing command; same style as `--print-profile`.
- [x] **Bug found by the recipes: `make` could not run `cc` under the sandbox.** Four syscalls were missing from the base allowlist: `faccessat2` (used by `eaccess`), `getrusage`, `setresuid` and `setresgid` (GNU make calls the last two at startup). With `EPERM` as the default action, make reported `cc: Operation not permitted`. Added all four. `setresuid`/`setresgid` can only keep the caller's own ids, because the user namespace maps one id; the base-profile doc comment says so. **verified** (smoke test and full suite).

### Follow-ups still open
- [x] **Shared delegated cgroup** — opt-in `move_existing_processes()` / `--move-cgroup-processes` moves the other processes into `tpt-sandbox-host`; off by default. Without it the run is refused with a clear error. **verified** as non-root in a delegated unit (refused without the flag; succeeds with it). The moved processes stay in the leaf afterwards.
- [x] **`drop_caps` example** reports the missing privilege and exits 1 instead of panicking — **verified** as UID 65534.
- [x] `tail_audit` exit codes documented in the example (1 unprivileged, 0 on stream end) — **checked**.
- [x] Missing command (`tpt-sandbox` with no arguments, or `--learn` without one) now exits 2, the documented usage-error code; it exited 1 before. — **verified** (`cli_without_command_is_a_usage_error`).

---

## Open Questions (from spec §5)

- [x] Default syscall and filesystem allowlist for maintainer scripts — proposed as the `maintainer-script` profile. **Needs review** against tpt-deb-toolkit's real scripts.
- [x] Minimum kernel version matrix — `docs/kernel-matrix.md`. Based on kernel documentation, not measured.

---

## Not verified yet (run before relying on it)

- CI workflows (`ci.yml`, `release.yml`) have not run on GitHub.
- `install.sh` download, `cargo binstall` download and the composite action have not run against a real release.
- Nix flake: untested. Docker image: not built (needs a published release).
- Nix flake and Docker image (see Phase 10).
- Nothing has been pushed; CI has not run on GitHub.

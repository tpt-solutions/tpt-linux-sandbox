# Cargo

Run `cargo` from a project. The smoke test runs `cargo metadata`, which reads
the project and needs no network:

```sh
tpt-sandbox --profile build --pass-env HOME \
    --allow-exec "$HOME/.cargo" --allow-exec "$HOME/.rustup" \
    -- cargo metadata --format-version 1 --no-deps
```

Why each flag is there:

- `cargo` is a rustup proxy. It runs the real binary from `~/.rustup`, which
  needs exec access, and reads `~/.cargo`.
- `--pass-env HOME` lets the proxy find its toolchain. Without it, cargo
  reports that it cannot find `cargo`.

For `cargo build` and `cargo test`, also grant the registry cache and allow
network access to the crates index:

```sh
tpt-sandbox --profile build --pass-env HOME \
    --allow-exec "$HOME/.cargo" --allow-exec "$HOME/.rustup" \
    --allow-write "$HOME/.cargo" \
    -- cargo build
```

The smoke test does not run `cargo build`, because it needs the network.

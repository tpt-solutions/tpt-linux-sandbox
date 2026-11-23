# CI step

The repository's composite action runs a command inside the sandbox on a
GitHub runner. It installs the CLI, prepares the runner, and runs your command
with the profile you pick.

```yaml
- uses: TPT-Solutions/tpt-linux-sandbox@v0.1.0
  with:
    version: v0.1.0
    profile: build
    command: cargo test --workspace
```

Inputs that matter here:

- `profile` defaults to `build`, which reads and writes the checkout.
- `workdir` sets the directory the command runs in (default: the workspace).
- `version` pins the CLI release. Use a tag in production workflows; `latest`
  moves.
- `relax-apparmor-userns` (default `true`) turns off the Ubuntu 24.04 AppArmor
  restriction on user namespaces. Set it to `false` on runners that do not
  need it.

The action is not run on GitHub yet, so treat this recipe as untested until a
release exists. The command inside it uses the same flags as the other
recipes.

# Recipes

Copy-paste commands for common jobs. Each one runs under a built-in profile
with the smallest extra grants that work. Start with
[quick start](../quick-start.md) if you have not run `tpt-sandbox` yet, and
use [troubleshooting](../troubleshooting.md) when a command is denied.

| Recipe | What it runs | Verified |
|---|---|---|
| [Python virtual environment](python-venv.md) | `python3 -m venv` inside the project | smoke test |
| [Cargo](cargo.md) | `cargo metadata` under `build` (no network) | smoke test |
| [C with make](c-make.md) | `make` and run the result | smoke test |
| [Untrusted script](untrusted-script.md) | a script with no network | smoke test |
| [CI step](ci-step.md) | the GitHub Action | not run on GitHub yet |

"Verified" means `scripts/recipes-smoke.sh` runs the same command in CI, so a
change to the CLI that breaks a recipe fails the build. Steps marked as not
covered by the smoke test are described from the profiles, not run.

Each recipe starts in the directory you run it from. The default profiles
grant nothing outside the paths listed, so a missing file usually means a
missing `--allow-read` or `--allow-exec` flag.

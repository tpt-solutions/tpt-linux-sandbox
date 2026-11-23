#!/bin/sh
# Runs the commands from docs/recipes against a built tpt-sandbox, so the
# documented recipes cannot drift from the CLI. CI runs this after a build.
#
#   TPT_SANDBOX=target/debug/tpt-sandbox scripts/recipes-smoke.sh
set -eu

SANDBOX="${TPT_SANDBOX:-tpt-sandbox}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

step() { echo "== $1"; }

step "python venv"
mkdir "$WORK/py"
cd "$WORK/py"
"$SANDBOX" --profile build -- python3 -m venv --without-pip .venv
"$SANDBOX" --profile build -- .venv/bin/python -c 'import sys; print("venv ok:", sys.prefix)'

step "cargo metadata (no network)"
cp -r "$ROOT/docs/recipes/fixtures/cargo-hello" "$WORK/cargo"
cd "$WORK/cargo"
"$SANDBOX" --profile build --pass-env HOME \
    --allow-exec "$HOME/.cargo" --allow-exec "$HOME/.rustup" \
    -- cargo metadata --format-version 1 --no-deps >/dev/null
echo "cargo ok"

step "C with make"
cp -r "$ROOT/docs/recipes/fixtures/c-hello" "$WORK/c"
cd "$WORK/c"
"$SANDBOX" --profile build -- make
"$SANDBOX" --profile build --allow-exec . -- ./hello

step "untrusted script, no network"
cp -r "$ROOT/docs/recipes/fixtures/untrusted" "$WORK/untrusted"
cd "$WORK/untrusted"
out="$("$SANDBOX" --profile untrusted-python --allow-read . -- python3 script.py)"
echo "$out"
case "$out" in
    *"network: blocked"*) ;;
    *) echo "untrusted script was not blocked from the network" >&2; exit 1 ;;
esac

step "policy check"
"$SANDBOX" --check-policy "$ROOT/crates/tpt-l-sandbox-cli/profiles/build.toml" >/dev/null
echo "policy check ok"

echo "ALL RECIPES OK"

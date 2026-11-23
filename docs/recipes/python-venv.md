# Python virtual environment

Create a virtual environment inside the project and run Python from it.

```sh
tpt-sandbox --profile build -- python3 -m venv .venv
tpt-sandbox --profile build -- .venv/bin/python script.py
```

The `build` profile reads the system directories and writes the current
directory, so `.venv` is created in the project.

**Installing packages** needs two things this recipe does not cover:

- On Debian and Ubuntu, `ensurepip` comes from the `python3-venv` package.
  Without it, `python3 -m venv` fails with a message that names the package.
- `pip` caches downloads in `~/.cache/pip`, which `build` does not write.
  Grant it with `--allow-write "$HOME/.cache/pip"` and pass `HOME` through with
  `--pass-env HOME`.

Network access is not restricted by the `build` profile, so `pip install`
works once those grants are in place. The smoke test uses
`--without-pip` and does not cover installing packages.

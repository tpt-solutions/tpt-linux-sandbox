# Untrusted script

Run code you do not trust with no network access, reading only the current
directory and the system libraries:

```sh
tpt-sandbox --profile untrusted-python --allow-read . -- python3 script.py
```

`untrusted-python` drops capabilities, blocks network access and enforces
seccomp. It sets no resource limits, because those need cgroup delegation.
Add them with `--memory-limit` and `--pids-limit` (see
[troubleshooting](../troubleshooting.md) for delegation):

```sh
tpt-sandbox --profile untrusted-python --allow-read . \
    --memory-limit 256M --pids-limit 64 -- python3 script.py
```

`--allow-read .` is needed because the script lives in the current directory,
which the profile does not grant. The fixture in
[fixtures/untrusted](fixtures/untrusted) tries a network connection and
reports it blocked.

The same command works with `untrusted-node` for JavaScript, with `node` in
place of `python3`.

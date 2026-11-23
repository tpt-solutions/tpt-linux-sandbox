# C with make

Build a C program with `make` and run the result. The fixture in
[fixtures/c-hello](fixtures/c-hello) is the one the smoke test uses.

```sh
tpt-sandbox --profile build -- make
tpt-sandbox --profile build --allow-exec . -- ./hello
```

- `build` reads the compiler's include and library directories and writes
  the project directory and `/tmp`, which the compiler uses for temporary
  files.
- Running `./hello` needs `--allow-exec .`, because the binary is in the
  project directory, not a system path.

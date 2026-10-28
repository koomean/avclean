# Changelog

## 2.1.0

- Publish Homebrew package `avclean` with executable `av`.
- Package a private, reproducible ClamAV/curl/OpenSSL runtime.
- Bootstrap per-user config/signatures safely on a new machine.
- Add offline `doctor` and real signature-matching `self-test` commands.
- Preserve all seven menu actions and the original `--scan` interface.
- Add command aliases and an explicit `--jobs` option.
- Preserve accurate errors/limits/skips, safe filenames, private daemon ownership,
  partial reports and collision-safe quarantine from version 2.0.

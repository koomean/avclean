# Reproducing the Homebrew runtime

The formula in `koomean/homebrew-tap` is the build recipe. It pins the avclean
source release and the unmodified upstream sources below, including SHA-256
checksums. Homebrew manages Python 3.14, OpenSSL 3, pcre2, json-c, CA certificates,
CMake, pkgconf and Rust. Both private curl and ClamAV link the same OpenSSL 3.

- ClamAV 1.5.4: `clamav-1.5.4.tar.gz`
  SHA256 `1af1117a228f1b5bc7fa91a0dabc37848a99e7d25188e9be8043332ce721dfd3`
- curl 8.23.0: `curl-8.23.0.tar.bz2`
  SHA256 `95b22eb32bf6d1fa6e3e9463bdb61cece3efc56d86576a9b3cbd428246a6d854`

The release provides these corresponding source archives alongside binary bottles.
ClamAV's release includes the locked Rust source/vendor tree. The build sets
`CARGO_NET_OFFLINE=true`, uses Homebrew's baseline architecture flags, and never
uses `-march=native` or `-mcpu=native`. The runtime is installed in the formula's
`libexec/runtime`; user state is not part of the package.

```sh
brew install --build-from-source koomean/tap/avclean
brew test koomean/tap/avclean
brew linkage --test koomean/tap/avclean
```

Bottle builds use `brew install --build-bottle`, followed by `brew bottle --json`.
Each bottle is tagged for its supported macOS/architecture. The formula retains
source-build installation when no matching bottle is available.

The native library licenses and notices are installed under
`share/avclean/licenses`. The application and helper use MIT; the third-party
components retain their upstream licenses and notices.

# Third-party components

The avclean menu and Python helper are MIT licensed. The Homebrew formula builds
third-party source distributions without changing their license terms. Its
installed `share/avclean/licenses/` directory includes their license notices.

| Component | Version | Source | License/notice |
|---|---|---|---|
| ClamAV | 1.5.4 | https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.5.4 | GPL-2.0-or-later; see upstream COPYING.txt and COPYING/ |
| curl | 8.23.0 | https://curl.se/download/curl-8.23.0.tar.bz2 | curl license, upstream COPYING |
| UnRAR inside ClamAV | as shipped upstream | ClamAV release source, libclamunrar/ | upstream license.txt and its distribution restrictions |
| libmspack inside ClamAV | as shipped upstream | ClamAV release source, libclammspack/ | upstream COPYING.LIB |

ClamAV's release archive includes its locked Rust dependencies and their upstream
licenses. OpenSSL, Python, json-c, pcre2 and CA certificates are Homebrew-managed
dependencies with their own licenses. Source URLs and SHA-256 checksums are in the
formula; the formula builds from those publicly available corresponding sources.

No virus signature databases, user logs, quarantined files, account credentials or
machine-specific runtime binaries are included in the avclean source release.

# avclean

A local, on-demand ClamAV scanner for macOS. Install **avclean**, run **av**.

The original seven-option Terminal menu stays intact. A private scanning engine,
accurate coverage reports, safe filename handling and an offline detection test
make the scanner easier to operate and verify.

## Install

Supported: macOS on Apple Silicon (ARM64). Intel and Linux are not supported by
this release. Homebrew and Xcode Command Line Tools are required for source builds.

```sh
brew install koomean/tap/avclean
av
```

The formula builds an isolated ClamAV/curl runtime against OpenSSL 3. It leaves an
existing Homebrew ClamAV installation and its services alone. A source installation
may take several minutes; Homebrew uses a matching prebuilt bottle when available.

The first scan downloads official ClamAV signatures. To prepare them explicitly:

```sh
av update
av doctor
av --self-test
```

The self-test runs offline against a harmless generated signature and temporary
files. It checks both standalone scanning and file-descriptor scanning through a
short-lived private daemon; it does not need the official signature database.

## Use

```sh
av                                      # open the menu
av scan "$HOME/Downloads"                # scan files or folders
av --scan "/path/with spaces/example.zip" # original CLI remains available
av quick                                # Downloads, Desktop, Documents
av full                                 # interactive confirmation
av update                               # signature updates
av status                               # engine, paths and worker count
av doctor                               # offline dependency/database checks
av --self-test                          # offline actual-detection check
av --jobs 6 scan "$HOME/Downloads"        # choose concurrency
```

Menu: **1** update, **2** quick scan, **3** choose folder, **4** full scan,
**5** drag and drop, **6** history, **7** status, **q** quit.

The default is up to four performance-core workers. `AV_JOBS=1..32` or `--jobs N`
overrides it. One private daemon is reused while the menu is open, restarted when
the signature files change, and stopped on quit or cancellation.

Scan exit status: **0** clean and complete, **1** detections with complete coverage,
**2** incomplete/error (including detections with coverage errors), **130** cancelled.

## Data and privacy

- Scanned file contents stay on the computer; this app does not upload samples.
- Official signature updates require Internet access through FreshClam.
- Configuration, signatures and reports live under `~/.av/`; `AV_DIR` changes that
  location. Signature files are in `~/.av/database/`.
- Detected files are moved only after an interactive confirmation, into
  `~/quarantine/` (`AV_QUARANTINE_DIR` overrides it). Unique batch directories and a
  manifest preserve original paths; changed or replaced files are refused.
- `brew uninstall avclean` removes the program. User reports, signatures and
  quarantined files remain available until the user removes them.

`AV_DB_DIR` and `AV_FRESHCLAM_CONF` support an explicitly chosen database/config.
An existing user config is preserved; the private update copy removes `NotifyClamd`
because the app manages its own engine. Never put credentials into issue reports.

## Coverage and limits

The scanner reports discovery/read errors, skipped files and engine limits
separately from malware detections. It never declares a complete clean result when
those conditions occur. Internal engine errors are retained even if an engine
response says `OK`.

Only accessible regular files are scanned. Descendant symlinks are not followed;
explicit symlink targets are reported as skipped. macOS cloud placeholders are
reported as skipped rather than downloaded automatically. Individual files above
2047 MiB and archive/engine limits make coverage incomplete.

“Full scan” covers `/Users`, `/Applications`, `/Library`, `/opt` and `/usr/local`.
Grant your Terminal Full Disk Access in macOS settings to reduce protected-folder
errors when appropriate. The app does not change macOS privacy permissions.
Detection can produce false positives, and a clean scan cannot prove that a file
is safe from every threat.

## Update and remove

```sh
brew update
brew upgrade avclean
brew uninstall avclean
```

`av update` updates signatures; `brew upgrade avclean` updates the app/runtime.
Runtime versions and source checksums are pinned in the
[Homebrew formula](https://github.com/koomean/homebrew-tap/blob/main/Formula/avclean.rb).

## Development

Python 3.10+ and zsh are sufficient for the regression suite. Homebrew selects
Python 3.14 for the installed package. No pip packages are required.

```sh
zsh -n bin/av
python3 -m unittest discover -s tests -v
```

See [architecture](docs/ARCHITECTURE.md), [third-party notices](THIRD_PARTY_NOTICES.md)
and [security reporting](SECURITY.md).

## ภาษาไทย

ติดตั้งด้วย `brew install koomean/tap/avclean` แล้วเปิดด้วย `av` ได้เลย เมนู 1–7 และ q
เหมือนเดิม ใช้ `av update` อัปเดตฐานข้อมูล และ `av --self-test` ทดสอบตัวตรวจแบบออฟไลน์
ไฟล์ที่สแกนไม่ถูกอัปโหลด การกักกันต้องยืนยันก่อน และรายงานจะแจ้งเมื่อสแกนไม่ครบ

# Architecture and trust boundaries

`avclean` is the package name; `av` is the command. The wrapper provides an
on-demand Terminal menu and command-line scan around ClamAV. It does not install
a background monitoring service.

## Components and data flow

- `bin/av` owns the menu, prerequisite checks, signature updates, temporary
  configuration, and child-process lifecycle.
- `lib/av_engine.py` uses Python's standard library to discover files, exchange
  file descriptors with ClamAV, write reports, and move confirmed detections to
  quarantine after a separate user choice.
- The ClamAV runtime supplies `clamd`, `clamscan`, and `freshclam`. The wrapper's
  license does not replace the runtime's license or notices.

A scan follows this path:

1. Validate the platform, runtime, and writable user state.
2. Check or update the signature database. An update failure is reported; an
   existing usable database may still be used with an unverified freshness
   warning.
3. Start a private, foreground `clamd` child with its own Unix socket,
   configuration, temporary directory, and persistent engine log. A healthy
   engine can be reused during the same menu session. A changed database
   fingerprint causes a restart.
4. Discover accessible regular files into a JSON-lines index. Normalize explicit
   targets to absolute paths, deduplicate overlapping paths, and retain
   discovery errors.
5. Submit a bounded number of scan jobs. Each worker opens the file without
   following a final symlink, passes its descriptor through the Unix socket
   using ClamAV's `FILDES` protocol, and checks file metadata after the reply.
6. Preserve detections and failures in text and JSON reports. Review new engine
   diagnostics before deciding whether a clean socket reply is trustworthy.
7. Stop owned scan workers when cancelled. Stop the private engine when the
   session ends, is cancelled, or reports an engine failure.

Only tracked child processes belonging to the current shell are eligible for
termination. The wrapper does not stop or reload unrelated ClamAV services.
Signature-update configuration excludes `NotifyClamd` so a private update does
not request a reload of another service.

## Coverage and result semantics

A clean result means the indexed files completed under the reported policy. It
is not a guarantee that a file is harmless or that every byte on the computer
was inspected. Detection quality depends on the ClamAV runtime and signatures.

- Directory and file symlinks discovered below a target are not followed.
  Explicit symlink targets are reported as unscanned.
- Files above the configured size limit, engine resource limits, inaccessible
  files, inaccessible directories, and files changed during scanning prevent a
  complete-coverage result.
- Cloud placeholders are reported as skipped rather than implicitly downloaded.
- Active runtime files, the current report, and the private engine's working
  files are excluded to avoid scanning files the scan itself is modifying.
  Exclusions and counts are recorded in the report.
- The menu's broad scan covers the listed filesystem locations. The current
  user and macOS privacy permissions determine which files are accessible.
- A detection can coexist with incomplete coverage. Inspect the counts and
  `coverage_complete` field as well as `outcome`.

The command-line exit codes are `0` for a complete clean result, `1` for
complete coverage with detections, `2` for an error or incomplete coverage, and
`130` for cancellation. Reports preserve partial findings after a normal
cancellation.

## Privacy and local artifacts

Default user state is `~/.av/`: the database is `~/.av/database/`, configuration
is `~/.av/freshclam.conf`, and reports are below `~/.av/logs/`. `AV_DIR` moves the
state root; `AV_DB_DIR` and `AV_FRESHCLAM_CONF` choose explicit alternatives.
Initialization preserves an existing user configuration and creates missing
private state without downloading signatures. `av doctor` checks dependencies
and the database offline. `av --self-test` uses its own temporary signature and
files, so it also works before the official database is downloaded.

File scanning is local. The wrapper sends file descriptors to a private local
Unix socket; it does not upload scanned files to a malware-analysis service.
Signature updates and package installation require network access to their
configured distribution services.

Reports can contain full filenames, target paths, detection names, and error
messages. Treat reports and quarantine manifests as private data when sharing
an issue. The wrapper creates its new state with a restrictive file-creation
mask. Initialization validates owned state directories and files, rejects final
symlinks, and applies private permissions. Permissions on parent directories and
an explicitly chosen quarantine destination remain relevant.

## Quarantine

Finding a detection does not automatically delete or move it. A separate
quarantine action reads the scan report and verifies that the source remains a
regular file with the recorded device, inode, size, and modification time.
Changed or replaced sources are refused and need another scan.

Each action creates a unique batch directory. A pending manifest is written
before changing a source pathname. The source is atomically claimed into a
private holding directory on its own filesystem, and its identity is checked
again before committing it to quarantine. Same-filesystem commits use an
exclusive hard link; cross-filesystem copies use an exclusive destination and a
verified open descriptor.

Numbered destination names avoid same-basename collisions, including concurrent
actions. A manifest records original and destination paths, identity, signature,
and move status. If a source changes, rollback uses a no-clobber link. When the
original pathname has been recreated, the staged file remains in its holding
directory and the manifest records its recovery path. Review that path after a
reported recovery failure.

Quarantine is a filesystem move with an audit trail; it is not an execution
sandbox. Metadata checks reduce accidental races but do not provide a guarantee
against a process actively modifying files and restoring their metadata.

## Validation boundaries

The regression suite uses temporary files, local fake Unix-socket daemons, and
real Python/Zsh subprocesses. It covers filename preservation, failure
accounting, resource-limit reporting, cancellation, process ownership,
concurrent engine logs, update configuration, and quarantine safety. These
tests do not certify the native ClamAV engine or the freshness of a downloaded
signature database. Release validation must separately exercise the packaged
native runtime and its updater on a supported machine.

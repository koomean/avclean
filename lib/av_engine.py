#!/usr/bin/env python3
"""Private ClamAV scan worker for av; uses only Python's standard library.

The menu owns the daemon. This module never starts/stops a daemon or changes its
configuration. Directory symlinks and file symlinks encountered during discovery
are not followed. A symlink explicitly supplied as a target is reported.
"""

from __future__ import annotations

import argparse
import array
from collections import Counter
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata

__version__ = "2.1.0"
MAX_FILE_SIZE = 2047 * 1024 * 1024
COUNTS = ("indexed", "completed", "scanned", "threats", "limits", "errors", "skipped")


def safe_text(value: object) -> str:
    """Escape terminal control characters, preserving ordinary Unicode text."""
    text = str(value)
    return "".join(
        {"\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(
            ch, f"\\u{ord(ch):04x}"
        )
        if unicodedata.category(ch).startswith("C")
        else ch
        for ch in text
    )


def atomic_write(path: str | Path, text: str) -> None:
    path = Path(path)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8", errors="backslashreplace") as out:
            out.write(text)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_write_json(path: str | Path, value: object) -> None:
    atomic_write(path, json.dumps(value, ensure_ascii=True, indent=2) + "\n")


def identity_from_stat(info: os.stat_result) -> dict[str, int]:
    return {
        "dev": info.st_dev,
        "ino": info.st_ino,
        "size": info.st_size,
        "mtime_ns": info.st_mtime_ns,
    }


class Cancelled(Exception):
    pass


def receive_reply(connection: socket.socket, stop: threading.Event, deadline: float) -> bytes:
    chunks = bytearray()
    while b"\0" not in chunks:
        if stop.is_set():
            raise Cancelled()
        if time.monotonic() >= deadline:
            raise TimeoutError("ClamAV did not reply before the scan timeout")
        try:
            part = connection.recv(4096)
        except socket.timeout:
            continue
        if not part:
            raise ConnectionError("ClamAV closed the connection without a complete reply")
        chunks.extend(part)
        if len(chunks) > 65536:
            raise ValueError("ClamAV reply exceeds the protocol response limit")
    return bytes(chunks).split(b"\0", 1)[0]


def daemon_command(socket_path: str, command: bytes, stop: threading.Event,
                   timeout: float = 1.0) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(min(timeout, 0.2))
        connection.connect(socket_path)
        connection.sendall(b"z" + command + b"\0")
        return receive_reply(connection, stop, time.monotonic() + timeout)


def ping(socket_path: str, stop: threading.Event, timeout: float = 1.0) -> bool:
    return daemon_command(socket_path, b"PING", stop, timeout) == b"PONG"


def classify_reply(reply: bytes) -> tuple[str, str]:
    response = reply.decode("utf-8", errors="replace")
    if response.endswith(": OK"):
        return "clean", ""
    if response.endswith(" FOUND") and ": " in response:
        signature = response.rsplit(": ", 1)[1][:-6]
        if not signature:
            return "error", "ClamAV returned an empty detection name"
        if signature.startswith("Heuristics.Limits.Exceeded"):
            return "limit", signature
        return "threat", signature
    if response.endswith(" ERROR"):
        return "error", response.rsplit(": ", 1)[-1][:-6]
    return "error", f"Unexpected ClamAV reply: {safe_text(response)}"


def scan_file(
    path: str,
    socket_path: str,
    max_file_size: int,
    stop: threading.Event,
    timeout: float = 180.0,
) -> dict:
    result = {"path": path, "status": "error", "message": "", "scanned": False}
    descriptor = None
    engine_active = False
    try:
        if stop.is_set():
            raise Cancelled()
        before_open = os.lstat(path)
        if not stat.S_ISREG(before_open.st_mode):
            result.update(status="skipped", message="File is no longer a regular file")
            return result
        if getattr(before_open, "st_flags", 0) & getattr(stat, "SF_DATALESS", 0):
            result.update(status="skipped", message="Cloud placeholder is not downloaded; download it before scanning")
            return result
        if before_open.st_size > max_file_size:
            result.update(status="skipped", message=f"File exceeds {max_file_size} byte scan limit")
            return result
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        result["identity"] = identity_from_stat(opened)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev, opened.st_ino
        ) != (before_open.st_dev, before_open.st_ino):
            raise OSError("File changed while opening it")
        if opened.st_size > max_file_size:
            result.update(status="skipped", message=f"File exceeds {max_file_size} byte scan limit")
            return result
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            engine_active = True
            connection.settimeout(0.2)
            connection.connect(socket_path)
            connection.sendall(b"zFILDES\0")
            rights = array.array("i", [descriptor])
            connection.sendmsg([b"\0"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
            reply = receive_reply(connection, stop, time.monotonic() + timeout)
        kind, message = classify_reply(reply)
        if kind == "error" and not (reply.endswith(b" ERROR") and b": " in reply):
            result["engine_error"] = True
        unchanged = identity_from_stat(os.fstat(descriptor)) == result["identity"]
        try:
            current = os.lstat(path)
            unchanged = unchanged and stat.S_ISREG(current.st_mode) and (
                identity_from_stat(current) == result["identity"]
            )
        except OSError:
            unchanged = False
        if not unchanged:
            if kind == "threat":
                result["changed"] = True
            else:
                kind, message = "error", "File changed or was removed during scanning"
        result.update(status=kind, message=message, scanned=unchanged and kind in ("clean", "threat"))
    except Cancelled:
        result.update(status="cancelled", message="Scan cancelled")
    except (OSError, ValueError) as error:
        result.update(status="error", message=str(error))
        if engine_active:
            result["engine_error"] = True
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return result


class ScanState:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.work = Path(args.work)
        self.stop = threading.Event()
        self.report = {name: 0 for name in COUNTS}
        self.report.update(
            version=__version__,
            started=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            targets=[os.path.abspath(os.path.expanduser(path)) for path in args.targets],
            records=[],
            symlinks_ignored=0,
            engine="clamd FILDES",
            jobs=args.jobs,
            max_file_size=args.max_file_size,
            policy="Regular files only; descendant symlinks are not followed; configured av runtime paths are excluded",
            exclusions=[os.path.abspath(os.path.expanduser(path))
                        for path in getattr(args, "exclude_path", [])],
            internal_paths_excluded=0,
            engine_errors=0,
            engine_healthy=True,
        )
        if getattr(args, "engine_log", None):
            self.report["engine_log"] = os.path.abspath(args.engine_log)
        if getattr(args, "daemon_pid", None):
            self.report["daemon_pid"] = args.daemon_pid
        self.phase = "indexing"
        self.last = ""
        self.last_progress = 0.0
        self.started = time.monotonic()

    def progress(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last_progress < 0.1:
            return
        values = [self.phase] + [str(self.report[name]) for name in COUNTS]
        values.append(safe_text(self.last))
        atomic_write(self.work / "progress", "\t".join(values) + "\n")
        self.last_progress = now

    def record(self, result: dict, completed: bool = False) -> None:
        kind = result["status"]
        if completed:
            self.report["completed"] += 1
        if result.get("scanned"):
            self.report["scanned"] += 1
        if kind == "threat":
            self.report["threats"] += 1
        elif kind == "limit":
            self.report["limits"] += 1
        elif kind == "error":
            self.report["errors"] += 1
        elif kind == "skipped":
            self.report["skipped"] += 1
        if result.get("changed"):
            self.report["errors"] += 1
        if result.get("engine_error"):
            self.report["engine_errors"] += 1
        if kind not in ("clean", "cancelled"):
            self.report["records"].append(result)
        self.last = result.get("path", "")
        self.progress()


def index_files(state: ScanState, spool: Path) -> None:
    """Index without following symlinks; retain discovery errors in the report."""
    seen: set[str] = set()
    visited_dirs: set[str] = set()
    with spool.open("w", encoding="utf-8") as output:
        for target in state.report["targets"]:
            if state.stop.is_set():
                break
            pending = [(target, True)]
            while pending and not state.stop.is_set():
                path, explicit = pending.pop()
                if any(path == excluded or path.startswith(excluded.rstrip(os.sep) + os.sep)
                       for excluded in state.report["exclusions"]):
                    state.report["internal_paths_excluded"] += 1
                    continue
                if path in seen:
                    continue
                seen.add(path)
                try:
                    info = os.lstat(path)
                    if stat.S_ISLNK(info.st_mode):
                        if explicit:
                            state.record({"path": path, "status": "skipped", "message": "Explicit symlink target is not followed"})
                        else:
                            state.report["symlinks_ignored"] += 1
                    elif stat.S_ISREG(info.st_mode):
                        output.write(json.dumps(path, ensure_ascii=True) + "\n")
                        state.report["indexed"] += 1
                    elif stat.S_ISDIR(info.st_mode):
                        if path in visited_dirs:
                            continue
                        visited_dirs.add(path)
                        with os.scandir(path) as entries:
                            for entry in entries:
                                if state.stop.is_set():
                                    break
                                pending.append((entry.path, False))
                    elif explicit:
                        state.record({"path": path, "status": "skipped", "message": "Target is not a regular file or directory"})
                except OSError as error:
                    state.record({"path": path, "status": "error", "message": f"Discovery failed: {error}"})
                state.last = path
                state.progress()


def await_daemon(state: ScanState) -> bool:
    state.phase = "waiting"
    state.progress(force=True)
    deadline = time.monotonic() + state.args.ready_timeout
    while not state.stop.is_set() and time.monotonic() < deadline:
        daemon_pid = getattr(state.args, "daemon_pid", None)
        if daemon_pid:
            try:
                os.kill(daemon_pid, 0)
            except ProcessLookupError:
                state.record({"path": state.args.socket, "status": "error", "engine_error": True, "message": "Private ClamAV daemon exited before becoming ready; inspect the engine log"})
                return False
            except PermissionError:
                pass
        try:
            if ping(state.args.socket, state.stop, min(1.0, max(0.05, deadline - time.monotonic()))):
                commands = daemon_command(state.args.socket, b"VERSIONCOMMANDS", state.stop)
                if b"FILDES" not in commands.split():
                    state.record({"path": state.args.socket, "status": "error", "engine_error": True, "message": "ClamAV daemon does not advertise FILDES support"})
                    return False
                return True
        except Cancelled:
            return False
        except (OSError, ValueError):
            pass
        state.stop.wait(0.1)
    if not state.stop.is_set():
        state.record({"path": state.args.socket, "status": "error", "engine_error": True, "message": "ClamAV daemon did not become ready before the timeout"})
    return False


def scan_index(state: ScanState, spool: Path) -> None:
    state.phase = "scanning"
    state.progress(force=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=state.args.jobs) as pool:
        with spool.open(encoding="utf-8") as source:
            pending: set[concurrent.futures.Future] = set()
            exhausted = False
            while not state.stop.is_set():
                while not exhausted and len(pending) < state.args.jobs * 4:
                    line = source.readline()
                    if not line:
                        exhausted = True
                        break
                    path = json.loads(line)
                    pending.add(pool.submit(scan_file, path, state.args.socket,
                                            state.args.max_file_size, state.stop))
                if not pending:
                    break
                completed, pending = concurrent.futures.wait(
                    pending, timeout=0.1, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for future in completed:
                    state.record(future.result(), completed=True)
                state.progress()
            if state.stop.is_set():
                for future in pending:
                    future.cancel()
                for future in pending:
                    if not future.cancelled():
                        state.record(future.result(), completed=True)


def inspect_engine_log(state: ScanState) -> None:
    """An OK protocol reply cannot erase an internal engine failure on stderr."""
    engine_log = getattr(state.args, "engine_log", None)
    if not engine_log:
        return
    offset = getattr(state.args, "engine_log_offset", 0)
    max_bytes = 1024 * 1024
    try:
        with open(engine_log, "rb") as source:
            if os.fstat(source.fileno()).st_size < offset:
                raise ValueError("Engine log was truncated during scanning")
            source.seek(offset)
            new_data = source.read(max_bytes + 1)
        diagnostics = Counter(
            line.strip()
            for line in new_data[:max_bytes].decode("utf-8", errors="replace").splitlines()
            if "LibClamAV Error:" in line or "ERROR:" in line
        )
        for line, occurrences in list(diagnostics.items())[:20]:
            state.record({
                "path": engine_log,
                "status": "error",
                "engine_error": True,
                "message": f"Engine diagnostic ({occurrences} occurrence(s)): {safe_text(line[:4000])}",
            })
        if len(new_data) > max_bytes or len(diagnostics) > 20:
            state.record({
                "path": engine_log,
                "status": "error",
                "engine_error": True,
                "message": "Additional engine log diagnostics exceed the report limit; inspect the engine log",
            })
    except (OSError, ValueError) as error:
        state.record({"path": engine_log, "status": "error", "engine_error": True, "message": f"Cannot verify engine diagnostics: {error}"})


def finalize(state: ScanState, failed: bool = False) -> int:
    report = state.report
    report["duration"] = round(time.monotonic() - state.started, 3)
    if state.stop.is_set():
        outcome, code = "cancelled", 130
    elif failed:
        outcome, code = "failed", 2
    elif report["threats"]:
        outcome, code = "threats", 1
    elif report["errors"] or report["skipped"] or report["limits"] or (
        report["scanned"] != report["indexed"]
    ):
        outcome, code = "incomplete", 2
    else:
        outcome, code = "clean", 0
    report["outcome"] = outcome
    report["engine_healthy"] = report["engine_errors"] == 0 and outcome != "failed"
    report["coverage_complete"] = (
        not state.stop.is_set() and not failed and
        not (report["errors"] or report["skipped"] or report["limits"]) and
        report["scanned"] == report["indexed"]
    )
    state.phase = "finished"
    state.progress(force=True)
    lines = [f"AV {__version__} {report['started']}", "Targets: " + json.dumps(report["targets"], ensure_ascii=True)]
    for record in report["records"]:
        lines.append(f"{record['status'].upper()} {json.dumps(record['path'], ensure_ascii=True)}: {safe_text(record['message'])}")
    lines.append(
        "SUMMARY " + " ".join(
            f"{name}={report[key]}"
            for name, key in (("scanned", "scanned"), ("infected", "threats"),
                              ("errors", "errors"), ("skipped", "skipped"),
                              ("limits", "limits"), ("indexed", "indexed"))
        ) + f" outcome={outcome} duration={report['duration']}"
    )
    atomic_write(state.args.log, "\n".join(lines) + "\n")
    atomic_write_json(state.args.log + ".json", report)
    atomic_write_json(state.work / "result.json", report)
    atomic_write(state.work / "done", str(code) + "\n")
    return code


def run_scan(args: argparse.Namespace) -> int:
    state = ScanState(args)
    state.work.mkdir(parents=True, exist_ok=True, mode=0o700)
    old_handlers = {}
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            old_handlers[sig] = signal.signal(sig, lambda _sig, _frame: state.stop.set())
    failed = False
    try:
        state.progress(force=True)
        spool = state.work / "files.jsonl"
        index_files(state, spool)
        if not state.stop.is_set() and state.report["indexed"]:
            if await_daemon(state):
                scan_index(state, spool)
            elif not state.stop.is_set():
                failed = True
    except Exception as error:
        failed = True
        state.record({"path": "", "status": "error", "message": f"Scan worker failed: {type(error).__name__}: {error}"})
    try:
        inspect_engine_log(state)
        return finalize(state, failed)
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


def read_report(path: str) -> dict:
    with open(path, encoding="utf-8") as source:
        report = json.load(source)
    if not isinstance(report, dict) or not isinstance(report.get("records"), list):
        raise ValueError("Not an av scan report")
    return report


def print_summary(report_path: str) -> int:
    report = read_report(report_path)
    print("\t".join(str(report.get(key, 0)) for key in COUNTS) +
          f"\t{report.get('outcome', 'failed')}\t{report.get('duration', 0)}")
    return 0


def print_detections(report_path: str) -> int:
    report = read_report(report_path)
    for result in report["records"]:
        if result.get("status") == "threat":
            print(f"  • {safe_text(result['path'])} → {safe_text(result['message'])}")
    return 0


def restore_staged_file(staged: Path, original: str) -> str:
    """A hard link restores the pathname exclusively; it cannot clobber a save."""
    try:
        os.link(staged, original, follow_symlinks=False)
        staged.unlink()
        return "Original pathname restored without overwriting any file"
    except OSError as error:
        return f"File preserved at {staged}; original pathname was not overwritten ({error})"


def commit_staged_file(staged: Path, destination: Path, expected: dict) -> None:
    """Commit a verified, privately staged file without overwriting destinations."""
    descriptor = os.open(staged, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    target_created = False
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or identity_from_stat(info) != expected:
            raise ValueError("Staged file changed since scanning; refusing quarantine")
        if info.st_dev == destination.parent.stat().st_dev:
            os.link(staged, destination, follow_symlinks=False)
            target_created = True
        else:
            output_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            target_created = True
            with os.fdopen(output_fd, "wb") as output:
                with os.fdopen(os.dup(descriptor), "rb") as source:
                    shutil.copyfileobj(source, output)
                output.flush()
                os.fsync(output.fileno())
                if os.fstat(output.fileno()).st_size != info.st_size:
                    raise ValueError("Quarantine copy did not contain the complete staged file")
                os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode) & 0o777)
                os.utime(output.fileno(), ns=(info.st_atime_ns, info.st_mtime_ns))
        if identity_from_stat(os.fstat(descriptor)) != expected or (
            identity_from_stat(staged.lstat()) != expected
        ):
            raise ValueError("File changed during quarantine; preserving it for review")
        if info.st_dev == destination.parent.stat().st_dev and identity_from_stat(destination.lstat()) != expected:
            raise ValueError("Quarantine destination changed during commit")
        staged.unlink()
    except BaseException:
        if target_created:
            destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def quarantine_report(report_path: str, destination: str) -> int:
    report = read_report(report_path)
    threats = [record for record in report["records"] if record.get("status") == "threat"]
    if not threats:
        print("No detected files to quarantine.")
        return 0
    destination = os.path.abspath(os.path.expanduser(destination))
    os.makedirs(destination, mode=0o700, exist_ok=True)
    if stat.S_ISLNK(os.lstat(destination).st_mode):
        raise ValueError("Quarantine destination must not be a symlink")
    batch = tempfile.mkdtemp(prefix=time.strftime("%Y%m%d-%H%M%S-"), dir=destination)
    manifest = {"source_report": os.path.abspath(report_path), "files": []}
    failures = 0
    for number, record in enumerate(threats, 1):
        source = record["path"]
        entry = {"original": source, "signature": record["message"], "identity": record.get("identity")}
        manifest["files"].append(entry)
        holding = None
        staged = None
        committed = False
        interrupted = None
        try:
            info = os.lstat(source)
            if record.get("changed") or not stat.S_ISREG(info.st_mode) or identity_from_stat(info) != record.get("identity"):
                raise ValueError("File changed since scanning; scan it again before quarantine")
            target = Path(batch) / f"{number:06d}-{os.path.basename(source)}"
            holding = Path(tempfile.mkdtemp(prefix=".avclean-quarantine-", dir=Path(source).parent))
            staged = holding / "item"
            entry.update(destination=str(target), staged=str(staged), status="pending")
            # The journal is complete before any source pathname changes.
            atomic_write_json(Path(batch) / "manifest.json", manifest)
            os.rename(source, staged)
            staged_info = staged.lstat()
            if not stat.S_ISREG(staged_info.st_mode) or identity_from_stat(staged_info) != record["identity"]:
                raise ValueError("Source changed while staging; refusing to quarantine an unscanned replacement")
            commit_staged_file(staged, target, record["identity"])
            committed = True
            entry.update(status="moved")
            entry.pop("staged", None)
            print(f"Moved {safe_text(source)}")
        except (OSError, ValueError, KeyboardInterrupt) as error:
            failures += 1
            entry.update(status="error", error=str(error))
            if staged is not None and os.path.lexists(staged) and not committed:
                entry["recovery"] = restore_staged_file(staged, source)
                if not os.path.lexists(staged):
                    entry.pop("staged", None)
                print(f"Recovery: {safe_text(entry['recovery'])}", file=sys.stderr)
            print(f"Could not move {safe_text(source)}: {safe_text(error)}", file=sys.stderr)
            if isinstance(error, KeyboardInterrupt):
                interrupted = error
        finally:
            if holding is not None:
                try:
                    holding.rmdir()
                except OSError:
                    pass
        try:
            atomic_write_json(Path(batch) / "manifest.json", manifest)
        except OSError as error:
            failures += 1
            print(f"Could not update quarantine manifest; pending journal preserves recovery paths: {safe_text(error)}", file=sys.stderr)
        if interrupted is not None:
            raise interrupted
    print(f"Quarantine manifest: {safe_text(os.path.join(batch, 'manifest.json'))}")
    return 2 if failures else 0


def count_quarantine(destination: str) -> int:
    total = 0
    if os.path.islink(destination):
        print(0)
        return 0
    for current, directories, files in os.walk(destination, followlinks=False):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(current, name))]
        for name in files:
            path = os.path.join(current, name)
            if name != "manifest.json" and not os.path.islink(path) and os.path.isfile(path):
                total += 1
    print(total)
    return 0


def database_stamp(directory: str) -> int:
    digest = hashlib.sha256()
    with os.scandir(directory) as entries:
        records = []
        for entry in entries:
            if entry.name.startswith(".") or entry.name.endswith((".lock", ".tmp")):
                continue
            if entry.is_file(follow_symlinks=False):
                info = entry.stat(follow_symlinks=False)
                records.append((entry.name, info.st_size, info.st_mtime_ns))
    for record in sorted(records):
        digest.update(json.dumps(record, ensure_ascii=True).encode("ascii"))
    print(digest.hexdigest())
    return 0


SIGNATURE_SUFFIXES = (
    ".cvd", ".cld", ".cud", ".hdb", ".hsb", ".ndb", ".ldb", ".sdb",
    ".zmd", ".rmd", ".cbc", ".crb", ".db", ".ign", ".ign2", ".fp",
    ".sfp", ".wdb", ".pdb", ".gdb", ".idb", ".cdb", ".cat", ".yar", ".yara",
)
SELF_TEST_SIGNATURE = "Avclean.SelfTest.HarmlessFixture"


def database_ready(directory: str) -> int:
    try:
        database = Path(directory)
        if not stat.S_ISDIR(database.lstat().st_mode):
            return 2
        for entry in database.iterdir():
            if entry.name.lower().endswith(SIGNATURE_SUFFIXES) and stat.S_ISREG(entry.lstat().st_mode) and os.access(entry, os.R_OK):
                return 0
    except OSError:
        pass
    return 2


def config_path(raw: str | Path) -> str:
    """ClamAV consumes the whole unquoted remainder of a path directive."""
    path = os.path.abspath(os.path.expanduser(str(raw)))
    if any(unicodedata.category(character).startswith("C") for character in path):
        raise ValueError("Configuration paths must not contain control characters")
    return path


def private_directory(raw: str | Path) -> Path:
    path = Path(config_path(raw))
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError(f"Private directory must be an owned directory, not a symlink: {path}")
    path.chmod(0o700)
    return path


def private_file(path: Path) -> None:
    """Validate an existing private file without following symlinks."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError(f"Private file must be an owned regular file: {path}")
    path.chmod(0o600)


def create_private_file(path: Path, content: str) -> bool:
    """Publish a complete file exclusively; concurrent init never overwrites it."""
    temporary_fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(temporary_fd, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary_name, path, follow_symlinks=False)
            return True
        except FileExistsError:
            private_file(path)
            return False
    finally:
        os.unlink(temporary_name)


def seed_legacy_database(source: Path, destination: Path) -> int:
    """Optional migration copies ordinary CVD/CLD/CUD files, never symlinks."""
    copied = 0
    with os.scandir(source) as entries:
        names = sorted(entry.name for entry in entries if entry.is_file(follow_symlinks=False)
                       and entry.name.lower().endswith((".cvd", ".cld", ".cud", ".cvd.sign", ".cld.sign", ".cud.sign")))
    for name in names:
        original = source / name
        target = destination / name
        descriptor = os.open(original, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                continue
            try:
                output_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            try:
                with os.fdopen(output_fd, "wb") as output:
                    with os.fdopen(os.dup(descriptor), "rb") as input_file:
                        shutil.copyfileobj(input_file, output)
                if identity_from_stat(os.fstat(descriptor)) != identity_from_stat(info):
                    raise ValueError(f"Legacy database changed while copying: {original}")
                os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns), follow_symlinks=False)
                copied += 1
            except BaseException:
                target.unlink(missing_ok=True)
                raise
        finally:
            os.close(descriptor)
    return copied


def initialize_state(state_path: str, database_path: str | None = None,
                     legacy_database: str | None = None) -> int:
    state = private_directory(state_path)
    database = private_directory(database_path or state / "database")
    logs = private_directory(state / "logs")
    create_private_file(logs / "freshclam.log", "")
    configuration = (
        f"# Created by avclean {__version__}; existing user configuration is preserved.\n"
        f"DatabaseDirectory {config_path(database)}\n"
        "DatabaseMirror database.clamav.net\n"
        "ScriptedUpdates yes\n"
        f"UpdateLogFile {config_path(logs / 'freshclam.log')}\n"
        "LogTime yes\n"
        "LogFileMaxSize 5M\n"
        "LogRotate yes\n"
    )
    created = create_private_file(state / "freshclam.conf", configuration)
    copied = 0
    if legacy_database:
        copied = seed_legacy_database(Path(config_path(legacy_database)), database)
    print(f"State ready: {safe_text(state)}")
    print(f"Database: {safe_text(database)}")
    print(f"FreshClam configuration {'created' if created else 'preserved'}: {safe_text(state / 'freshclam.conf')}")
    if legacy_database:
        print(f"Migrated {copied} database file(s); existing files were preserved.")
    return 0


def executable_path(raw: str) -> str:
    path = shutil.which(raw) if os.sep not in raw else os.path.abspath(os.path.expanduser(raw))
    if not path or not os.path.isfile(path) or not os.access(path, os.X_OK):
        raise ValueError(f"Executable is missing or not executable: {raw}")
    return path


def executable_version(raw: str) -> tuple[str, str]:
    path = executable_path(raw)
    result = subprocess.run([path, "--version"], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, timeout=10, check=False)
    output = result.stdout.strip()
    if result.returncode != 0 or "ClamAV" not in output:
        raise ValueError(f"Version check failed for {path}: {safe_text(output[:1000])}")
    return path, output.splitlines()[0]


def descriptor_passing_available() -> None:
    """Exercise a real local SCM_RIGHTS round trip, without network access."""
    descriptors = array.array("i")
    with tempfile.TemporaryFile() as fixture:
        fixture.write(b"avclean descriptor probe")
        fixture.flush()
        fixture.seek(0)
        first, second = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with first, second:
            first.settimeout(2)
            second.settimeout(2)
            first.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                   array.array("i", [fixture.fileno()]))])
            _, messages, flags, _ = second.recvmsg(1, socket.CMSG_SPACE(descriptors.itemsize))
            try:
                for level, kind, payload in messages:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        descriptors.frombytes(payload[:len(payload) - len(payload) % descriptors.itemsize])
                if flags & getattr(socket, "MSG_CTRUNC", 0) or len(descriptors) != 1:
                    raise ValueError("SCM_RIGHTS descriptor transfer was incomplete")
                if os.read(descriptors[0], 64) != b"avclean descriptor probe":
                    raise ValueError("Transferred descriptor did not read the expected fixture")
            finally:
                for descriptor in descriptors:
                    os.close(descriptor)


def doctor(clamd: str, clamscan: str, freshclam: str, database_path: str) -> int:
    problems = 0
    print(f"avclean {__version__} diagnostics (offline)")
    if sys.platform == "darwin":
        print("[OK] Platform: macOS")
    else:
        print(f"[FAIL] Supported platform is macOS; current platform is {safe_text(sys.platform)}")
        problems += 1
    for name, path in (("clamd", clamd), ("clamscan", clamscan), ("freshclam", freshclam)):
        try:
            resolved, version = executable_version(path)
            print(f"[OK] {name}: {safe_text(version)} ({safe_text(resolved)})")
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print(f"[FAIL] {name}: {safe_text(error)}")
            problems += 1
    try:
        descriptor_passing_available()
        print("[OK] Local UNIX descriptor passing (FILDES transport)")
    except (OSError, ValueError, AttributeError) as error:
        print(f"[FAIL] Descriptor passing: {safe_text(error)}")
        problems += 1
    try:
        database = Path(config_path(database_path))
        info = database.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Database path must be a directory, not a symlink")
        if not os.access(database, os.R_OK | os.W_OK | os.X_OK):
            raise ValueError("Database directory must be readable and writable by this user")
        if info.st_uid != os.getuid() or info.st_mode & 0o022:
            raise ValueError("Database directory must be owned by this user and not writable by other users")
        print(f"[OK] Database directory permissions: {safe_text(database)}")
        candidates = [entry for entry in database.iterdir()
                      if entry.name.lower().endswith(SIGNATURE_SUFFIXES)
                      and stat.S_ISREG(entry.lstat().st_mode)]
        if not candidates:
            raise ValueError("No signature database is installed; run av --update")
        for entry in candidates:
            if not os.access(entry, os.R_OK):
                raise ValueError(f"Database file is not readable: {entry.name}")
        daily = [entry for entry in candidates if entry.name.lower() in ("daily.cvd", "daily.cld", "daily.cud")]
        newest = max(entry.stat().st_mtime for entry in (daily or candidates))
        age = max(0, time.time() - newest)
        size = sum(entry.stat().st_size for entry in candidates)
        if age > 7 * 86400:
            raise ValueError(f"Database files are {age / 86400:.1f} days old; run av --update")
        print(f"[OK] Signature files: {len(candidates)}, {size / (1024 * 1024):.1f} MiB; age {age / 3600:.1f} hours")
    except (OSError, ValueError) as error:
        print(f"[FAIL] Database: {safe_text(error)}")
        problems += 1
    print("Run av --self-test to verify actual clean/detection responses with a harmless local fixture.")
    return 2 if problems else 0


def stop_owned_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def run_owned_program(command: list[str], stop: threading.Event,
                      timeout: float = 15.0) -> tuple[int, str]:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, errors="replace")
    deadline = time.monotonic() + timeout
    try:
        while not stop.is_set() and time.monotonic() < deadline:
            try:
                output, _ = process.communicate(timeout=0.1)
                return process.returncode, output
            except subprocess.TimeoutExpired:
                pass
        if stop.is_set():
            raise Cancelled()
        raise TimeoutError(f"Timed out running {command[0]}")
    finally:
        stop_owned_process(process)


def self_test(clamd: str, clamscan: str, freshclam: str | None = None) -> int:
    """Verify signature matching offline using only our own short-lived daemon."""
    stop = threading.Event()
    previous_handlers = {}
    process = None
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous_handlers[sig] = signal.signal(sig, lambda _sig, _frame: stop.set())
    try:
        binaries = {}
        for name, raw in (("clamd", clamd), ("clamscan", clamscan), ("freshclam", freshclam)):
            if raw:
                resolved = executable_path(raw)
                version_code, version_output = run_owned_program([resolved, "--version"], stop, timeout=10)
                if version_code != 0 or "ClamAV" not in version_output:
                    raise ValueError(f"Version check failed for {resolved}: {safe_text(version_output[:1000])}")
                version = version_output.strip().splitlines()[0]
                binaries[name] = resolved
                print(f"{name}: {safe_text(version)}")
        descriptor_passing_available()
        temporary_parent = config_path(os.environ.get("AV_SELF_TEST_TMPDIR", "/tmp"))
        with tempfile.TemporaryDirectory(prefix="a.", dir=temporary_parent) as temporary:
            root = Path(temporary)
            socket_path = root / "s"
            if len(os.fsencode(socket_path)) > 103:
                raise ValueError("Self-test socket path is too long; set AV_SELF_TEST_TMPDIR to a shorter writable directory")
            database = root / "database"
            database.mkdir(mode=0o700)
            payload = b"avclean harmless offline signature-matching self-test fixture.\n"
            fixture = root / "harmless-fixture.txt"
            fixture.write_bytes(payload)
            clean = root / "clean.txt"
            clean.write_text("Ordinary clean avclean self-test input.\n", encoding="utf-8")
            signature = f"{hashlib.md5(payload).hexdigest()}:{len(payload)}:{SELF_TEST_SIGNATURE}\n"
            (database / "self-test.hdb").write_text(signature, encoding="ascii")
            for path, expected in ((fixture, 1), (clean, 0)):
                result, output = run_owned_program(
                    [binaries["clamscan"], f"--database={database}", "--no-summary", "--stdout", str(path)], stop)
                if result != expected or (expected == 1 and SELF_TEST_SIGNATURE not in output):
                    raise ValueError(f"clamscan self-test failed ({path.name}, exit {result}): {safe_text(output[:2000])}")
                if "LibClamAV Error:" in output or "ERROR:" in output:
                    raise ValueError(f"clamscan reported an internal failure: {safe_text(output[:2000])}")
            configuration = root / "clamd.conf"
            configuration.write_text(
                f"Foreground yes\nLocalSocket {socket_path}\nLocalSocketMode 600\n"
                f"DatabaseDirectory {database}\nTemporaryDirectory {root}\n"
                "MaxThreads 2\nMaxQueue 8\nMaxFileSize 20M\nMaxScanSize 40M\n"
                "MaxScanTime 10000\nAlertExceedsMax yes\nConcurrentDatabaseReload no\n"
                "SelfCheck 0\nExitOnOOM yes\n", encoding="utf-8")
            log_path = root / "clamd.log"
            with log_path.open("w", encoding="utf-8") as engine_log:
                process = subprocess.Popen([binaries["clamd"], f"--config-file={configuration}"],
                                           stdout=engine_log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 15
                ready = False
                while not stop.is_set() and time.monotonic() < deadline:
                    if process.poll() is not None:
                        diagnostics = log_path.read_text(encoding="utf-8", errors="replace")
                        raise ValueError(f"Private self-test daemon exited before becoming ready: {safe_text(diagnostics[-4000:])}")
                    try:
                        if ping(str(socket_path), stop, 0.5):
                            commands = daemon_command(str(socket_path), b"VERSIONCOMMANDS", stop)
                            if b"FILDES" not in commands.split():
                                raise ValueError("Private self-test daemon does not support FILDES")
                            ready = True
                            break
                    except (OSError, ValueError):
                        pass
                    stop.wait(0.05)
                if stop.is_set():
                    raise Cancelled()
                if not ready:
                    raise ValueError("Private self-test daemon did not become ready within 15 seconds")
                detection = scan_file(str(fixture), str(socket_path), MAX_FILE_SIZE, stop, timeout=15)
                clean_result = scan_file(str(clean), str(socket_path), MAX_FILE_SIZE, stop, timeout=15)
                if stop.is_set():
                    raise Cancelled()
                if detection["status"] != "threat" or not detection["message"].startswith(SELF_TEST_SIGNATURE):
                    raise ValueError(f"FILDES signature detection failed: {safe_text(detection)}")
                if clean_result["status"] != "clean":
                    raise ValueError(f"FILDES clean-file check failed: {safe_text(clean_result)}")
                stop_owned_process(process)
                process = None
            diagnostics = log_path.read_text(encoding="utf-8", errors="replace")
            if "LibClamAV Error:" in diagnostics or "ERROR:" in diagnostics:
                raise ValueError(f"Private daemon reported an internal failure: {safe_text(diagnostics[-4000:])}")
            print("[OK] Offline self-test: harmless signature detected; clean file accepted by clamscan and FILDES.")
            return 0
    except Cancelled:
        print("[CANCELLED] Offline self-test cancelled.", file=sys.stderr)
        return 130
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"[FAIL] Offline self-test: {safe_text(error)}", file=sys.stderr)
        return 2
    finally:
        if process is not None:
            stop_owned_process(process)
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)


def positive_integer(raw: str) -> int:
    value = int(raw)
    if value < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return value


def nonnegative_integer(raw: str) -> int:
    value = int(raw)
    if value < 0:
        raise argparse.ArgumentTypeError("must be a nonnegative integer")
    return value


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--version", action="version", version=__version__)
    commands = root.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--socket", required=True)
    scan.add_argument("--work", required=True)
    scan.add_argument("--log", required=True)
    scan.add_argument("--jobs", type=positive_integer, default=4)
    scan.add_argument("--ready-timeout", type=float, default=240.0)
    scan.add_argument("--max-file-size", type=positive_integer, default=MAX_FILE_SIZE)
    scan.add_argument("--engine-log")
    scan.add_argument("--engine-log-offset", type=nonnegative_integer, default=0)
    scan.add_argument("--daemon-pid", type=positive_integer)
    scan.add_argument("--exclude-path", action="append", default=[])
    scan.add_argument("targets", nargs="+")
    for name in ("summary", "status", "detections", "engine-health"):
        commands.add_parser(name).add_argument("report")
    quarantine = commands.add_parser("quarantine")
    quarantine.add_argument("--report", required=True)
    quarantine.add_argument("--dest", required=True)
    count = commands.add_parser("count-quarantine")
    count.add_argument("--dest", required=True)
    stamp = commands.add_parser("db-stamp")
    stamp.add_argument("--database", required=True)
    commands.add_parser("database-ready").add_argument("--database", required=True)
    initialize = commands.add_parser("init")
    initialize.add_argument("--state", required=True)
    initialize.add_argument("--database")
    initialize.add_argument("--legacy-db")
    diagnostics = commands.add_parser("doctor")
    diagnostics.add_argument("--clamd", required=True)
    diagnostics.add_argument("--clamscan", required=True)
    diagnostics.add_argument("--freshclam", required=True)
    diagnostics.add_argument("--database", required=True)
    test = commands.add_parser("self-test")
    test.add_argument("--clamd", required=True)
    test.add_argument("--clamscan", required=True)
    test.add_argument("--freshclam")
    return root


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    if args.command == "scan":
        if args.jobs > 64:
            parser().error("--jobs must be between 1 and 64")
        if args.ready_timeout <= 0:
            parser().error("--ready-timeout must be positive")
        return run_scan(args)
    try:
        if args.command in ("summary", "status"):
            return print_summary(args.report)
        if args.command == "detections":
            return print_detections(args.report)
        if args.command == "engine-health":
            report = read_report(args.report)
            return 0 if report.get("engine_healthy", False) else 2
        if args.command == "quarantine":
            return quarantine_report(args.report, args.dest)
        if args.command == "count-quarantine":
            return count_quarantine(args.dest)
        if args.command == "db-stamp":
            return database_stamp(args.database)
        if args.command == "database-ready":
            return database_ready(args.database)
        if args.command == "init":
            return initialize_state(args.state, args.database, args.legacy_db)
        if args.command == "doctor":
            return doctor(args.clamd, args.clamscan, args.freshclam, args.database)
        if args.command == "self-test":
            return self_test(args.clamd, args.clamscan, args.freshclam)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"av: {safe_text(error)}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("av: cancelled", file=sys.stderr)
        return 130
    return 2


if __name__ == "__main__":
    sys.exit(main())

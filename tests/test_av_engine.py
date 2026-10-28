"""Regression coverage for av's isolated scanner helper.

All files, reports, and UNIX sockets are temporary; no installed clamd is used.
"""
from __future__ import annotations

import argparse
import array
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import stat
import types
import tempfile
import threading
import time
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
ENGINE_SOURCE = REPO_ROOT / "lib" / "av_engine.py"
MENU_SOURCE = REPO_ROOT / "bin" / "av"


class FakeClamd:
    """Tiny local FILDES daemon, sufficient to exercise the real socket client."""

    def __init__(self, socket_path, response=b"stream: OK\0", delay=0):
        self.socket_path = str(socket_path)
        self.response = response
        self.delay = delay
        self.received = []
        self.errors = []
        self._stop = threading.Event()
        self._threads = []
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(32)
        self._server.settimeout(0.05)
        self._acceptor = threading.Thread(target=self._accept, daemon=True)

    def __enter__(self):
        self._acceptor.start()
        return self

    def _accept(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            self._threads.append(thread)
            thread.start()

    def _handle(self, conn):
        fd = None
        try:
            with conn:
                conn.settimeout(1)
                command = bytearray()
                while not command.endswith(b"\0"):
                    data = conn.recv(1)
                    if not data:
                        return
                    command.extend(data)
                if command == b"zPING\0":
                    conn.sendall(b"PONG\0")
                    return
                if command == b"zVERSIONCOMMANDS\0":
                    conn.sendall(b"ClamAV 1.5.4/28158/test| COMMANDS: SCAN PING VERSIONCOMMANDS FILDES VERSION END IDSESSION INSTREAM\0")
                    return
                if command != b"zFILDES\0":
                    self.errors.append(f"unexpected command: {command!r}")
                    return
                _, ancillary, _, _ = conn.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize))
                for level, kind, payload in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        values = array.array("i")
                        values.frombytes(payload[: len(payload) // values.itemsize * values.itemsize])
                        fd = values[0]
                        for extra in values[1:]:
                            os.close(extra)
                if fd is None:
                    self.errors.append("FILDES request omitted descriptor")
                    return
                content = os.read(fd, 65536)
                self.received.append(content)
                if self.delay:
                    self._stop.wait(self.delay)
                response = self.response(content) if callable(self.response) else self.response
                if response:
                    with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                        conn.sendall(response)
        except Exception as exc:
            self.errors.append(repr(exc))
        finally:
            if fd is not None:
                os.close(fd)

    def __exit__(self, *_):
        self._stop.set()
        self._server.close()
        self._acceptor.join(2)
        for thread in self._threads:
            thread.join(2)


def load_engine():
    spec = importlib.util.spec_from_file_location("av_engine_under_test", ENGINE_SOURCE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

class EngineRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = load_engine()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avtest-", dir="/tmp")
        self.root = Path(self.temp.name)
        self.stop = threading.Event()

    def tearDown(self):
        self.temp.cleanup()

    def file(self, name="fixture.txt", contents=b"safe text"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        return path

    def scan(self, path, response=b"stream: OK\0", max_size=1024, delay=0, timeout=1):
        with FakeClamd(self.root / "clamd.sock", response=response, delay=delay) as daemon:
            result = self.engine.scan_file(str(path), daemon.socket_path, max_size, self.stop, timeout=timeout)
        self.assertEqual(daemon.errors, [])
        return result, daemon

    def test_clean_file_reaches_real_fildes_socket(self):
        path = self.file(contents=b"entire fixture payload")
        record, daemon = self.scan(path)
        self.assertEqual(record["status"], "clean")
        self.assertEqual(daemon.received, [b"entire fixture payload"])

    def test_newline_and_unicode_filename_remain_one_file(self):
        path = self.file("folder/first\nsecond-ไทย.txt", b"whole filename")
        record, daemon = self.scan(path)
        self.assertEqual(record["status"], "clean")
        self.assertEqual(record["path"], str(path))
        self.assertEqual(daemon.received, [b"whole filename"])

    def test_detection_is_a_threat(self):
        record, _ = self.scan(self.file(), b"fd[7]: Test.Signature FOUND\0")
        self.assertEqual(record["status"], "threat")
        self.assertIn("Test.Signature", record["message"])

    def test_engine_limit_is_not_classified_as_malware(self):
        for signature in (
            "Heuristics.Limits.Exceeded.MaxFileSize",
            "Heuristics.Limits.Exceeded.MaxScanSize",
            "Heuristics.Limits.Exceeded.MaxRecursion",
            "Heuristics.Limits.Exceeded.MaxFiles",
        ):
            with self.subTest(signature=signature):
                status, _ = self.engine.classify_reply(f"fd[7]: {signature} FOUND".encode())
                self.assertEqual(status, "limit")

    def test_read_error_is_not_clean(self):
        missing = self.root / "does-not-exist"
        record = self.engine.scan_file(str(missing), str(self.root / "unused.sock"), 1024, self.stop, timeout=.05)
        self.assertEqual(record["status"], "error")

    def test_error_from_daemon_is_not_clean(self):
        record, _ = self.scan(self.file(), b"fd[7]: Access denied ERROR\0")
        self.assertEqual(record["status"], "error")
        self.assertIn("Access denied", record["message"])
        self.assertFalse(record.get("engine_error", False))

    def test_file_larger_than_limit_is_reported_without_claiming_scan(self):
        path = self.file(contents=b"12345")
        record = self.engine.scan_file(str(path), str(self.root / "unused.sock"), 4, self.stop, timeout=.05)
        self.assertIn(record["status"], {"limit", "skipped"})
        self.assertFalse(record.get("scanned", False))

    @unittest.skipUnless(getattr(stat, "SF_DATALESS", 0), "macOS dataless flag unavailable")
    def test_cloud_placeholder_is_not_opened_or_hydrated(self):
        info = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_flags=stat.SF_DATALESS, st_size=1)
        with mock.patch.object(self.engine.os, "lstat", return_value=info), mock.patch.object(
            self.engine.os, "open"
        ) as open_file:
            record = self.engine.scan_file(str(self.root / "cloud.txt"), "unused", 1024, self.stop)
        self.assertEqual(record["status"], "skipped")
        self.assertFalse(record.get("scanned", False))
        open_file.assert_not_called()

    def test_malformed_daemon_reply_is_not_clean(self):
        for reply in (b"unexpected reply\0", b"", b"stream: OK-without-terminator"):
            with self.subTest(reply=reply):
                socket_path = self.root / "clamd.sock"
                socket_path.unlink(missing_ok=True)
                record, _ = self.scan(self.file(), reply)
                self.assertEqual(record["status"], "error")
                self.assertTrue(record.get("engine_error", False))

    def test_timeout_is_bounded_and_reported(self):
        start = time.monotonic()
        record, _ = self.scan(self.file(), delay=.3, timeout=.04)
        self.assertEqual(record["status"], "error")
        self.assertLess(time.monotonic() - start, 1)
        self.assertTrue(record.get("engine_error", False))

    def test_preexisting_cancel_prevents_new_scan(self):
        self.stop.set()
        record = self.engine.scan_file(str(self.file()), str(self.root / "unused.sock"), 1024, self.stop, timeout=.05)
        self.assertIn(record["status"], {"cancelled", "skipped"})

    def threat_report(self, paths):
        records = []
        for path in paths:
            records.append({
                "path": str(path),
                "status": "threat",
                "message": "Test.Signature",
                "identity": self.engine.identity_from_stat(path.stat()),
            })
        report = self.root / "report.json"
        report.write_text(json.dumps({"records": records}), encoding="utf-8")
        return report

    def quarantine(self, report):
        import io
        output = io.StringIO()
        destination = self.root / "quarantine"
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = self.engine.quarantine_report(str(report), str(destination))
        return result, destination, output.getvalue()

    def test_quarantine_same_basename_never_overwrites(self):
        one = self.file("one/same.txt", b"first content")
        two = self.file("two/same.txt", b"second content")
        report = self.threat_report([one, two])
        result, destination, output = self.quarantine(report)
        payloads = [p.read_bytes() for p in destination.rglob("*") if p.is_file()]
        self.assertEqual(result, 0, output)
        self.assertEqual(payloads.count(b"first content"), 1)
        self.assertEqual(payloads.count(b"second content"), 1)
        self.assertFalse(one.exists())
        self.assertFalse(two.exists())

    def test_changed_file_is_refused_by_quarantine(self):
        path = self.file(contents=b"original")
        report = self.threat_report([path])
        path.write_bytes(b"new and different content")
        _, destination, _ = self.quarantine(report)
        self.assertEqual(path.read_bytes(), b"new and different content")
        self.assertNotIn(b"new and different content", [p.read_bytes() for p in destination.rglob("*") if p.is_file()])

    def test_replaced_symlink_is_refused_by_quarantine(self):
        path = self.file("original.txt", b"original")
        victim = self.file("unrelated.txt", b"keep me")
        report = self.threat_report([path])
        path.unlink()
        path.symlink_to(victim)
        _, destination, _ = self.quarantine(report)
        self.assertTrue(path.is_symlink())
        self.assertEqual(victim.read_bytes(), b"keep me")
        self.assertNotIn(b"keep me", [p.read_bytes() for p in destination.rglob("*") if p.is_file()])

    def test_quarantine_swap_at_atomic_stage_boundary_is_refused_and_restored(self):
        source = self.file("source.txt", b"original scanned content")
        report = self.threat_report([source])
        original_saved = self.root / "original-preserved.txt"
        real_rename = os.rename
        triggered = []

        def swap_then_rename(old, new, *args, **kwargs):
            if Path(old) == source and not triggered:
                triggered.append(True)
                real_rename(source, original_saved)
                source.write_bytes(b"replacement at move boundary")
            return real_rename(old, new, *args, **kwargs)

        with mock.patch.object(self.engine.os, "rename", side_effect=swap_then_rename):
            code, destination, output = self.quarantine(report)
        self.assertTrue(triggered, "Test did not reach the atomic source staging boundary")
        self.assertEqual(code, 2, output)
        self.assertEqual(source.read_bytes(), b"replacement at move boundary")
        self.assertEqual(original_saved.read_bytes(), b"original scanned content")
        self.assertNotIn(b"replacement at move boundary", [path.read_bytes() for path in destination.rglob("*") if path.is_file()])

    def test_quarantine_failed_rollback_preserves_recreated_source_and_staged_file(self):
        source = self.file("source.txt", b"original scanned content")
        report = self.threat_report([source])
        original_saved = self.root / "original-preserved.txt"
        real_rename = os.rename
        triggered = []

        def swap_stage_and_recreate(old, new, *args, **kwargs):
            if Path(old) == source and not triggered:
                triggered.append(True)
                real_rename(source, original_saved)
                source.write_bytes(b"replacement retained in holding")
                result = real_rename(old, new, *args, **kwargs)
                source.write_bytes(b"newly recreated source must survive")
                return result
            return real_rename(old, new, *args, **kwargs)

        with mock.patch.object(self.engine.os, "rename", side_effect=swap_stage_and_recreate):
            code, _destination, output = self.quarantine(report)
        self.assertTrue(triggered, "Test did not reach the atomic source staging boundary")
        self.assertEqual(code, 2, output)
        self.assertEqual(source.read_bytes(), b"newly recreated source must survive")
        self.assertEqual(original_saved.read_bytes(), b"original scanned content")
        payloads = [path.read_bytes() for path in self.root.rglob("*") if path.is_file()]
        self.assertEqual(payloads.count(b"replacement retained in holding"), 1)
        self.assertEqual(payloads.count(b"newly recreated source must survive"), 1)
        self.assertEqual(payloads.count(b"original scanned content"), 1)

    def test_file_changed_during_scan_is_not_clean(self):
        path = self.file(contents=b"original content")

        def mutate_then_reply(_content):
            path.write_bytes(b"changed after opening")
            return b"stream: OK\0"

        record, _ = self.scan(path, response=mutate_then_reply)
        self.assertEqual(record["status"], "error")
        self.assertFalse(record["scanned"])
        self.assertIn("changed", record["message"].lower())

    def test_file_changed_during_detection_retains_threat_and_error(self):
        path = self.file(contents=b"original content")

        def mutate_then_reply(_content):
            path.write_bytes(b"different content now")
            return b"stream: Test.Signature FOUND\0"

        record, _ = self.scan(path, response=mutate_then_reply)
        self.assertEqual(record["status"], "threat")
        self.assertTrue(record["changed"])
        self.assertFalse(record["scanned"])
        args = self.args([path])
        Path(args.work).mkdir()
        state = self.engine.ScanState(args)
        state.record(record, completed=True)
        self.assertEqual(state.report["threats"], 1)
        self.assertEqual(state.report["errors"], 1)

    def test_terminal_control_characters_are_escaped_in_user_visible_paths(self):
        dangerous = "folder/\x1b]52;c;clipboard\x07\nnew\rreturn\ttab\u202e.txt"
        displayed = self.engine.safe_text(dangerous)
        self.assertNotIn("\x1b", displayed)
        self.assertNotIn("\x07", displayed)
        self.assertNotIn("\n", displayed)
        self.assertNotIn("\r", displayed)
        self.assertNotIn("\t", displayed)
        self.assertNotIn("\u202e", displayed)
        self.assertIn("folder/", displayed)
        self.assertIn("clipboard", displayed)

    def test_simultaneous_quarantines_preserve_same_basename_in_separate_batches(self):
        first = self.file("parallel-one/same.txt", b"parallel first")
        second = self.file("parallel-two/same.txt", b"parallel second")
        first_report = self.threat_report([first])
        saved_report = self.root / "first-report.json"
        first_report.rename(saved_report)
        second_report = self.threat_report([second])
        destination = self.root / "quarantine"
        processes = [
            subprocess.Popen(
                [sys.executable, str(ENGINE_SOURCE), "quarantine", "--report", str(report), "--dest", str(destination)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            for report in (saved_report, second_report)
        ]
        try:
            for process in processes:
                output, error = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, (output, error))
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        payloads = [path.read_bytes() for path in destination.rglob("*") if path.is_file()]
        self.assertEqual(payloads.count(b"parallel first"), 1)
        self.assertEqual(payloads.count(b"parallel second"), 1)
        self.assertEqual(len(list(destination.glob("*/manifest.json"))), 2)
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())

    def args(self, targets, jobs=2):
        return argparse.Namespace(
            socket=str(self.root / "clamd.sock"),
            work=str(self.root / "work"),
            log=str(self.root / "scan.log"),
            jobs=jobs,
            ready_timeout=.5,
            max_file_size=1024,
            targets=[str(path) for path in targets],
        )

    def run_report(self, args, response=b"stream: OK\0"):
        with FakeClamd(args.socket, response=response) as daemon:
            result = self.engine.run_scan(args)
        report = json.loads(Path(args.log + ".json").read_text())
        self.assertEqual(daemon.errors, [])
        return result, report, daemon

    def test_run_scan_error_cannot_be_clean(self):
        args = self.args([self.file()])
        code, report, _ = self.run_report(args, response=b"stream: unreadable ERROR\0")
        self.assertEqual(code, 2)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertEqual(report["errors"], 1)
        self.assertTrue(report["engine_healthy"])
        self.assertEqual(report["engine_errors"], 0)
        self.assertEqual(report["scanned"], 0)
        self.assertTrue(any("unreadable" in item["message"] for item in report["records"]))

    def test_malformed_scan_protocol_invalidates_engine_health(self):
        code, report, _ = self.run_report(self.args([self.file()]), response=b"unexpected protocol data\0")
        self.assertEqual(code, 2)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertFalse(report["engine_healthy"])
        self.assertGreater(report["engine_errors"], 0)

    def test_discovery_permission_error_survives_in_report(self):
        directory = self.root / "blocked"
        directory.mkdir()
        args = self.args([directory])
        with mock.patch.object(self.engine.os, "scandir", side_effect=PermissionError("fixture denied")):
            code = self.engine.run_scan(args)
        report = json.loads(Path(args.log + ".json").read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertEqual(report["errors"], 1)
        self.assertIn("fixture denied", report["records"][0]["message"])

    def test_relative_leading_dash_and_newline_targets_are_detected(self):
        path = self.file("-relative\nไทย.txt", b"detected content")
        args = self.args([path.name])
        previous = os.getcwd()
        try:
            os.chdir(self.root)
            code, report, daemon = self.run_report(args, response=b"stream: Test.Signature FOUND\0")
        finally:
            os.chdir(previous)
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "threats")
        self.assertEqual(report["threats"], 1)
        self.assertEqual(report["scanned"], 1)
        self.assertEqual(report["records"][0]["path"], str(path.resolve()))
        self.assertEqual(daemon.received, [b"detected content"])

    def test_size_limit_prevents_clean_report(self):
        args = self.args([self.file(contents=b"12345")])
        args.max_file_size = 4
        code, report, _ = self.run_report(args)
        self.assertEqual(code, 2)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertEqual(report["scanned"], 0)
        self.assertEqual(report["skipped"] + report["limits"], 1)

    def test_empty_directory_needs_no_daemon_and_reports_zero_files(self):
        directory = self.root / "empty"
        directory.mkdir()
        args = self.args([directory])
        code = self.engine.run_scan(args)
        report = json.loads(Path(args.log + ".json").read_text())
        self.assertEqual(code, 0)
        self.assertEqual(report["indexed"], 0)
        self.assertEqual(report["scanned"], 0)
        self.assertEqual(report["errors"], 0)

    def test_explicit_symlink_is_reported_as_unscanned(self):
        path = self.file()
        link = self.root / "link.txt"
        link.symlink_to(path)
        args = self.args([link])
        code = self.engine.run_scan(args)
        report = json.loads(Path(args.log + ".json").read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertEqual(report["skipped"], 1)
        self.assertEqual(report["scanned"], 0)

    def test_daemon_unavailable_writes_failure_report(self):
        args = self.args([self.file()])
        args.ready_timeout = .05
        code = self.engine.run_scan(args)
        report = json.loads(Path(args.log + ".json").read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["outcome"], "failed")
        self.assertGreater(report["errors"], 0)
        self.assertEqual(Path(args.work, "done").read_text().strip(), "2")

    def test_cancellation_writes_partial_report_and_keeps_detection(self):
        paths = [self.file(f"cancel/{number}.txt") for number in range(64)]
        args = self.args(paths, jobs=1)
        original_scan_file = self.engine.scan_file
        completed = []

        def scan_then_stop(path, socket_path, max_size, stop, *other, **kwargs):
            record = original_scan_file(path, socket_path, max_size, stop, *other, **kwargs)
            if record["status"] == "threat":
                completed.append(path)
                stop.set()
            return record

        with mock.patch.object(self.engine, "scan_file", side_effect=scan_then_stop):
            code, report, _ = self.run_report(args, response=b"stream: Test.Signature FOUND\0")
        self.assertEqual(code, 130)
        self.assertEqual(report["outcome"], "cancelled")
        self.assertEqual(report["threats"], 1)
        self.assertEqual(len(completed), 1)
        self.assertLess(report["completed"], report["indexed"])
        self.assertEqual(Path(args.work, "done").read_text().strip(), "130")
        self.assertTrue(any(record["status"] == "threat" for record in report["records"]))

    def test_clean_reply_with_daemon_error_is_incomplete(self):
        args = self.args([self.file()])
        engine_log = self.root / "engine.log"
        engine_log.write_text("LibClamAV Error: signature database could not be loaded\n")
        args.engine_log = str(engine_log)
        args.engine_log_offset = 0
        code, report, _ = self.run_report(args)
        self.assertEqual(code, 2)
        self.assertEqual(report["outcome"], "incomplete")
        self.assertEqual(report["scanned"], 1)
        self.assertGreater(report["errors"], 0)
        self.assertFalse(report["coverage_complete"])
        self.assertFalse(report["engine_healthy"])
        self.assertGreater(report["engine_errors"], 0)
        health = subprocess.run([sys.executable, str(ENGINE_SOURCE), "engine-health", args.log + ".json"], capture_output=True)
        self.assertEqual(health.returncode, 2)
        self.assertEqual(health.stdout, b"")
        self.assertTrue(any("signature database" in record["message"] for record in report["records"]))

    def test_old_engine_errors_before_scan_offset_are_ignored(self):
        args = self.args([self.file()])
        engine_log = self.root / "engine.log"
        engine_log.write_text("LibClamAV Error: previous scan failure\n")
        args.engine_log = str(engine_log)
        args.engine_log_offset = engine_log.stat().st_size
        code, report, _ = self.run_report(args)
        self.assertEqual(code, 0)
        self.assertEqual(report["outcome"], "clean")
        self.assertEqual(report["errors"], 0)
        self.assertTrue(report["coverage_complete"])
        self.assertTrue(report["engine_healthy"])
        self.assertEqual(report["engine_errors"], 0)
        health = subprocess.run([sys.executable, str(ENGINE_SOURCE), "engine-health", args.log + ".json"], capture_output=True)
        self.assertEqual(health.returncode, 0)

    def test_new_daemon_error_after_offset_survives_clean_reply(self):
        args = self.args([self.file()])
        engine_log = self.root / "engine.log"
        engine_log.write_text("LibClamAV Error: previous scan failure\n")
        args.engine_log = str(engine_log)
        args.engine_log_offset = engine_log.stat().st_size

        def clean_with_error(_content):
            with engine_log.open("a") as output:
                output.write("LibClamAV Error: current scan failed hash verification\n")
            return b"stream: OK\0"

        code, report, _ = self.run_report(args, response=clean_with_error)
        self.assertEqual(code, 2)
        self.assertEqual(report["outcome"], "incomplete")
        messages = "\n".join(record["message"] for record in report["records"])
        self.assertIn("current scan failed hash verification", messages)
        self.assertNotIn("previous scan failure", messages)

    def test_truncated_engine_log_is_not_silently_clean(self):
        args = self.args([self.file()])
        engine_log = self.root / "engine.log"
        engine_log.write_text("short\n")
        args.engine_log = str(engine_log)
        args.engine_log_offset = 99
        code, report, _ = self.run_report(args)
        self.assertEqual(code, 2)
        self.assertFalse(report["coverage_complete"])
        self.assertGreater(report["errors"], 0)

    def test_dead_owned_daemon_fails_without_full_ready_timeout(self):
        args = self.args([self.file()])
        args.daemon_pid = 12345
        args.ready_timeout = 240
        started = time.monotonic()
        with mock.patch.object(self.engine.os, "kill", side_effect=ProcessLookupError):
            code, report, _ = self.run_report(args)
        self.assertEqual(code, 2)
        self.assertEqual(report["outcome"], "failed")
        self.assertLess(time.monotonic() - started, 1)
        self.assertGreater(report["errors"], 0)

    def test_real_subprocess_sigint_preserves_cancelled_report(self):
        args = self.args([self.file()])
        command = [
            sys.executable, str(ENGINE_SOURCE), "scan", "--socket", args.socket,
            "--work", args.work, "--log", args.log, "--jobs", "1", "--ready-timeout", "1",
            "--max-file-size", "1024", "--", *args.targets,
        ]
        with FakeClamd(args.socket, delay=60) as daemon:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 3
                while not daemon.received and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.005)
                self.assertTrue(daemon.received, "worker never started the FILDES scan")
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(process.returncode, 130, (stdout, stderr))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        report = json.loads(Path(args.log + ".json").read_text())
        self.assertEqual(report["outcome"], "cancelled")
        self.assertFalse(report["coverage_complete"])
        self.assertEqual(Path(args.work, "done").read_text().strip(), "130")

    def test_excluded_subtree_does_not_exclude_shared_prefix_sibling(self):
        self.file("private/skip.txt", b"excluded subtree")
        self.file("private-other/keep.txt", b"retained sibling")
        self.file("exact", b"excluded exact file")
        self.file("exact-other", b"retained exact sibling")
        args = self.args([self.root])
        args.exclude_path = [str(self.root / "private"), str(self.root / "exact"), args.work]
        code, report, daemon = self.run_report(args)
        self.assertEqual(code, 0)
        self.assertEqual(report["scanned"], 2)
        self.assertCountEqual(daemon.received, [b"retained sibling", b"retained exact sibling"])
        self.assertGreaterEqual(report["internal_paths_excluded"], 3)
        self.assertIn(str(self.root / "private"), report["exclusions"])

    def test_own_work_directory_is_not_indexed_inside_target(self):
        payload = self.file("payload.txt", b"external payload")
        args = self.args([self.root])
        work = Path(args.work)
        work.mkdir()
        (work / "worker.log").write_text("mutable internal runtime state")
        args.exclude_path = [str(work)]
        code, report, daemon = self.run_report(args)
        self.assertEqual(code, 0)
        self.assertEqual(report["indexed"], 1)
        self.assertEqual(report["scanned"], 1)
        self.assertEqual(daemon.received, [payload.read_bytes()])
        self.assertGreater(report["internal_paths_excluded"], 0)
        spool_paths = [json.loads(line) for line in (work / "files.jsonl").read_text().splitlines()]
        self.assertEqual(spool_paths, [str(payload)])

    def test_pending_futures_remain_bounded(self):
        paths = [self.file(f"queue/{number}.txt") for number in range(80)]
        args = self.args(paths, jobs=2)
        args_path = Path(args.work)
        args_path.mkdir()
        state = self.engine.ScanState(args)
        spool = args_path / "files.jsonl"
        self.engine.index_files(state, spool)
        release = threading.Event()
        original_wait = self.engine.concurrent.futures.wait
        pending_sizes = []

        def mock_scan(path, _socket, _limit, _stop):
            self.assertTrue(release.wait(1))
            return {"path": path, "status": "clean", "scanned": True, "message": ""}

        def observe_wait(futures, *other, **kwargs):
            pending_sizes.append(len(futures))
            release.set()
            return original_wait(futures, *other, **kwargs)

        with mock.patch.object(self.engine, "scan_file", side_effect=mock_scan), mock.patch.object(
            self.engine.concurrent.futures, "wait", side_effect=observe_wait
        ):
            self.engine.scan_index(state, spool)
        self.assertGreater(len(pending_sizes), 0)
        self.assertLessEqual(max(pending_sizes), args.jobs * 4)
        self.assertEqual(state.report["scanned"], len(paths))


class MenuIntegrationTests(unittest.TestCase):
    """Execute the real sourced Zsh run_scan with only daemon startup stubbed."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avmenu-", dir="/tmp")
        self.root = Path(self.temp.name)
        self.payload = self.root / "target-ไทย.txt"
        self.payload.write_bytes(b"small fixture")
        self.socket = self.root / "clamd.sock"
        self.avdir = self.root / "av state"
        (self.avdir / "logs").mkdir(parents=True)
        self.stopped = self.root / "daemon-stopped"

    def tearDown(self):
        self.temp.cleanup()

    def menu_process(self, setup=""):
        environment = os.environ.copy()
        environment.update(
            AV_SOURCE_ONLY="1", AV_DIR=str(self.avdir), AV_ENGINE_PATH=str(ENGINE_SOURCE),
            AV_PYTHON=sys.executable, MENU_SOURCE=str(MENU_SOURCE), TEST_SOCKET=str(self.socket),
            TEST_TARGET=str(self.payload), TEST_STOPPED=str(self.stopped),
            TEST_DAEMON_PID=str(os.getpid()), HOME=str(self.root),
        )
        script = r'''source "$MENU_SOURCE"
JOBS=1
ensure_fresh() { return 0; }
start_clamd() {
  RUN_SOCK="$TEST_SOCKET"; DAEMON_PID="$TEST_DAEMON_PID"; DAEMON_FRESH=1
  DAEMON_DIR="$AVDIR/daemon-unused"; DAEMON_LOG="$AVDIR/clamd.log"
  : > "$DAEMON_LOG"
  return 0
}
stop_clamd() { print stopped >> "$TEST_STOPPED"; DAEMON_PID=""; DAEMON_DIR=""; return 0; }
caffeinate() { return 0; }
run_scan custom Fixture "$TEST_TARGET"
result_code=$?
exit $result_code
'''
        script = script.replace('run_scan custom Fixture "$TEST_TARGET"', setup + '\nrun_scan custom Fixture "$TEST_TARGET"')
        return subprocess.Popen(["/bin/zsh", "-c", script], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def execute_menu(self, response=b"stream: OK\0"):
        with FakeClamd(self.socket, response=response) as daemon:
            process = self.menu_process()
            stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(daemon.errors, [])
        return process.returncode, stdout.decode(), stderr.decode()

    def report(self):
        reports = list((self.avdir / "logs").glob("*.log.json"))
        self.assertEqual(len(reports), 1)
        return json.loads(reports[0].read_text())

    def test_early_engine_start_failure_returns_two(self):
        process = self.menu_process("start_clamd() { return 1; }")
        output, error = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 2, (output, error))
        self.assertIn(b"Cannot start the private engine", output)

    def test_early_work_directory_failure_returns_two(self):
        process = self.menu_process("mktemp() { return 1; }")
        output, error = process.communicate(timeout=3)
        self.assertEqual(process.returncode, 2, (output, error))

    def test_owned_alive_refuses_sibling_but_accepts_owned_child(self):
        unrelated = subprocess.Popen(["/bin/sleep", "30"])
        environment = os.environ.copy()
        environment.update(AV_SOURCE_ONLY="1", MENU_SOURCE=str(MENU_SOURCE), TEST_UNRELATED=str(unrelated.pid))
        script = r'''source "$MENU_SOURCE"
owned_alive "$TEST_UNRELATED" && exit 20
stop_child "$TEST_UNRELATED"
/bin/sleep 30 &
owned=$!
owned_alive "$owned" || { kill "$owned"; exit 21; }
stop_child "$owned"
kill -0 "$owned" 2>/dev/null && exit 22
exit 0
'''
        try:
            result = subprocess.run(["/bin/zsh", "-c", script], env=environment, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
            self.assertIsNone(unrelated.poll(), "stop_child must leave unrelated sibling process alive")
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=3)

    def test_simultaneous_menu_sessions_keep_separate_engine_diagnostics(self):
        fake_daemon = self.root / "fake-daemon.py"
        fake_daemon.write_text(
            "#!/usr/bin/env python3\n"
            "import os, signal, sys\n"
            "from pathlib import Path\n"
            "sys.stderr.write(os.environ['TEST_DIAGNOSTIC'] + '\\n'); sys.stderr.flush()\n"
            "Path(os.environ['TEST_READY']).write_text('ready')\n"
            "while True: signal.pause()\n"
        )
        fake_daemon.chmod(0o700)
        database = self.root / "database"
        database.mkdir()
        release = self.root / "release-sessions"
        sessions = []
        log_paths = []
        script = r'''source "$MENU_SOURCE"
DBDIR="$TEST_DATABASE"
trap cleanup_all EXIT
start_clamd || exit 10
print -r -- "$DAEMON_LOG" > "$TEST_METADATA"
while [[ ! -f "$TEST_RELEASE" ]]; do sleep .01; done
'''
        try:
            for number, diagnostic in enumerate(("LibClamAV Error: first startup failed", "second engine healthy")):
                ready = self.root / f"ready-{number}"
                metadata = self.root / f"metadata-{number}"
                environment = os.environ.copy()
                environment.update(
                    AV_SOURCE_ONLY="1", AV_DIR=str(self.avdir), AV_ENGINE_PATH=str(ENGINE_SOURCE),
                    AV_PYTHON=sys.executable, AV_CLAMD_BIN=str(fake_daemon), MENU_SOURCE=str(MENU_SOURCE),
                    TEST_DATABASE=str(database), TEST_DIAGNOSTIC=diagnostic, TEST_READY=str(ready),
                    TEST_METADATA=str(metadata), TEST_RELEASE=str(release),
                )
                process = subprocess.Popen(["/bin/zsh", "-c", script], env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                sessions.append(process)
                deadline = time.monotonic() + 3
                while not (ready.exists() and metadata.exists()) and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.005)
                detail = ""
                if not ready.exists():
                    if process.poll() is not None:
                        out, err = process.communicate(timeout=1)
                        detail = f" exit={process.returncode}, stdout={out!r}, stderr={err!r}"
                    elif metadata.exists():
                        log_path = Path(metadata.read_text().strip())
                        detail = f" log={log_path.read_text() if log_path.exists() else 'missing log'}"
                self.assertTrue(ready.exists(), f"session {number} daemon did not start{detail}")
                log_paths.append(Path(metadata.read_text().strip()))
            self.assertNotEqual(log_paths[0], log_paths[1])
            self.assertEqual(log_paths[0].read_text().strip(), "LibClamAV Error: first startup failed")
            self.assertEqual(log_paths[1].read_text().strip(), "second engine healthy")
        finally:
            release.touch()
            for process in sessions:
                try:
                    output, error = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 0, (output, error))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()
                    raise

    def test_clean_menu_scan_returns_zero_and_keeps_healthy_engine(self):
        code, output, error = self.execute_menu()
        self.assertEqual(code, 0, (output, error))
        self.assertIn("Scan complete", output)
        self.assertIn("1 of 1 indexed", output)
        self.assertFalse(self.stopped.exists())
        self.assertEqual(self.report()["outcome"], "clean")

    def test_threat_menu_scan_returns_one_and_keeps_healthy_engine(self):
        code, output, error = self.execute_menu(b"stream: Test.Signature FOUND\0")
        self.assertEqual(code, 1, (output, error))
        self.assertIn("1 threat(s) detected", output)
        self.assertFalse(self.stopped.exists())
        self.assertEqual(self.report()["outcome"], "threats")

    def test_read_error_menu_scan_returns_two_without_invalidating_engine(self):
        code, output, error = self.execute_menu(b"stream: unavailable file ERROR\0")
        self.assertEqual(code, 2, (output, error))
        self.assertIn("Scan incomplete", output)
        self.assertFalse(self.stopped.exists())
        self.assertTrue(self.report()["engine_healthy"])

    def test_engine_error_menu_scan_returns_two_and_stops_untrusted_engine(self):
        def clean_with_engine_error(_content):
            with (self.avdir / "clamd.log").open("a") as stream:
                stream.write("LibClamAV Error: bad startup signature database\n")
            return b"stream: OK\0"

        code, output, error = self.execute_menu(clean_with_engine_error)
        self.assertEqual(code, 2, (output, error))
        self.assertIn("Scan incomplete", output)
        self.assertTrue(self.stopped.exists(), "Untrusted daemon must not be reused")
        self.assertFalse(self.report()["engine_healthy"])

    def test_protocol_error_menu_scan_stops_untrusted_engine(self):
        code, output, error = self.execute_menu(b"malformed protocol reply\0")
        self.assertEqual(code, 2, (output, error))
        self.assertTrue(self.stopped.exists(), "Protocol failure must invalidate reusable daemon")
        self.assertFalse(self.report()["engine_healthy"])

    def test_sigint_menu_returns_130_and_stops_owned_engine(self):
        with FakeClamd(self.socket, delay=60) as daemon:
            process = self.menu_process()
            try:
                deadline = time.monotonic() + 3
                while not daemon.received and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(.005)
                self.assertTrue(daemon.received)
                process.send_signal(signal.SIGINT)
                output, error = process.communicate(timeout=5)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        self.assertEqual(process.returncode, 130, (output, error))
        self.assertIn(b"Scan cancelled", output)
        self.assertTrue(self.stopped.exists())
        self.assertEqual(self.report()["outcome"], "cancelled")


class UpdateSignatureIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avupdate-", dir="/tmp")
        self.root = Path(self.temp.name)
        self.prefix = self.root / "controlled-prefix"
        self.source_config = self.prefix / "etc/clamav/freshclam.conf"
        self.source_config.parent.mkdir(parents=True)
        self.original_config = (
            "DatabaseMirror database.clamav.net\n"
            "  NotifyClamd /private/unrelated-service/clamd.conf\n"
            "Checks 12\n"
            "# NotifyClamd commented-example\n"
        )
        self.source_config.write_text(self.original_config)
        self.fake = self.root / "fake-freshclam.py"
        self.fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, signal, sys\n"
            "from pathlib import Path\n"
            "args = dict(item[2:].split('=', 1) for item in sys.argv[1:])\n"
            "cfg = Path(args['config-file'])\n"
            "data = dict(config_path=str(cfg), config=cfg.read_text(), args=args, pid=os.getpid())\n"
            "Path(os.environ['TEST_CAPTURE']).write_text(json.dumps(data))\n"
            "if os.environ['TEST_MODE'] == 'cancel':\n"
            "    while True: signal.pause()\n"
            "sys.exit(0 if os.environ['TEST_MODE'] == 'success' else 13)\n"
        )
        self.fake.chmod(0o700)

    def tearDown(self):
        self.temp.cleanup()

    def launch_update(self, mode, public_cli=None):
        state = self.root / mode
        state.mkdir()
        capture = state / "capture.json"
        environment = os.environ.copy()
        environment.update(
            AV_SOURCE_ONLY="1", AV_DIR=str(state), AV_FRESHCLAM_BIN=str(self.fake),
            HOMEBREW_PREFIX=str(self.prefix), MENU_SOURCE=str(MENU_SOURCE),
            AV_FRESHCLAM_CONF=str(self.source_config), AV_DB_DIR=str(self.prefix / "var/lib/clamav"),
            TEST_CAPTURE=str(capture), TEST_MODE=mode,
        )
        script = r'''source "$MENU_SOURCE"
trap cleanup_all EXIT
trap 'ABORT=1' INT
update_signatures
result_code=$?
exit $result_code
'''
        if public_cli is not None:
            environment.pop("AV_SOURCE_ONLY", None)
            environment.update(AV_PYTHON=sys.executable, AV_CLAMD_BIN="/usr/bin/true", AV_CLAMSCAN_BIN="/usr/bin/true", AV_ENGINE_PATH=str(ENGINE_SOURCE))
            command = ["/bin/zsh", str(MENU_SOURCE), public_cli]
        else:
            command = ["/bin/zsh", "-c", script]
        process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return process, state, capture

    def assert_private_config_cleaned(self, state, capture):
        data = json.loads(capture.read_text())
        self.assertNotEqual(Path(data["config_path"]), self.source_config)
        self.assertFalse(Path(data["config_path"]).exists())
        self.assertEqual(list(state.glob("update-config.*")), [])
        self.assertEqual(self.source_config.read_text(), self.original_config)
        self.assertIn("DatabaseMirror database.clamav.net", data["config"])
        self.assertFalse(any(line.split() and line.split()[0] == "NotifyClamd" for line in data["config"].splitlines()))
        self.assertEqual(data["args"]["datadir"], str(self.prefix / "var/lib/clamav"))
        return data

    def test_success_uses_private_filtered_config_and_marks_freshness(self):
        process, state, capture = self.launch_update("success")
        output, error = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, (output, error))
        self.assertIn(b"Signatures are up to date", output)
        self.assertTrue((state / "db-checked").exists())
        self.assert_private_config_cleaned(state, capture)

    def test_failure_and_cancellation_clean_private_config_without_false_freshness(self):
        for mode, expected_code in (("failure", 13), ("cancel", 130)):
            with self.subTest(mode=mode):
                process, state, capture = self.launch_update(mode)
                try:
                    if mode == "cancel":
                        deadline = time.monotonic() + 3
                        while not capture.exists() and process.poll() is None and time.monotonic() < deadline:
                            time.sleep(.005)
                        self.assertTrue(capture.exists())
                        process.send_signal(signal.SIGINT)
                    output, error = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, expected_code, (output, error))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                self.assertFalse((state / "db-checked").exists())
                data = self.assert_private_config_cleaned(state, capture)
                with self.assertRaises(ProcessLookupError):
                    os.kill(data["pid"], 0)

    @unittest.skipUnless(sys.platform == "darwin", "Public wrapper supports macOS")
    def test_public_update_cli_preserves_failure_and_cancel_status(self):
        for mode, command, expected in (("failure", "update", 13), ("cancel", "--update", 130)):
            with self.subTest(mode=mode):
                process, state, capture = self.launch_update(mode, public_cli=command)
                try:
                    if mode == "cancel":
                        deadline = time.monotonic() + 3
                        while not capture.exists() and process.poll() is None and time.monotonic() < deadline:
                            time.sleep(.005)
                        self.assertTrue(capture.exists())
                        process.send_signal(signal.SIGINT)
                    output, error = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, expected, (output, error))
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
                self.assertFalse((state / "db-checked").exists())
                self.assert_private_config_cleaned(state, capture)


class CleanMachineCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="avcli-", dir="/tmp")
        self.root = Path(self.temp.name)
        self.home = self.root / "empty-home"
        self.home.mkdir()
        self.runtime = self.root / "fake-runtime.py"
        self.runtime.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('ClamAV 1.5.4/fixture'); sys.exit(0)\n"
            "sys.exit(13)\n"
        )
        self.runtime.chmod(0o700)
        self.environment = os.environ.copy()
        for key in (
            "AV_SOURCE_ONLY", "AV_DIR", "AV_DB_DIR", "AV_FRESHCLAM_CONF", "AV_ENGINE_PATH",
            "AV_QUARANTINE_DIR", "AV_RUNTIME_PREFIX", "AV_JOBS",
        ):
            self.environment.pop(key, None)
        self.environment.update(
            HOME=str(self.home), HOMEBREW_PREFIX=str(self.root / "no-global-prefix"), AV_PYTHON=sys.executable,
            AV_CLAMD_BIN=str(self.runtime), AV_CLAMSCAN_BIN=str(self.runtime), AV_FRESHCLAM_BIN=str(self.runtime),
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_cli(self, arguments, overrides=None):
        environment = self.environment.copy()
        environment.update(overrides or {})
        return subprocess.run(["/bin/zsh", str(MENU_SOURCE), *arguments], env=environment, capture_output=True, timeout=10)

    @unittest.skipUnless(sys.platform == "darwin", "Public wrapper supports macOS")
    def test_clean_home_doctor_creates_private_state_and_reports_missing_database(self):
        result = self.run_cli(["doctor"])
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertNotIn(b"helper missing", result.stderr)
        self.assertIn(b"No signature database", result.stdout)
        state = self.home / ".av"
        self.assertTrue((state / "freshclam.conf").is_file())
        self.assertTrue((state / "database").is_dir())
        self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((state / "database").stat().st_mode), 0o700)
        self.assertFalse((self.root / "no-global-prefix/var/lib/clamav").exists())
        self.assertFalse((state / "db-checked").exists())

    @unittest.skipUnless(sys.platform == "darwin", "Public wrapper supports macOS")
    def test_state_database_and_jobs_overrides_reach_real_cli(self):
        state = self.root / "custom state"
        database = self.root / "custom database"
        result = self.run_cli(["--jobs", "2", "status"], {"AV_DIR": str(state), "AV_DB_DIR": str(database)})
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertTrue((state / "freshclam.conf").is_file())
        self.assertTrue(database.is_dir())
        self.assertIn(str(database), (state / "freshclam.conf").read_text())
        self.assertIn(b"2 \xc2\xb7 private engine", result.stdout)
        self.assertFalse((self.home / ".av").exists())

    def test_unsupported_platform_fails_before_creating_user_state(self):
        mock_bin = self.root / "mock-bin"
        mock_bin.mkdir()
        uname = mock_bin / "uname"
        uname.write_text("#!/bin/sh\nprintf 'Linux\\n'\n")
        uname.chmod(0o700)
        result = self.run_cli(["doctor"], {"PATH": str(mock_bin) + os.pathsep + self.environment["PATH"]})
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        self.assertIn(b"supports macOS only", result.stderr)
        self.assertFalse((self.home / ".av").exists())

    def test_help_and_version_need_no_runtime_or_user_state(self):
        for command in ("--help", "version"):
            with self.subTest(command=command):
                result = self.run_cli([command], {"AV_PYTHON": "/missing/python", "AV_CLAMD_BIN": "/missing/clamd"})
                self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                self.assertIn(b"Usage: av" if command == "--help" else b"avclean", result.stdout)
        self.assertFalse((self.home / ".av").exists())


if __name__ == "__main__":
    unittest.main()

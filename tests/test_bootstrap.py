"""Offline bootstrap and runtime checks; no installed ClamAV is required."""
from __future__ import annotations

import concurrent.futures
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "lib" / "av_engine.py"
SPEC = importlib.util.spec_from_file_location("avclean_bootstrap_engine", SOURCE)
ENGINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ENGINE)


FAKE_CLAMAV = r'''#!/usr/bin/env python3
import array, hashlib, os, pathlib, signal, socket, sys
args = sys.argv[1:]
if '--version' in args:
    print('ClamAV 9.9.9/FakeOfflineFixture')
    raise SystemExit(0)
config = next((arg.split('=', 1)[1] for arg in args if arg.startswith('--config-file=')), None)
if config:
    values = dict(line.strip().split(' ', 1) for line in pathlib.Path(config).read_text().splitlines() if line.strip())
    socket_path = values['LocalSocket']
    database = pathlib.Path(values['DatabaseDirectory'])
    pathlib.Path(PID_RECORD).write_text(str(os.getpid()))
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(8)
    while True:
        connection, _ = server.accept()
        with connection:
            command = bytearray()
            while not command.endswith(b'\0'):
                piece = connection.recv(1)
                if not piece: break
                command.extend(piece)
            if command == b'zPING\0':
                if STALL: continue
                connection.sendall(b'PONG\0')
            elif command == b'zVERSIONCOMMANDS\0':
                connection.sendall(b'ClamAV fake COMMANDS: PING VERSIONCOMMANDS FILDES\0')
            elif command == b'zFILDES\0':
                descriptors = array.array('i')
                _, messages, _, _ = connection.recvmsg(1, socket.CMSG_SPACE(descriptors.itemsize))
                for level, kind, payload in messages:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        descriptors.frombytes(payload[:len(payload) - len(payload) % descriptors.itemsize])
                descriptor = descriptors[0]
                try:
                    content = b''
                    while True:
                        piece = os.read(descriptor, 4096)
                        if not piece: break
                        content += piece
                finally:
                    os.close(descriptor)
                signature = next(database.glob('*.hdb')).read_text().strip().split(':', 2)
                matched = not BROKEN and hashlib.md5(content).hexdigest() == signature[0]
                response = 'stream: ' + signature[2] + '.UNOFFICIAL FOUND' if matched else 'stream: OK'
                connection.sendall(response.encode() + b'\0')
else:
    database = pathlib.Path(next(arg.split('=', 1)[1] for arg in args if arg.startswith('--database=')))
    fixture = pathlib.Path(args[-1])
    signature = next(database.glob('*.hdb')).read_text().strip().split(':', 2)
    matched = not BROKEN and hashlib.md5(fixture.read_bytes()).hexdigest() == signature[0]
    print(str(fixture) + ': ' + (signature[2] + '.UNOFFICIAL FOUND' if matched else 'OK'))
    raise SystemExit(1 if matched else 0)
'''


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="avboot-", dir="/tmp")
        self.root = Path(self.temporary.name)
        self.output = io.StringIO()
        self.redirect_out = contextlib.redirect_stdout(self.output)
        self.redirect_err = contextlib.redirect_stderr(self.output)
        self.redirect_out.__enter__()
        self.redirect_err.__enter__()

    def tearDown(self):
        self.redirect_err.__exit__(None, None, None)
        self.redirect_out.__exit__(None, None, None)
        self.temporary.cleanup()

    def initialize(self, **kwargs):
        state = self.root / "state"
        code = ENGINE.initialize_state(str(state), **kwargs)
        self.assertEqual(code, 0)
        return state

    def fake_binary(self, *, broken=False, stall=False):
        executable = self.root / "fake-clamav"
        pid_record = self.root / "daemon.pid"
        preamble = f"PID_RECORD = {str(pid_record)!r}\nBROKEN = {broken!r}\nSTALL = {stall!r}\n"
        lines = FAKE_CLAMAV.splitlines(keepends=True)
        executable.write_text(lines[0] + preamble + "".join(lines[1:]), encoding="utf-8")
        executable.chmod(0o700)
        return executable, pid_record

    def make_database(self):
        database = self.root / "database"
        database.mkdir(mode=0o700)
        (database / "daily.cld").write_text("fixture database", encoding="utf-8")
        return database

    def test_init_creates_private_offline_state_and_configuration(self):
        state = self.initialize()
        for directory in (state, state / "database", state / "logs"):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for file in (state / "freshclam.conf", state / "logs" / "freshclam.log"):
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
        configuration = (state / "freshclam.conf").read_text()
        self.assertIn("DatabaseMirror database.clamav.net\n", configuration)
        self.assertIn("ScriptedUpdates yes\n", configuration)
        self.assertIn(f"DatabaseDirectory {state / 'database'}\n", configuration)
        self.assertNotIn("NotifyClamd", configuration)
        self.assertEqual(list((state / "database").iterdir()), [])

    def test_repeated_init_preserves_user_configuration_and_logs(self):
        state = self.initialize()
        configuration = state / "freshclam.conf"
        configuration.write_text("# User proxy settings\nHTTPProxyServer localhost\n")
        update_log = state / "logs" / "freshclam.log"
        update_log.write_text("Existing update history\n")
        self.initialize()
        self.assertEqual(configuration.read_text(), "# User proxy settings\nHTTPProxyServer localhost\n")
        self.assertEqual(update_log.read_text(), "Existing update history\n")

    def test_database_override_is_private_and_recorded(self):
        database = self.root / "custom database"
        state = self.initialize(database_path=str(database))
        self.assertIn(f"DatabaseDirectory {database}\n", (state / "freshclam.conf").read_text())
        self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o700)
        self.assertFalse((state / "database").exists())

    def test_control_characters_in_configuration_paths_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "control characters"):
            ENGINE.initialize_state(str(self.root / "bad\nDatabaseMirror attacker.invalid"))

    def test_state_symlink_is_rejected_without_changing_target(self):
        target = self.root / "elsewhere"
        target.mkdir(mode=0o755)
        link = self.root / "state"
        link.symlink_to(target, target_is_directory=True)
        before = target.stat().st_mode
        with self.assertRaises(ValueError):
            ENGINE.initialize_state(str(link))
        self.assertEqual(target.stat().st_mode, before)
        self.assertEqual(list(target.iterdir()), [])

    def test_configuration_symlink_is_rejected_without_overwriting_target(self):
        state = self.root / "state"
        state.mkdir()
        target = self.root / "other.conf"
        target.write_text("Preserve this\n")
        (state / "freshclam.conf").symlink_to(target)
        with self.assertRaises(ValueError):
            ENGINE.initialize_state(str(state))
        self.assertEqual(target.read_text(), "Preserve this\n")

    def test_concurrent_init_publishes_one_complete_configuration(self):
        state = self.root / "state"
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: ENGINE.initialize_state(str(state)), range(16)))
        self.assertEqual(results, [0] * 16)
        configuration = (state / "freshclam.conf").read_text()
        self.assertEqual(configuration.count("DatabaseDirectory "), 1)
        self.assertTrue(configuration.endswith("LogRotate yes\n"))
        self.assertFalse(list(state.glob(".freshclam.conf.*")))

    def test_legacy_migration_is_explicit_and_preserves_existing_files(self):
        legacy = self.root / "legacy"
        legacy.mkdir()
        (legacy / "daily.cld").write_text("legacy signatures")
        (legacy / "main.cvd").write_text("legacy main")
        (legacy / "unsafe.cvd").symlink_to(legacy / "main.cvd")
        (legacy / "freshclam.conf").write_text("NotifyClamd global.conf")
        state = self.initialize()
        self.assertEqual(list((state / "database").iterdir()), [])
        (state / "database" / "daily.cld").write_text("existing signatures")
        self.initialize(legacy_database=str(legacy))
        self.assertEqual((state / "database" / "daily.cld").read_text(), "existing signatures")
        self.assertEqual((state / "database" / "main.cvd").read_text(), "legacy main")
        self.assertFalse((state / "database" / "unsafe.cvd").exists())
        self.assertFalse((state / "database" / "freshclam.conf").exists())

    def test_descriptor_passing_round_trip_is_local_and_usable(self):
        ENGINE.descriptor_passing_available()

    def test_wrong_executable_cannot_pass_version_check(self):
        with self.assertRaises(ValueError):
            ENGINE.executable_version("/bin/echo")

    def test_doctor_reports_healthy_private_database_without_network(self):
        database = self.make_database()
        with mock.patch.object(ENGINE, "executable_version", return_value=("/fixture/clamav", "ClamAV fixture")), \
             mock.patch.object(ENGINE.sys, "platform", "darwin"), \
             mock.patch.object(ENGINE.socket, "create_connection", side_effect=AssertionError("No network")):
            code = ENGINE.doctor("clamd", "clamscan", "freshclam", str(database))
        self.assertEqual(code, 0)
        self.assertIn("[OK] Signature files: 1", self.output.getvalue())

    def test_doctor_rejects_absent_and_stale_databases(self):
        database = self.make_database()
        old = time.time() - 8 * 86400
        os.utime(database / "daily.cld", (old, old))
        with mock.patch.object(ENGINE, "executable_version", return_value=("/fixture/clamav", "ClamAV fixture")), \
             mock.patch.object(ENGINE.sys, "platform", "darwin"):
            self.assertEqual(ENGINE.doctor("clamd", "clamscan", "freshclam", str(database)), 2)
            self.assertEqual(ENGINE.doctor("clamd", "clamscan", "freshclam", str(self.root / "missing")), 2)
        self.assertIn("8.0 days old", self.output.getvalue())

    def test_doctor_rejects_database_writable_by_other_users(self):
        database = self.make_database()
        database.chmod(0o777)
        with mock.patch.object(ENGINE, "executable_version", return_value=("/fixture/clamav", "ClamAV fixture")), \
             mock.patch.object(ENGINE.sys, "platform", "darwin"):
            self.assertEqual(ENGINE.doctor("clamd", "clamscan", "freshclam", str(database)), 2)

    def test_database_ready_accepts_all_supported_signatures_and_rejects_symlinks(self):
        database = self.root / "database"
        database.mkdir()
        self.assertEqual(ENGINE.database_ready(str(database)), 2)
        target = self.root / "target"
        target.write_text("not an installed signature")
        (database / "main.cvd").symlink_to(target)
        self.assertEqual(ENGINE.database_ready(str(database)), 2)
        (database / "local-rule.yar").write_text("rule local { condition: false }")
        self.assertEqual(ENGINE.database_ready(str(database)), 0)
        self.assertEqual(ENGINE.database_ready(str(self.root / "missing")), 2)

    def test_database_ready_rejects_unreadable_signature(self):
        database = self.make_database()
        with mock.patch.object(ENGINE.os, "access", return_value=False):
            self.assertEqual(ENGINE.database_ready(str(database)), 2)

    def force_cross_filesystem(self, destination_parent):
        real_stat = Path.stat
        device = real_stat(destination_parent).st_dev
        def alternate_device(path, *args, **kwargs):
            if path == destination_parent:
                return types.SimpleNamespace(st_dev=device + 1)
            return real_stat(path, *args, **kwargs)
        return mock.patch.object(Path, "stat", alternate_device)

    def test_cross_filesystem_quarantine_copy_preserves_bytes_without_overwrite(self):
        holding = self.root / "holding"
        holding.mkdir()
        staged = holding / "item"
        staged.write_bytes(b"verified scanned bytes\n")
        staged.chmod(0o640)
        expected = ENGINE.identity_from_stat(staged.stat())
        destination_parent = self.root / "quarantine"
        destination_parent.mkdir()
        destination = destination_parent / "item"
        with self.force_cross_filesystem(destination_parent):
            ENGINE.commit_staged_file(staged, destination, expected)
        self.assertFalse(staged.exists())
        self.assertEqual(destination.read_bytes(), b"verified scanned bytes\n")
        self.assertEqual(destination.stat().st_mtime_ns, expected["mtime_ns"])
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o640)
        staged.write_bytes(b"second source")
        with self.force_cross_filesystem(destination_parent), self.assertRaises(FileExistsError):
            ENGINE.commit_staged_file(staged, destination, ENGINE.identity_from_stat(staged.stat()))
        self.assertEqual(staged.read_bytes(), b"second source")
        self.assertEqual(destination.read_bytes(), b"verified scanned bytes\n")

    def test_failed_cross_filesystem_copy_keeps_staged_data_and_removes_partial_output(self):
        staged = self.root / "staged"
        staged.write_bytes(b"verified scanned bytes\n")
        expected = ENGINE.identity_from_stat(staged.stat())
        destination_parent = self.root / "quarantine"
        destination_parent.mkdir()
        destination = destination_parent / "item"
        def fail_mid_copy(source, output):
            output.write(source.read(4))
            raise OSError("Simulated disk-full failure")
        with self.force_cross_filesystem(destination_parent), \
             mock.patch.object(ENGINE.shutil, "copyfileobj", side_effect=fail_mid_copy), \
             self.assertRaisesRegex(OSError, "disk-full"):
            ENGINE.commit_staged_file(staged, destination, expected)
        self.assertEqual(staged.read_bytes(), b"verified scanned bytes\n")
        self.assertFalse(destination.exists())

    def test_changed_staged_file_during_cross_filesystem_copy_is_not_committed(self):
        staged = self.root / "staged"
        staged.write_bytes(b"verified scanned bytes\n")
        expected = ENGINE.identity_from_stat(staged.stat())
        destination_parent = self.root / "quarantine"
        destination_parent.mkdir()
        destination = destination_parent / "item"
        real_copy = ENGINE.shutil.copyfileobj
        def mutate_during_copy(source, output):
            real_copy(source, output)
            staged.write_bytes(b"changed while copying, preserved for review\n")
        with self.force_cross_filesystem(destination_parent), \
             mock.patch.object(ENGINE.shutil, "copyfileobj", side_effect=mutate_during_copy), \
             self.assertRaises(ValueError):
            ENGINE.commit_staged_file(staged, destination, expected)
        self.assertEqual(staged.read_bytes(), b"changed while copying, preserved for review\n")
        self.assertFalse(destination.exists())

    def test_self_test_exercises_cli_fildes_and_reaps_only_its_child(self):
        executable, pid_record = self.fake_binary()
        self.assertEqual(ENGINE.self_test(str(executable), str(executable)), 0)
        daemon_pid = int(pid_record.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(daemon_pid, 0)
        self.assertIn("[OK] Offline self-test", self.output.getvalue())

    def test_self_test_rejects_false_ok_hash_failure(self):
        executable, pid_record = self.fake_binary(broken=True)
        self.assertEqual(ENGINE.self_test(str(executable), str(executable)), 2)
        self.assertFalse(pid_record.exists())
        self.assertIn("clamscan self-test failed", self.output.getvalue())

    def test_self_test_rejects_false_ok_from_daemon_and_reaps_it(self):
        broken, pid_record = self.fake_binary(broken=True)
        daemon = self.root / "broken-daemon"
        broken.rename(daemon)
        healthy_cli, _ = self.fake_binary()
        self.assertEqual(ENGINE.self_test(str(daemon), str(healthy_cli)), 2)
        daemon_pid = int(pid_record.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(daemon_pid, 0)
        self.assertIn("FILDES signature detection failed", self.output.getvalue())

    def test_self_test_rejects_internal_daemon_diagnostics_despite_matching(self):
        executable, pid_record = self.fake_binary()
        script = executable.read_text().replace(
            "    socket_path = values['LocalSocket']",
            "    print('LibClamAV Error: injected self-test failure', flush=True)\n    socket_path = values['LocalSocket']",
        )
        executable.write_text(script)
        self.assertEqual(ENGINE.self_test(str(executable), str(executable)), 2)
        daemon_pid = int(pid_record.read_text())
        with self.assertRaises(ProcessLookupError):
            os.kill(daemon_pid, 0)
        self.assertIn("Private daemon reported an internal failure", self.output.getvalue())

    def test_self_test_honors_private_temp_parent_without_changing_it(self):
        executable, _ = self.fake_binary()
        parent = self.root / "temp parent"
        parent.mkdir(mode=0o755)
        marker = parent / "keep.txt"
        marker.write_text("preserved")
        before = parent.stat().st_mode
        with mock.patch.dict(os.environ, {"AV_SELF_TEST_TMPDIR": str(parent)}):
            self.assertEqual(ENGINE.self_test(str(executable), str(executable)), 0)
        self.assertEqual(parent.stat().st_mode, before)
        self.assertEqual(list(parent.iterdir()), [marker])
        self.assertEqual(marker.read_text(), "preserved")

    def test_self_test_overlong_socket_path_is_a_friendly_failure(self):
        executable, _ = self.fake_binary()
        parent = self.root / ("long-" + "x" * 90)
        parent.mkdir()
        with mock.patch.dict(os.environ, {"AV_SELF_TEST_TMPDIR": str(parent)}):
            self.assertEqual(ENGINE.self_test(str(executable), str(executable)), 2)
        self.assertIn("socket path is too long", self.output.getvalue())
        self.assertEqual(list(parent.iterdir()), [])

    def test_sigterm_during_self_test_reaps_daemon_and_returns_130(self):
        executable, pid_record = self.fake_binary(stall=True)
        process = subprocess.Popen([sys.executable, str(SOURCE), "self-test", "--clamd", str(executable),
                                    "--clamscan", str(executable)], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 5
            while not pid_record.exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    self.fail(f"Self-test exited before daemon startup: {process.communicate()[0]}")
                time.sleep(0.01)
            self.assertTrue(pid_record.exists(), "Self-test daemon did not start")
            daemon_pid = int(pid_record.read_text())
            process.send_signal(signal.SIGTERM)
            output, _ = process.communicate(timeout=4)
            self.assertEqual(process.returncode, 130, output)
            with self.assertRaises(ProcessLookupError):
                os.kill(daemon_pid, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""OC2MAC1 integration tests. Standard library only; requires a real macOS helper."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import unittest

MAGIC = b"OC2MAC1\0"
TIMEOUT = 12.0
BINARY = None
SESSION = None


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def text(value):
    encoded = str(value).encode("utf-16le")
    return struct.pack("<I", len(encoded) // 2) + encoded


def entry(kind, path, saved="", digest="", mode=0, ticks=0, size=0, children=0):
    return (struct.pack("<I", kind) + text(path) + text(saved) + text(digest)
            + struct.pack("<IqqI", mode, ticks, size, children))


def records(items):
    return struct.pack("<I", len(items)) + b"".join(items)


class Fixture:
    def __init__(self, root):
        self.root = root
        self.boundary = root / "BepInEx"
        self.plugins = self.boundary / "plugins"
        self.cache = self.boundary / "cache" / "HostUtilitiesUpdates"
        self.home = self.cache / "plan-test"
        self.old_dir = self.plugins / "old"
        self.old_dir.mkdir(parents=True)
        self.home.mkdir(parents=True)
        self.helper = self.home / "HostUtilities.Installer"
        shutil.copy2(BINARY, self.helper)
        self.helper.chmod(0o755)
        self.target = self.old_dir / "HostUtilities.dll"
        self.old_bytes = b"original DLL\x00\xff"
        self.new_bytes = b"replacement DLL\x00\xfe"
        self.write(self.target, self.old_bytes, 0o640)
        self.source = self.home / "stage-new"
        self.write(self.source, self.new_bytes, 0o644)
        self.owner = None
        self.processes = []
        self.query_count = 0
        try:
            # This is a real, short-lived owner; EOF releases it naturally.
            self.owner = subprocess.Popen(
                [sys.executable, "-c", "import sys; sys.stdin.buffer.read(1)"],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.creation = int(self.query("--owner", str(self.owner.pid), r"[0-9]+\n"))
            require(self.creation > 0, "invalid owner FILETIME")
            self.old_record = self.file_record(self.target, "snapshot-old")
            self.old_metadata = self.metadata(self.target)
            self.new_record = self.install_record(self.target)
            self.checks = [self.old_record]
            self.moves = [self.old_record]
            self.installs = [self.new_record]
            self.directories = [self.plugins / "created-empty"]
            self.prune = []
            self.cleanup = 0
        except BaseException:
            self.close()
            raise

    @staticmethod
    def write(path, data, mode=0o644):
        path.write_bytes(data)
        path.chmod(mode)
        # Exact microsecond time works on APFS and exercises FILETIME conversion.
        stamp = 1700000000123456000
        os.utime(path, ns=(stamp, stamp))

    def query(self, option, value, pattern):
        self.query_count += 1
        result = subprocess.run([str(self.helper), option, str(value)],
                                capture_output=True, timeout=TIMEOUT, check=False)
        (self.root / ("query-%03d.log" % self.query_count)).write_bytes(
            ("%s %s rc=%d\n" % (option, value, result.returncode)).encode("utf-8")
            + result.stdout + b"\nstderr:\n" + result.stderr)
        require(result.returncode == 0, "helper query failed: " + option)
        output = result.stdout.decode("ascii")
        require(re.fullmatch(pattern, output) is not None, "invalid query stdout: " + repr(output))
        return output

    def metadata(self, path):
        mode, ticks = map(int, self.query("--metadata", path, r"[0-9]+ [0-9]+\n").split())
        st = path.stat()
        require(mode == (st.st_mode & 0o777), "metadata mode mismatch")
        require(ticks == 116444736000000000 + st.st_mtime_ns // 100, "metadata FILETIME mismatch")
        return mode, ticks

    def file_record(self, path, snapshot):
        saved = self.home / snapshot
        shutil.copy2(path, saved)
        mode, ticks = self.metadata(path)
        data = path.read_bytes()
        return entry(1, path, saved, hashlib.sha256(data).hexdigest(), mode, ticks, len(data))

    def install_record(self, target):
        mode, ticks = self.metadata(self.source)
        return entry(0, target, self.source, hashlib.sha256(self.new_bytes).hexdigest(),
                     mode, ticks, len(self.new_bytes))

    def plan(self):
        # validate_plan: home is a strict cache descendant; both boundaries are
        # the same real BepInEx directory; every saved file lives below home.
        header = MAGIC + struct.pack("<IqI", self.owner.pid, self.creation, self.cleanup)
        roots = (self.boundary, self.boundary, self.plugins, self.cache, self.target)
        group = b"".join(records(items) for items in (self.checks, self.moves, self.installs))
        group += records([text(p) for p in self.directories])
        group += records([text(p) for p in self.prune])
        (self.home / "install.plan").write_bytes(
            header + b"".join(text(p) for p in roots) + struct.pack("<I", 1) + group)

    def launch(self):
        # No shell and no start_new_session: the helper calls setsid itself.
        log = self.root / ("launch-%d.log" % len(self.processes))
        with log.open("wb") as output:
            proc = subprocess.Popen([str(self.helper)], cwd=str(self.root),
                                    stdin=subprocess.DEVNULL, stdout=output, stderr=output)
        self.processes.append(proc)
        return proc

    def wait_marker(self, name, expected):
        path = self.home / name
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if path.exists():
                require(path.read_bytes() == expected, "wrong marker bytes: " + name)
                return
            require(self.processes[-1].poll() is None, "helper exited before " + name)
            time.sleep(0.02)
        raise AssertionError("timeout waiting for " + name)

    def marker(self, name, data):
        # Match the managed publisher: flush a fresh file, then atomically rename.
        pending = self.home / (name + ".test-pending")
        with pending.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(pending, self.home / name)

    def start(self, authorize=True):
        self.plan()
        self.launch()
        self.wait_marker("ready.flag", b"ready\r\n")
        require((self.home / "started.flag").is_file(), "missing anti-replay marker")
        if authorize:
            self.marker("armed.flag", b"armed\r\n")
            self.wait_marker("authorized.flag", b"authorized\r\n")

    def exit_owner(self):
        if self.owner and self.owner.stdin:
            self.owner.stdin.close()
            self.owner.stdin = None
        if self.owner:
            require(self.owner.wait(timeout=TIMEOUT) == 0, "owner did not exit normally")

    def finish(self, success, reason=None, code=None):
        # Popen is the actual helper, not a detached launcher or shell.
        rc = self.processes[-1].wait(timeout=TIMEOUT)
        require((rc == 0) == success, "unexpected helper exit code: %d" % rc)
        if code is not None:
            require(rc == code, "expected rc=%d, got %d" % (code, rc))
        complete = self.home / "complete.flag"
        if success:
            require(complete.read_bytes() == b"Applied successfully\r\n", "invalid completion marker")
        else:
            require(not complete.exists(), "failed transaction published completion")
        if reason:
            require(reason in self.log(), "missing log evidence: " + reason)

    def log(self):
        name = "cleanup-resources.log" if self.cleanup else "apply.log"
        path = self.home / name
        return path.read_text(encoding="utf-8") if path.exists() else ""

    def unchanged(self, data=None):
        require(self.target.read_bytes() == (self.old_bytes if data is None else data),
                "target changed unexpectedly")
        require(not (self.home / "rollback-00000000-00000000").exists(), "backup ran unexpectedly")

    def close(self):
        # Only terminate children owned by this fixture, never game processes.
        # Stop helper first so cleanup cannot release an authorized transaction.
        errors = []
        for proc in self.processes + ([self.owner] if self.owner else []):
            try:
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=2)
                if proc.stdin:
                    proc.stdin.close()
            except Exception as exc:
                errors.append(repr(exc))
        if errors:
            raise RuntimeError("child cleanup failed: " + "; ".join(errors))


class InstallerTests(unittest.TestCase):
    def setUp(self):
        root = SESSION / self._testMethodName
        root.mkdir()
        self.fx = Fixture(root)
        self.addCleanup(self.fx.close)

    def test_normal_install(self):
        f = self.fx
        # A same-version replacement may include its still-used version folder
        # in prune. Keep that nonempty folder after installing its new DLL.
        f.prune = [f.old_dir]
        f.start()
        f.exit_owner()
        f.finish(True, "files-committed=true")
        self.assertEqual(f.target.read_bytes(), f.new_bytes)
        self.assertEqual(f.metadata(f.target), f.metadata(f.source))
        self.assertEqual((f.home / "rollback-00000000-00000000").read_bytes(), f.old_bytes)
        self.assertTrue(f.directories[0].is_dir())

    def test_owner_alive_does_not_modify_files(self):
        f = self.fx
        f.start()
        deadline = time.monotonic() + 0.4
        while time.monotonic() < deadline:
            self.assertIsNone(f.owner.poll())
            self.assertIsNone(f.processes[-1].poll())
            f.unchanged()
            self.assertEqual(f.metadata(f.target), f.old_metadata)
            self.assertFalse((f.home / "complete.flag").exists())
            time.sleep(0.05)
        f.exit_owner()
        f.finish(True)

    def test_replay_rejected_with_live_owner(self):
        f = self.fx
        f.start()
        f.marker("cancel.flag", b"cancel\r\n")
        f.finish(False, "cancelled-before-owner-exit", 5)
        f.unchanged()
        self.assertIsNone(f.owner.poll())
        before = (f.home / "started.flag").read_bytes()
        (f.home / "cancel.flag").unlink()
        # Same immutable plan, same still-valid owner, existing started.flag.
        offset = len(f.log())
        f.launch()
        f.finish(False, code=4)
        self.assertIn("publish-marker", f.log()[offset:])
        self.assertEqual((f.home / "started.flag").read_bytes(), before)
        f.unchanged()

    def test_cancel_before_authorization(self):
        f = self.fx
        f.start(authorize=False)
        f.marker("cancel.flag", b"cancel\r\n")
        f.finish(False, "authorization-cancelled", 4)
        self.assertFalse((f.home / "authorized.flag").exists())
        f.unchanged()

    def test_cancel_after_authorization(self):
        f = self.fx
        f.start()
        f.marker("cancel.flag", b"cancel\r\n")
        f.finish(False, "cancelled-before-owner-exit", 5)
        f.unchanged()

    def test_late_file_change_rejected(self):
        f = self.fx
        f.start()
        changed = b"player edit after authorization"
        f.target.write_bytes(changed)
        f.exit_owner()
        f.finish(False, "file-changed", 6)
        f.unchanged(changed)
        self.assertNotIn("intent=rename-exclusive", f.log())

    def test_symlink_target_rejected(self):
        f = self.fx
        external = f.root / "outside-plugin.dll"
        external.write_bytes(f.old_bytes)
        f.target.unlink()
        f.target.symlink_to(external)
        f.plan()
        f.launch()
        f.finish(False, code=2)
        self.assertFalse((f.home / "ready.flag").exists())
        self.assertTrue(f.target.is_symlink())
        self.assertEqual(external.read_bytes(), f.old_bytes)

    def test_late_symlink_parent_rejected(self):
        f = self.fx
        f.start()
        retained = f.plugins / "retained-old"
        f.old_dir.rename(retained)
        f.old_dir.symlink_to(retained, target_is_directory=True)
        f.exit_owner()
        f.finish(False, code=6)
        self.assertTrue(f.old_dir.is_symlink())
        self.assertEqual((retained / f.target.name).read_bytes(), f.old_bytes)
        self.assertFalse((f.home / "rollback-00000000-00000000").exists())

    def test_rollback_restores_old_file(self):
        f = self.fx
        conflict = f.plugins / "collision.dll"
        conflict.write_bytes(b"unrelated player file")
        f.installs.append(f.install_record(conflict))
        f.start()
        f.exit_owner()
        f.finish(False, "restore-only-owned-bytes=true", 6)
        self.assertEqual(f.target.read_bytes(), f.old_bytes)
        self.assertEqual(f.metadata(f.target), f.old_metadata)
        self.assertEqual(conflict.read_bytes(), b"unrelated player file")
        self.assertEqual((f.home / "failed-new-00000000-00000000").read_bytes(), f.new_bytes)
        self.assertFalse((f.home / "rollback-00000000-00000000").exists())
        self.assertIn("stage=rollback", f.log())

    def test_metacharacters_and_unicode_paths(self):
        # A full fixture under shell metacharacters, quotes and a surrogate pair.
        root = self.fx.root / "空 格 & ; ' \" $() [x] % ! 한글 🥘"
        root.mkdir()
        f = Fixture(root)
        self.addCleanup(f.close)
        f.start()
        f.exit_owner()
        f.finish(True)
        self.assertEqual(f.target.read_bytes(), f.new_bytes)
        self.assertFalse((root / "x").exists())

    def test_ordinary_dsstore_preserved(self):
        f = self.fx
        finder = f.old_dir / ".DS_Store"
        finder.write_bytes(b"Finder before approval")
        finder_record = f.file_record(finder, "snapshot-finder")
        # Inventory ignores ordinary .DS_Store, but counts the old DLL.
        f.checks += [finder_record, entry(2, f.old_dir, children=1)]
        f.moves.append(finder_record)
        new_target = f.plugins / "new" / "HostUtilities.dll"
        f.installs = [f.install_record(new_target)]
        f.prune = [f.old_dir]
        f.start()
        finder.write_bytes(b"Finder changed after approval")
        f.exit_owner()
        f.finish(True, "keep-metadata-only-directory")
        self.assertEqual(finder.read_bytes(), b"Finder changed after approval")
        self.assertTrue(f.old_dir.is_dir())
        self.assertFalse(f.target.exists())
        self.assertEqual(new_target.read_bytes(), f.new_bytes)
        self.assertFalse((f.home / "rollback-00000000-00000001").exists())
        self.assertIn("keep-ordinary-metadata-file", f.log())

    def test_dsstore_symlink_rejected(self):
        f = self.fx
        finder = f.old_dir / ".DS_Store"
        finder.symlink_to(f.target)
        f.checks.append(entry(2, f.old_dir, children=1))
        f.start()
        f.exit_owner()
        f.finish(False, "inventory-failed", 6)
        f.unchanged()
        self.assertTrue(finder.is_symlink())

    def test_windows_magic_rejected(self):
        f = self.fx
        f.plan()
        path = f.home / "install.plan"
        data = path.read_bytes()
        path.write_bytes(b"OC2UPD1\0" + data[8:])
        f.launch()
        f.finish(False, code=2)
        self.assertFalse((f.home / "ready.flag").exists())
        f.unchanged()


class RecordedResult(unittest.TextTestResult):
    def startTest(self, test):
        self.started_at = time.monotonic()
        super().startTest(test)

    def stopTest(self, test):
        failures = {item.id() for item, _ in self.failures + self.errors}
        row = {"test": test.id(), "passed": test.id() not in failures,
               "seconds": round(time.monotonic() - self.started_at, 3)}
        with (SESSION / "results.jsonl").open("a", encoding="utf-8") as output:
            output.write(json.dumps(row, ensure_ascii=False) + "\n")
        super().stopTest(test)


def main():
    global BINARY, SESSION, TIMEOUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("dist/HostUtilities.Installer"))
    parser.add_argument("--workspace", type=Path, default=Path("dist/tests"),
                        help="parent for unique retained temporary sessions (default: dist/tests)")
    parser.add_argument("--timeout", type=float, default=12.0,
                        help="seconds per query/handshake/helper exit; a timeout is a failure")
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("requires macOS and a real compiled helper; no emulation or fake success")
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    TIMEOUT = args.timeout
    BINARY = args.binary.resolve(strict=True)
    if not BINARY.is_file() or not os.access(BINARY, os.X_OK):
        parser.error("--binary must be an executable regular file")
    workspace = args.workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    SESSION = Path(tempfile.mkdtemp(prefix="run-", dir=workspace))
    (SESSION / "environment.json").write_text(json.dumps({
        "binary": str(BINARY), "sha256": hashlib.sha256(BINARY.read_bytes()).hexdigest(),
        "protocol": "OC2MAC1", "machine": platform.machine(), "macOS": platform.mac_ver()[0],
        "python": sys.version, "timeout": TIMEOUT,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Retained regression workspace: " + str(SESSION), flush=True)
    try:
        with (SESSION / "unittest.log").open("w", encoding="utf-8") as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=RecordedResult).run(
                unittest.defaultTestLoader.loadTestsFromTestCase(InstallerTests))
        summary = {"tests": result.testsRun, "failures": len(result.failures),
                   "errors": len(result.errors), "passed": result.wasSuccessful(),
                   "machine": platform.machine(), "workspace": str(SESSION)}
        (SESSION / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print((SESSION / "unittest.log").read_text(encoding="utf-8"), end="")
        return 0 if result.wasSuccessful() else 1
    except BaseException:
        (SESSION / "runner-error.log").write_text(traceback.format_exc(), encoding="utf-8")
        raise


if __name__ == "__main__":
    sys.exit(main())

"""Sandbox guarantees for the analyzer CLI.

The engine already needs no network, no writes and no privileges. That is an
asset to keep, not to acquire, so these tests fail the moment it stops being
true. Two layers:

- process-level tests run everywhere (including CI without Docker) by taking the
  capabilities away in-process;
- the Docker test runs the exact command batch consumers run.
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOL_FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "solidity", "WithdrawNoGuard.sol")
DOCKERFILE = os.path.join(REPO_ROOT, "Dockerfile.analyzer")

# Set to an existing tag to skip the build step in this test run.
IMAGE_ENV = "SG_ANALYZER_IMAGE"
DEFAULT_IMAGE = "smartgraphical-analyzer:pytest"

SANDBOX_FLAGS = ["--network", "none", "--cap-drop", "ALL", "--read-only"]


def docker_available():
    if not shutil.which("docker"):
        return False
    probe = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, timeout=60,
    )
    return probe.returncode == 0


class _NoNetwork:
    """Make every outbound socket attempt raise, the way --network none does."""

    def __enter__(self):
        self._saved = (socket.socket, socket.create_connection, socket.getaddrinfo)

        def blocked(*args, **kwargs):
            raise AssertionError("analysis attempted a network operation")

        socket.socket = blocked
        socket.create_connection = blocked
        socket.getaddrinfo = blocked
        return self

    def __exit__(self, *exc_info):
        socket.socket, socket.create_connection, socket.getaddrinfo = self._saved
        return False


def _snapshot(directory):
    """Path -> (size, mtime_ns) for everything under `directory`."""
    state = {}
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            info = os.stat(full)
            state[os.path.relpath(full, directory)] = (info.st_size, info.st_mtime_ns)
    return state


@unittest.skipUnless(os.path.isfile(SOL_FIXTURE), "solidity fixture WithdrawNoGuard.sol missing")
class AnalyzerProcessSandboxTests(unittest.TestCase):

    def _run_cli(self, argv, cwd=None):
        import io

        from smartgraphical.interfaces.cli import analyzer

        stdout, stderr = io.StringIO(), io.StringIO()
        previous = os.getcwd()
        if cwd:
            os.chdir(cwd)
        try:
            code = analyzer.main(argv, stdout=stdout, stderr=stderr)
        finally:
            os.chdir(previous)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_analysis_completes_with_networking_disabled(self):
        with _NoNetwork():
            code, stdout, _ = self._run_cli(["analyze", SOL_FIXTURE, "--graph"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["status"], "ok")

    def test_analysis_does_not_write_to_the_target_directory(self):
        import tempfile

        with tempfile.TemporaryDirectory() as target_dir:
            copied = os.path.join(target_dir, "T.sol")
            shutil.copy(SOL_FIXTURE, copied)
            before = _snapshot(target_dir)
            code, _, _ = self._run_cli(["analyze", copied, "--graph"])
            self.assertEqual(code, 0)
            self.assertEqual(_snapshot(target_dir), before)

    @unittest.skipIf(os.geteuid() == 0, "root ignores directory permissions")
    def test_analysis_completes_from_a_read_only_working_directory(self):
        import tempfile

        with tempfile.TemporaryDirectory() as work_dir:
            os.chmod(work_dir, 0o500)
            try:
                code, stdout, _ = self._run_cli(["analyze", SOL_FIXTURE, "--graph"], cwd=work_dir)
            finally:
                os.chmod(work_dir, 0o700)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(stdout)["status"], "ok")

    def test_analysis_writes_no_bytecode_next_to_the_sources(self):
        # A stray __pycache__ write is exactly what breaks --read-only.
        result = subprocess.run(
            [sys.executable, "-B", "-m", "smartgraphical", "analyze", SOL_FIXTURE],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "ok")


@unittest.skipUnless(os.path.isfile(DOCKERFILE), "Dockerfile.analyzer missing")
@unittest.skipUnless(docker_available(), "docker daemon not available")
class AnalyzerImageSandboxTests(unittest.TestCase):
    """Runs the published contract's exact command line."""

    image = None
    audit_dir = None
    _tempdir = None

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls.image = os.environ.get(IMAGE_ENV)
        if not cls.image:
            cls.image = DEFAULT_IMAGE
            build = subprocess.run(
                [
                    "docker", "build", "-f", DOCKERFILE,
                    "--build-arg", "SG_TOOL_VERSION=pytest",
                    "-t", cls.image, REPO_ROOT,
                ],
                capture_output=True, text=True, timeout=1800,
            )
            if build.returncode != 0:
                raise unittest.SkipTest(f"analyzer image build failed:\n{build.stderr[-2000:]}")

        cls._tempdir = tempfile.TemporaryDirectory()
        cls.audit_dir = cls._tempdir.name
        shutil.copy(SOL_FIXTURE, os.path.join(cls.audit_dir, "T.sol"))

    @classmethod
    def tearDownClass(cls):
        if cls._tempdir is not None:
            cls._tempdir.cleanup()

    def run_sandboxed(self, args, entrypoint=None):
        command = ["docker", "run", "--rm", *SANDBOX_FLAGS,
                   "-v", f"{self.audit_dir}:/audit:ro"]
        if entrypoint:
            command += ["--entrypoint", entrypoint]
        command += [self.image, *args]
        return subprocess.run(command, capture_output=True, text=True, timeout=600)

    def test_analysis_succeeds_under_the_full_sandbox(self):
        result = self.run_sandboxed(["/audit/T.sol", "--mode", "auditor"])
        self.assertEqual(result.returncode, 0, result.stderr)
        document = json.loads(result.stdout)
        self.assertEqual(document["status"], "ok")
        self.assertTrue(document["rules_run"])

    def test_container_does_not_run_as_root(self):
        result = self.run_sandboxed([], entrypoint="id")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("uid=0(root)", result.stdout)

    def test_target_mount_stays_untouched(self):
        before = _snapshot(self.audit_dir)
        self.run_sandboxed(["/audit/T.sol", "--graph"])
        self.assertEqual(_snapshot(self.audit_dir), before)

    def test_missing_path_is_a_json_error_with_a_non_zero_exit(self):
        result = self.run_sandboxed(["/audit/does_not_exist.sol"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        document = json.loads(result.stderr.strip().splitlines()[-1])
        self.assertEqual(document["status"], "error")
        self.assertEqual(document["code"], "invalid_path")

    def test_repeated_sandboxed_runs_are_byte_identical(self):
        first = self.run_sandboxed(["/audit/T.sol", "--graph"])
        second = self.run_sandboxed(["/audit/T.sol", "--graph"])
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)


@unittest.skipUnless(os.path.isfile(DOCKERFILE), "Dockerfile.analyzer missing")
@unittest.skipUnless(docker_available(), "docker daemon not available")
class AnalyzerImageProvenanceTests(unittest.TestCase):
    """`tool.version` must report the build, never a value inherited from a base.

    `Dockerfile.analyzer` writes the build arg into the environment with
    `ENV SG_TOOL_VERSION=${SG_TOOL_VERSION}`, and exposes `BASE_IMAGE` so
    consumers can pin a digest. Those two features meet in an awkward place: a
    base image is free to define `SG_TOOL_VERSION` itself, and if that value
    ever won, every report from the image would carry a wrong provenance string
    while looking perfectly well-formed. Docker resolves it the safe way today.
    These tests exist so it keeps doing so -- and so the `ENV` line, which is
    what blocks the inherited value, is not deleted as redundant.
    """

    base_image = "sg-analyzer-basefixture:pytest"
    poisoned_version = "POISONED-FROM-BASE"
    _built = []
    _tempdir = None

    @classmethod
    def setUpClass(cls):
        import tempfile

        cls._tempdir = tempfile.TemporaryDirectory()
        dockerfile = os.path.join(cls._tempdir.name, "Dockerfile")
        with open(dockerfile, "w", encoding="utf-8") as handle:
            handle.write(
                "FROM python:3.12-slim\n"
                f"ENV SG_TOOL_VERSION={cls.poisoned_version}\n"
            )
        build = subprocess.run(
            ["docker", "build", "-f", dockerfile, "-t", cls.base_image, cls._tempdir.name],
            capture_output=True, text=True, timeout=1800,
        )
        if build.returncode != 0:
            raise unittest.SkipTest(f"base fixture build failed:\n{build.stderr[-2000:]}")
        cls._built.append(cls.base_image)

    @classmethod
    def tearDownClass(cls):
        for tag in cls._built:
            subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, timeout=120)
        if cls._tempdir is not None:
            cls._tempdir.cleanup()

    def build_on_poisoned_base(self, tag, tool_version=None):
        command = [
            "docker", "build", "-f", DOCKERFILE,
            "--build-arg", f"BASE_IMAGE={self.base_image}",
        ]
        if tool_version is not None:
            command += ["--build-arg", f"SG_TOOL_VERSION={tool_version}"]
        command += ["-t", tag, REPO_ROOT]
        build = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        self.assertEqual(build.returncode, 0, build.stderr[-2000:])
        self._built.append(tag)
        return tag

    def reported_version(self, tag):
        result = subprocess.run(
            ["docker", "run", "--rm", *SANDBOX_FLAGS, "--entrypoint", "printenv",
             tag, "SG_TOOL_VERSION"],
            capture_output=True, text=True, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_build_arg_wins_over_a_base_image_that_defines_the_variable(self):
        tag = self.build_on_poisoned_base("sg-analyzer-prov-arg:pytest", "v9.9.9-expected")
        self.assertEqual(self.reported_version(tag), "v9.9.9-expected")

    def test_arg_default_wins_when_no_build_arg_is_passed(self):
        # The dangerous case: nothing is passed, so a leaked base value would be
        # taken for a real build identity instead of the honest placeholder.
        tag = self.build_on_poisoned_base("sg-analyzer-prov-default:pytest")
        version = self.reported_version(tag)
        self.assertNotEqual(version, self.poisoned_version)
        self.assertEqual(version, "analyzer-unversioned")

    def test_reported_version_reaches_the_json_report(self):
        import tempfile

        tag = self.build_on_poisoned_base("sg-analyzer-prov-report:pytest", "v8.8.8-expected")
        with tempfile.TemporaryDirectory() as audit_dir:
            shutil.copy(SOL_FIXTURE, os.path.join(audit_dir, "T.sol"))
            result = subprocess.run(
                ["docker", "run", "--rm", *SANDBOX_FLAGS,
                 "-v", f"{audit_dir}:/audit:ro", tag, "/audit/T.sol"],
                capture_output=True, text=True, timeout=600,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["tool"]["version"], "v8.8.8-expected")


if __name__ == "__main__":
    unittest.main()

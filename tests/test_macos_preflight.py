"""Portable checks of truthful refusal; these are not macOS isolation tests."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "preflight-macos.sh"


@unittest.skipUnless(
    os.name == "posix",
    "POSIX-shell inventory tests run on Linux/macOS; this is not macOS runtime evidence",
)
class MacPreflightContract(unittest.TestCase):
    def call(self, *arguments, cwd=None, env=None):
        result = subprocess.run(
            ["/bin/sh", str(SCRIPT), *arguments],
            capture_output=True,
            text=True,
            timeout=5,
            cwd=cwd,
            env=env,
            check=False,
        )
        return result

    def report(self, result):
        # json.loads rejects extra prose or a second JSON document.
        report = json.loads(result.stdout)
        self.assertEqual(report["schema"], "petri.macos-preflight/v1")
        self.assertFalse(report["isolation_verified"])
        self.assertEqual(report["runtime_probe"], "NOT_RUN")
        self.assertEqual(report["runtime_status"], "UNVERIFIED")
        self.assertEqual(report["descendant_stop"], "UNVERIFIED")
        self.assertEqual(report["aggregate_resources"], "UNVERIFIED")
        self.assertEqual(report["release_acceptance"], "UNVERIFIED")
        return report

    def test_unselected_profile_cannot_certify_host_or_runtime(self):
        result = self.call()
        self.assertEqual(result.returncode, 2, result.stderr)
        report = self.report(result)
        self.assertIn(report["inventory_status"], ("UNSUPPORTED_HOST", "PROFILE_NOT_PINNED", "HOST_FACTS_UNVERIFIED"))
        self.assertEqual(report["artifacts"]["helper"]["signature_kind"], "not_provided")

    def test_unknown_argument_is_one_error_envelope_not_shell_code(self):
        with tempfile.TemporaryDirectory(prefix="petri-mac-preflight-contract-") as directory:
            marker = Path(directory) / "must-not-exist"
            argument = '--unknown="quote\\slash"\n$(touch ' + str(marker) + ")"
            result = self.call(argument, cwd=directory)
            self.assertEqual(result.returncode, 1)
            report = self.report(result)
            self.assertEqual(report["inventory_status"], "INVALID_REQUEST")
            self.assertIn(argument, report["reason"])
            self.assertFalse(marker.exists())

    def test_missing_option_value_fails_without_inventory(self):
        for option in ("--profile", "--expected-version", "--expected-build", "--expected-arch", "--petri-binary", "--helper"):
            with self.subTest(option=option):
                result = self.call(option)
                self.assertEqual(result.returncode, 1)
                report = self.report(result)
                self.assertEqual(report["inventory_status"], "INVALID_REQUEST")
                self.assertEqual(report["host"]["system"], "unknown")

    def test_error_json_preserves_trailing_newlines(self):
        argument = "--unknown\n\n"
        result = self.call(argument)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.report(result)["reason"], "Unknown argument: " + argument)

    def test_control_character_artifact_paths_are_rejected_before_inventory(self):
        result = self.call("--helper", "/tmp/line\nbreak")
        self.assertEqual(result.returncode, 1)
        report = self.report(result)
        self.assertEqual(report["host"]["system"], "unknown")
        self.assertEqual(report["artifacts"]["helper"]["signature_verification"], "not_run")

    def test_invalid_profile_and_architecture_are_not_accepted(self):
        for arguments in (("--profile", "candidate;true"), ("--expected-arch", "aarch64"), ("--expected-build", "<not-a-real-build>")):
            with self.subTest(arguments=arguments):
                result = self.call(*arguments)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.report(result)["inventory_status"], "INVALID_REQUEST")

    def test_unpinned_inventory_does_not_read_supplied_artifact(self):
        with tempfile.TemporaryDirectory(prefix="petri-mac-unselected-code-") as directory:
            pipe = Path(directory) / "not-a-selected-code-file"
            os.mkfifo(pipe)
            result = self.call("--helper", str(pipe), cwd=directory)
            self.assertEqual(result.returncode, 2)
            report = self.report(result)
            self.assertEqual(report["artifacts"]["helper"]["signature_verification"], "not_run")

    def test_help_performs_no_inventory_or_path_tool_execution(self):
        with tempfile.TemporaryDirectory(prefix="petri-mac-preflight-help-") as directory:
            marker = Path(directory) / "unexpected-tool"
            for name in ("uname", "id", "sw_vers", "codesign", "security", "xcrun", "clang"):
                tool = Path(directory) / name
                tool.write_text('#!/bin/sh\nprintf called > "' + str(marker) + '"\nexit 90\n', encoding="utf-8")
                tool.chmod(0o700)
            environment = dict(os.environ)
            environment["PATH"] = directory
            result = self.call("--help", cwd=directory, env=environment)
            self.assertEqual(result.returncode, 0)
            self.assertIn("never starts or certifies", result.stdout)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()

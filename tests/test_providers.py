"""Logs de otros proveedores (GitHub Actions, GitLab CI, Jenkins, genérico), definiciones e intentos."""

import json
import tempfile
import unittest
from pathlib import Path

from pipeline_analyzer.cli import main
from pipeline_analyzer.extractors import extract
from pipeline_analyzer.logparser import detect_provider, parse_attempts, parse_log, parse_run
from pipeline_analyzer.pipeline_def import check_definition

from test_analyzer import run_dir
from pipeline_analyzer.rules import evaluate


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


GITHUB_LOG = """2026-09-29T10:00:00.0000000Z Current runner version: '2.319.1'
2026-09-29T10:00:01.0000000Z ##[group]Run actions/checkout@v4
2026-09-29T10:00:02.0000000Z Syncing repository: org/app
2026-09-29T10:00:03.0000000Z ##[endgroup]
2026-09-29T10:00:04.0000000Z ##[group]Run mvn -B verify
2026-09-29T10:00:05.0000000Z [INFO] Tests run: 10, Failures: 0, Errors: 0, Skipped: 0
2026-09-29T10:00:06.0000000Z [INFO] BUILD SUCCESS
2026-09-29T10:00:07.0000000Z ##[group]Run aquasecurity/trivy-action@0.24.0
2026-09-29T10:00:08.0000000Z Total: 5 (UNKNOWN: 0, LOW: 1, MEDIUM: 1, HIGH: 2, CRITICAL: 1)
2026-09-29T10:00:09.0000000Z ##[error]Process completed with exit code 1.
"""

GITHUB_WORKFLOW = """on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Trivy
        uses: aquasecurity/trivy-action@0.24.0
        continue-on-error: true
      - run: curl -sSL https://get.example.sh | bash
"""

GITLAB_LOG = (
    "2026-09-29T10:00:00.000000Z 00O Running with gitlab-runner 17.2.0 (abc123)\n"
    "2026-09-29T10:00:01.000000Z 00O section_start:1727604001:prepare_executor\r\x1b[0K\x1b[0K\x1b[36;1mPreparing the \"docker\" executor\x1b[0;m\n"
    "2026-09-29T10:00:02.000000Z 00O Using docker image python:latest\n"
    "2026-09-29T10:00:03.000000Z 00O section_end:1727604003:prepare_executor\r\x1b[0K\n"
    "2026-09-29T10:00:04.000000Z 00O section_start:1727604004:step_script\r\x1b[0K\x1b[0K\x1b[36;1mExecuting \"step_script\" stage of the job script\x1b[0;m\n"
    "2026-09-29T10:00:05.000000Z 00O $ pytest\n"
    "2026-09-29T10:00:06.000000Z 00O FAILED tests/test_api.py::test_login - AssertionError: assert 401 == 200\n"
    "2026-09-29T10:00:07.000000Z 00O ================= 1 failed, 9 passed in 1.23s =================\n"
    "2026-09-29T10:00:08.000000Z 00O section_end:1727604008:step_script\r\x1b[0K\n"
    "2026-09-29T10:00:09.000000Z 00O ERROR: Job failed: exit code 1\n"
)

JENKINS_LOG = """Started by user admin
[2026-09-29T10:00:00.000Z] [Pipeline] Start of Pipeline
[2026-09-29T10:00:01.000Z] [Pipeline] stage
[2026-09-29T10:00:01.100Z] [Pipeline] { (Build)
[2026-09-29T10:00:02.000Z] > Task :test
[2026-09-29T10:00:03.000Z] com.acme.FooTest > debeCalcular FAILED
[2026-09-29T10:00:04.000Z] 12 tests completed, 2 failed
[2026-09-29T10:00:05.000Z] BUILD FAILED in 9s
[2026-09-29T10:00:05.100Z] [Pipeline] }
[2026-09-29T10:00:05.200Z] [Pipeline] // stage
[2026-09-29T10:00:06.000Z] [Pipeline] { (Security)
[2026-09-29T10:00:07.000Z] found 3 vulnerabilities (1 low, 2 high)
[2026-09-29T10:00:08.000Z] leaks found: 1
[2026-09-29T10:00:08.500Z] [Pipeline] // stage
[2026-09-29T10:00:09.000Z] ERROR: script returned exit code 1
Finished: FAILURE
"""

GENERIC_LOG = """2026-09-29 10:00:00 === Build ===
2026-09-29 10:00:01 Compilando proyecto...
2026-09-29 10:00:02 === Tests ===
2026-09-29 10:00:03 Tests:       1 failed, 4 passed, 5 total
2026-09-29 10:00:04 === Scan ===
2026-09-29 10:00:05 Passed checks: 10, Failed checks: 2, Skipped checks: 0
"""


class ProviderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_detect(self):
        self.assertEqual(detect_provider(GITHUB_LOG), "github")
        self.assertEqual(detect_provider(GITLAB_LOG), "gitlab")
        self.assertEqual(detect_provider(JENKINS_LOG), "jenkins")
        self.assertEqual(detect_provider(GENERIC_LOG), "generic")

    def test_github(self):
        m = extract(parse_log(_write(self.tmp / "gh.txt", GITHUB_LOG)))
        self.assertEqual(m["meta"]["provider"], "github")
        self.assertEqual(m["tests"]["total"], 10)
        self.assertEqual(m["scanners"]["trivy"]["critical"], 1)
        self.assertEqual(m["meta"]["result"], "FAILURE")
        ids = {f.id for f in evaluate(m)}
        self.assertIn("SCANNER_VULNS", ids)

    def test_gitlab(self):
        log = parse_log(_write(self.tmp / "job.log", GITLAB_LOG))
        self.assertEqual([s.name for s in log.steps], ['Preparing the "docker" executor', 'Executing "step_script" stage of the job script'])
        m = extract(log)
        self.assertEqual((m["tests"]["framework"], m["tests"]["total"], m["tests"]["failures"]), ("pytest", 10, 1))
        self.assertEqual(m["tests"]["failing"][0]["method"], "test_login")
        self.assertEqual(m["meta"]["result"], "FAILURE")

    def test_jenkins(self):
        log = parse_log(_write(self.tmp / "consoleText.txt", JENKINS_LOG))
        self.assertEqual([s.name for s in log.steps], ["Build", "Security"])
        m = extract(log)
        self.assertEqual((m["tests"]["framework"], m["tests"]["total"], m["tests"]["failures"]), ("gradle", 12, 2))
        self.assertEqual(m["scanners"]["npm_audit"]["high"], 2)
        self.assertEqual(m["scanners"]["gitleaks"]["leaks"], 1)
        self.assertEqual(m["meta"]["result"], "FAILURE")
        ids = {f.id for f in evaluate(m)}
        self.assertTrue({"TESTS_FAILED", "SCANNER_VULNS", "SCANNER_LEAKS"} <= ids)

    def test_generic(self):
        log = parse_log(_write(self.tmp / "build.log", GENERIC_LOG))
        self.assertEqual([s.name for s in log.steps], ["Build", "Tests", "Scan"])
        m = extract(log)
        self.assertEqual((m["tests"]["framework"], m["tests"]["total"], m["tests"]["failures"]), ("jest", 5, 1))
        self.assertEqual(m["scanners"]["checkov"]["failed"], 2)

    def test_plain_file_without_markers(self):
        log = parse_log(_write(self.tmp / "salida.txt", "hola\nmundo\n"))
        self.assertEqual(len(log.steps), 1)
        self.assertEqual(log.steps[0].name, "salida")

    def test_github_download_with_workflow(self):
        d = self.tmp / "logs_42"
        _write(d / "build" / "1_Set up job.txt", GITHUB_LOG.splitlines()[0])
        _write(d / "build" / "2_Run actions_checkout@v4.txt", "\n".join(GITHUB_LOG.splitlines()[1:4]))
        _write(d / "build" / "3_Run mvn -B verify.txt", "\n".join(GITHUB_LOG.splitlines()[4:7]))
        _write(d / "build" / "4_Run aquasecurity_trivy-action@0.24.0.txt", "\n".join(GITHUB_LOG.splitlines()[7:]))
        _write(d / "1_build.txt", GITHUB_LOG)
        _write(d / ".github" / "workflows" / "ci.yml", GITHUB_WORKFLOW)
        log = parse_run(d)
        self.assertEqual(log.provider, "github")
        self.assertEqual(len(log.steps), 4)
        m = extract(log)
        self.assertEqual(m["tests"]["total"], 10)
        ids = {f.id for f in evaluate(m)}
        self.assertTrue({"PDEF_PR_TARGET", "PDEF_UNPINNED_ACTIONS", "PDEF_TOLERATED_SECURITY", "PDEF_PIPE_SHELL",
                         "PDEF_PERMISSIONS"} <= ids, ids)


class DefinitionTest(unittest.TestCase):
    def test_owner_before_and_after(self):
        yml = "steps:\n- task: Bash@3\n  continueOnError: true\n  displayName: Breaker - CxOne\n" \
              "- task: Bash@3\n  displayName: Publicar\n  continueOnError: true\n"
        r = check_definition("azure-pipelines.yml", yml)
        self.assertEqual([(t["step"], t["security"]) for t in r["tolerated_failures"]],
                         [("Breaker - CxOne", True), ("Publicar", False)])

    def test_gitlab_allow_failure(self):
        yml = "stages: [test]\nsast:\n  stage: test\n  script: semgrep\n  allow_failure: true\n"
        r = check_definition(".gitlab-ci.yml", yml)
        self.assertEqual(r["flavor"], "gitlab")
        self.assertEqual(r["tolerated_failures"][0]["step"], "sast")


class AttemptsTest(unittest.TestCase):
    def test_two_attempts(self):
        d = Path(tempfile.mkdtemp()) / "logs_7"
        a1 = GITHUB_LOG.replace("2026-09-29T10:", "2026-09-29T08:")
        _write(d / "1_build (1).txt", a1)
        _write(d / "1_build.txt", GITHUB_LOG)
        atts = parse_attempts(d)
        self.assertEqual(len(atts), 2)
        self.assertEqual(atts[-1].start.hour, 10)
        out = Path(tempfile.mkdtemp())
        main([str(d), "--all-attempts", "--out-dir", str(out), "--no-console", "--no-progress"])
        data = json.loads((run_dir(out) / "reporte.json").read_text(encoding="utf-8"))
        self.assertEqual([r["label"] for r in data["runs"]], ["7 #1", "7 #2"])


if __name__ == "__main__":
    unittest.main()

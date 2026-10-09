"""Descargas de Azure DevOps (carpeta logs_<id> / .zip) e indicador de avance."""

import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from pipeline_analyzer.cli import _expand, main
from pipeline_analyzer.extractors import extract
from pipeline_analyzer.logparser import parse_attempts, parse_run
from pipeline_analyzer.progress import Progress

from test_analyzer import run_dir

TS = "2026-09-29T10:00:%02d.0000000Z "
JOB = "Build Block + Security"
STEPS = [
    ("Initialize job", ["Agent name: x"]),
    ("Checkout repo@refs/pull/77/merge to s", ["Syncing repository"]),
    ("Maven - Verify", ["[INFO] Tests run: 5, Failures: 1, Errors: 0, Skipped: 0",
                        "[ERROR]   FooTest.bar:10 expected: <null> but was: <[]>", "[INFO] BUILD SUCCESS"]),
    ("ReportBugs - PMD", ['docker: Error response from daemon: Conflict. The container name "/20260929.4" is already in use by container "x".',
                          "OCI runtime exec failed: possible container breakout detected",
                          "##[error]Bash exited with code '1'."]),
]


def _step_lines(i, name, body, headers=True):
    out = [TS % (i * 5) + "##[section]Starting: " + name] if headers else []
    out += [TS % (i * 5 + 1 + k) + l for k, l in enumerate(body)]
    if headers:
        out.append(TS % (i * 5 + 4) + "##[section]Finishing: " + name)
    return out


def make_download(root: Path, build="123456", headers=True, combined=False) -> Path:
    d = root / ("logs_" + build)
    job = d / JOB
    job.mkdir(parents=True)
    allines = [TS % 0 + "##[section]Starting: " + JOB]
    for i, (name, body) in enumerate(STEPS, 1):
        safe = "".join("_" if c in '\\/:*?"<>|' else c for c in name)
        (job / ("%d_%s.txt" % (i, safe))).write_text("\n".join(_step_lines(i, name, body, headers)), encoding="utf-8")
        allines += _step_lines(i, name, body)
    allines.append(TS % 59 + "##[section]Finishing: " + JOB)
    if combined:
        (d / ("1_%s.txt" % JOB)).write_text("\n".join(allines), encoding="utf-8")
    return d


class FolderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_folder_is_one_run(self):
        log = parse_run(make_download(self.tmp))
        self.assertEqual([s.name for s in log.steps], [n for n, _ in STEPS])
        self.assertEqual(log.job, JOB)
        m = extract(log)
        self.assertEqual(m["meta"]["build_id"], "123456")
        self.assertEqual(m["meta"]["pull_request"], "77")
        self.assertEqual(m["tests"]["failures"], 1)
        self.assertIn("3_Maven - Verify.txt:3", m["tests"]["failing"][0]["where"])
        self.assertEqual(m["static"]["pmd"]["status"], "NO EJECUTADO")

    def test_parse_attempts_can_skip_pipeline_definitions(self):
        folder = make_download(self.tmp)
        definition = folder / "azure-pipelines.yml"
        definition.write_text("steps: []\n", encoding="utf-8")
        included_files = []
        included = parse_attempts(folder, included_files.append)[0]
        self.assertEqual(included.definitions, [("azure-pipelines.yml", "steps: []\n")])
        self.assertIn("azure-pipelines.yml", included_files)

        skipped_files = []
        skipped = parse_attempts(folder, skipped_files.append, include_definitions=False)[0]
        self.assertEqual(skipped.definitions, [])
        self.assertNotIn("azure-pipelines.yml", skipped_files)

    def test_cli_applies_yaml_selection_and_no_yaml(self):
        folder = make_download(self.tmp)
        workflow = folder / ".github" / "workflows" / "ci.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                            "    steps:\n      - uses: actions/checkout@v4\n", encoding="utf-8")

        def run_case(name, selection=None, no_yaml=False, interactive=False):
            out = self.tmp / ("out_" + name)
            common = ["--out-dir", str(out), "--formats", "html,json", "--no-console", "--no-progress"]
            if no_yaml:
                common.append("--no-yaml")
            if interactive:
                selected = {"logs": [str(folder)], "main": str(folder), "pom": None, "reports": [], "compare_only": False}
                if selection is not None:
                    selected["yaml"] = {str(folder): selection}
                with mock.patch("pipeline_analyzer.cli.gather_console", return_value=selected):
                    rc = main(["--no-gui"] + common)
            else:
                rc = main([str(folder)] + common)
            report_dir = sorted(d for d in out.iterdir() if d.is_dir())[-1]
            return rc, (report_dir / "reporte.json").read_text(encoding="utf-8"), \
                (report_dir / "reporte.html").read_text(encoding="utf-8")

        for name, selection, no_yaml, interactive, included in (
                ("unchecked", False, False, True, False),
                ("checked", True, False, True, True),
                ("flag", None, True, False, False),
                ("default", None, False, False, True)):
            with self.subTest(name=name):
                rc, report, html = run_case(name, selection, no_yaml, interactive)
                self.assertEqual(rc, 0)
                self.assertEqual("PDEF_UNPINNED_ACTIONS" in report, included)
                self.assertEqual("ci.yml" in html, included)
                self.assertIn("1 definición(es) de pipeline" if included else "0 definición(es) de pipeline", html)

    def test_yaml_selection_of_a_grouping_folder_applies_to_every_run_inside(self):
        group = self.tmp / "descargas"
        group.mkdir()
        for build in ("111111", "222222"):
            run = make_download(group, build)
            (run / "azure-pipelines.yml").write_text("steps: []\n", encoding="utf-8")
        for selected, expected in ((False, 0), (True, 2)):
            with self.subTest(selected=selected):
                out = self.tmp / ("out_group_%s" % selected)
                choice = {"logs": [str(group)], "main": str(group), "pom": None, "reports": [], "compare_only": False,
                          "yaml": {str(group): selected}}
                with mock.patch("pipeline_analyzer.cli.gather_console", return_value=choice):
                    rc = main(["--no-gui", "--out-dir", str(out), "--formats", "html", "--no-console", "--no-progress"])
                self.assertEqual(rc, 0)
                html = (sorted(d for d in out.iterdir() if d.is_dir())[-1] / "reporte.html").read_text(encoding="utf-8")
                self.assertIn("%d definición(es) de pipeline" % expected, html)

    def test_cli_rejects_more_than_three_expanded_runs(self):
        folder = make_download(self.tmp)
        stderr = io.StringIO()
        with mock.patch("sys.stderr", stderr):
            rc = main([str(folder)] * 4 + ["--no-gui", "--no-progress", "--formats", "none"])
        self.assertEqual(rc, 2)
        self.assertIn("Máximo 3 ejecuciones", stderr.getvalue())

    def test_step_files_without_headers(self):
        log = parse_run(make_download(self.tmp, headers=False))
        self.assertEqual(len(log.steps), len(STEPS))
        self.assertEqual(log.step("Maven - Verify").name, "Maven - Verify")
        self.assertEqual(extract(log)["meta"]["pull_request"], "77")  # recuperado del nombre de archivo

    def test_combined_plus_steps_not_duplicated(self):
        log = parse_run(make_download(self.tmp, combined=True))
        self.assertEqual([s.name for s in log.steps], [n for n, _ in STEPS])  # sin pasos duplicados
        self.assertEqual(len(log.sources), len(STEPS))  # se prefieren los archivos por paso
        self.assertEqual(extract(log)["infra"]["oci_errors"], 1)

    def test_zip(self):
        d = make_download(self.tmp)
        z = self.tmp / "logs_123456.zip"
        with zipfile.ZipFile(z, "w") as zf:
            for f in d.rglob("*.txt"):
                zf.write(f, f.relative_to(d))
        log = parse_run(z)
        self.assertEqual(len(log.steps), len(STEPS))
        self.assertEqual(extract(log)["meta"]["build_id"], "123456")

    def test_expand(self):
        parent = self.tmp / "descargas"
        make_download(parent, "100")
        make_download(parent, "200")
        runs = _expand([str(parent)])
        self.assertEqual([r.name for r in runs], ["logs_100", "logs_200"])
        self.assertEqual(_expand([str(parent / "logs_100")]), [parent / "logs_100"])

    def test_cli_with_folders(self):
        parent = self.tmp / "descargas"
        make_download(parent, "100")
        make_download(parent, "200")
        out = self.tmp / "rep"
        rc = main([str(parent), "--out-dir", str(out), "--no-console", "--no-progress"])
        self.assertEqual(rc, 0)
        data = json.loads((run_dir(out) / "reporte.json").read_text(encoding="utf-8"))
        self.assertEqual(len(data["runs"]), 2)
        tf = next(f for f in data["runs"][-1]["findings"] if f["id"] == "TESTS_FAILED")
        self.assertTrue(tf["location"].endswith("3_Maven - Verify.txt:2"))


class ProgressTest(unittest.TestCase):
    def test_non_tty_prints_stages_only(self):
        buf = io.StringIO()
        p = Progress(3, stream=buf)
        p.stage("Leyendo")
        p.advance("archivo 1")
        p.log("listo")
        p.close("fin")
        out = buf.getvalue()
        self.assertRegex(out, r"[»>] Leyendo")  # » en terminales UTF-8, > en el resto
        self.assertIn("listo", out)
        self.assertIn("fin", out)
        self.assertNotIn("\r", out)
        self.assertNotIn("archivo 1", out)  # el detalle por archivo solo se dibuja en terminal

    def test_disabled(self):
        buf = io.StringIO()
        p = Progress(3, enabled=False, stream=buf)
        p.stage("x")
        p.log("y")
        p.close("z")
        self.assertEqual(buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()

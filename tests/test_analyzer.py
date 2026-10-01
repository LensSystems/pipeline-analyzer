"""Pruebas con logs sintéticos mínimos. Ejecutar: python -m unittest discover -s tests"""

import json
import tempfile
import textwrap
import unittest
from pathlib import Path

from pipeline_analyzer.cli import main
from pipeline_analyzer.compare import IMPROVED, WORSE, trend
from pipeline_analyzer.extractors import extract
from pipeline_analyzer.logparser import parse_log
from pipeline_analyzer.pom_checks import check_pom
from pipeline_analyzer.rules import evaluate

T = "2026-09-28T17:00:%02d.0000000Z "


def run_dir(out):
    """Subcarpeta del análisis más reciente dentro de --out-dir (cada corrida crea una nueva)."""
    return sorted(d for d in Path(out).iterdir() if d.is_dir())[-1]


def _log(lines):
    body = "\n".join((T % (i % 60)) + l for i, l in enumerate(lines))
    f = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
    f.write(body)
    f.close()
    return Path(f.name)


def _step(name, *content):
    return ["##[section]Starting: " + name, *content, "##[section]Finishing: " + name]


SONAR_JSON = """{
  "projectStatus": {
    "status": "ERROR",
    "conditions": [
      {"status": "ERROR", "metricKey": "reliability_rating", "comparator": "GT", "errorThreshold": "1", "actualValue": "5"},
      {"status": "OK", "metricKey": "coverage", "comparator": "LT", "errorThreshold": "95", "actualValue": "95.4"},
      {"status": "OK", "metricKey": "test_success_density", "comparator": "LT", "errorThreshold": "100", "actualValue": "100.0"}
    ]
  }
}""".splitlines()


def failing_log():
    return _log(
        ["##[section]Starting: Build Block + Security"]
        + _step("Checkout repo@refs/pull/42/merge to s", "ok")
        + _step("Maven - Verify",
                'openjdk version "25.0.2" 2026-01-20 LTS',
                "[INFO]  T E S T S",
                "[INFO] Results:",
                "[ERROR] Failures: ",
                "[ERROR]   ZipPdfBusinessTest.generaPdf_null:55 expected: <null> but was: <[]>",
                "[ERROR] Tests run: 10, Failures: 1, Errors: 0, Skipped: 0",
                "[INFO] BUILD SUCCESS")
        + _step("Sonarqube - Run", "sonar.branch.name=master", "[INFO] ANALYSIS SUCCESSFUL, you can find the results at: x")
        + _step("Sonarqube - Get report", "-- Show report", *SONAR_JSON)
        + _step("ReportBugs - Spotbugs",
                "[INFO] --- spotbugs:4.8.3.0:spotbugs (default-cli) @ app ---",
                "     [java]     java.lang.IllegalArgumentException: Unsupported class file major version 69",
                "[INFO] BUILD FAILURE", "##[error]Bash exited with code '1'.")
        + _step("ReportBugs - PMD",
                'docker: Error response from daemon: Conflict. The container name "/20260928.2" is already in use by container "abc".',
                "OCI runtime exec failed: exec failed: unable to start container process",
                "Error, File pmd.ok not found! , something went wrong during mvn execution",
                "##[error]Bash exited with code '1'.")
        + _step("Breaker - Sonarqube - Full", "ERROR , Bad Quality Gate", "##[error]Bash exited with code '1'.")
        + _step("Breaker - CxOne",
                "[INFO] Ejecutando validación directa (No se encontro linea base)",
                "| SAST     |  FALLO     | 0        | 1        | Linea Base: N/A (Scan Directo)                  |",
                "| SCA      |  PASO      | 0        | 0        | Politicas cumplidas                             |",
                "##[error]Bash exited with code '1'.")
        + ["##[section]Finishing: Build Block + Security"]
    )


def passing_log():
    ok_json = [l.replace('"ERROR"', '"OK"').replace('"actualValue": "5"', '"actualValue": "1"') for l in SONAR_JSON]
    return _log(
        ["##[section]Starting: Build Block + Security"]
        + _step("Maven - Verify", "[INFO] Tests run: 10, Failures: 0, Errors: 0, Skipped: 0", "[INFO] BUILD SUCCESS")
        + _step("Sonarqube - Get report", "-- Show report", *ok_json)
        + _step("Breaker - Sonarqube - Full", "OK")
        + ["##[section]Finishing: Build Block + Security"]
    )


class ParserTest(unittest.TestCase):
    def test_steps_and_errors(self):
        log = parse_log(failing_log())
        self.assertEqual(log.job, "Build Block + Security")
        self.assertIn("Maven - Verify", [s.name for s in log.steps])
        self.assertTrue(log.step("ReportBugs - Spotbugs").failed)
        self.assertFalse(log.step("Maven - Verify").failed)


class ExtractTest(unittest.TestCase):
    def setUp(self):
        self.m = extract(parse_log(failing_log()))

    def test_tests(self):
        t = self.m["tests"]
        self.assertEqual((t["total"], t["failures"]), (10, 1))
        self.assertEqual(t["failing"][0]["method"], "generaPdf_null")
        self.assertEqual(t["build_result"], "SUCCESS")

    def test_sonar(self):
        s = self.m["sonar"]
        self.assertEqual(s["conditions"]["reliability_rating"]["actual"], "5")
        self.assertEqual(s["breaker"], "FALLO")

    def test_static(self):
        st = self.m["static"]
        self.assertEqual(st["spotbugs"]["plugin_version"], "4.8.3.0")
        self.assertEqual(st["spotbugs"]["unsupported_class_versions"], {69: 1})
        self.assertEqual(st["pmd"]["status"], "NO EJECUTADO")
        self.assertEqual(self.m["infra"]["container_conflicts"], ["/20260928.2"])

    def test_cxone(self):
        c = self.m["cxone"]
        self.assertEqual(c["modules"]["SAST"]["high"], 1)
        self.assertFalse(c["baseline"])


class RulesTest(unittest.TestCase):
    def test_findings(self):
        ids = {f.uid for f in evaluate(extract(parse_log(failing_log())))}
        for expected in ("TESTS_FAILED", "TESTS_FAILURE_IGNORED", "SONAR_STALE_GATE",
                         "SONAR_CONDITION:reliability_rating", "SPOTBUGS_JAVA_UNSUPPORTED",
                         "DOCKER_CONTAINER_CONFLICT", "STATIC_NOT_EXECUTED", "CXONE_SAST",
                         "CXONE_NO_BASELINE", "SONAR_BRANCH_ON_PR", "SONAR_COVERAGE_MARGIN:coverage"):
            self.assertIn(expected, ids)

    def test_empty_array_hint(self):
        f = next(f for f in evaluate(extract(parse_log(failing_log()))) if f.id == "TESTS_FAILED")
        self.assertIn("arreglo vacío", f.steps[0])
        self.assertIn("assertEquals(0, result.length)", f.snippet)

    def test_trend(self):
        self.assertEqual(trend(2, 0, "lower"), IMPROVED)
        self.assertEqual(trend("A", "E", "rating"), WORSE)
        self.assertEqual(trend(8, "NO EJECUTADO", "lower"), WORSE)
        self.assertEqual(trend("FALLO", "OK", "status"), IMPROVED)


class PomTest(unittest.TestCase):
    def test_pom(self):
        pom = textwrap.dedent("""\
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>4.1.1</version></parent>
              <properties>
                <sonar.exclusions>a</sonar.exclusions><sonar.exclusions>b</sonar.exclusions>
                <sonar.jacoco.reportPath>x</sonar.jacoco.reportPath>
              </properties>
              <dependencies>
                <dependency><groupId>tools.jackson.core</groupId><artifactId>jackson-core</artifactId><version>3.2.2</version></dependency>
                <dependency><groupId>tools.jackson.core</groupId><artifactId>jackson-databind</artifactId><version>3.2.3</version></dependency>
                <dependency><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId></dependency>
              </dependencies>
              <build><plugins><plugin><artifactId>maven-surefire-plugin</artifactId>
                <configuration><testFailureIgnore>true</testFailureIgnore><test>${no.definida}</test></configuration>
              </plugin></plugins></build>
              <profiles><profile><id>dev</id><build><plugins>
                <plugin><groupId>com.github.spotbugs</groupId><artifactId>spotbugs-maven-plugin</artifactId>
                  <configuration><threshold>Max</threshold></configuration></plugin>
              </plugins></build></profile></profiles>
            </project>""")
        f = tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8")
        f.write(pom)
        f.close()
        ids = {x.id for x in check_pom(f.name)}
        for expected in ("POM_DUPLICATE_PROPERTY", "POM_DEPRECATED_SONAR", "POM_VERSION_MISMATCH", "POM_LOMBOK_SCOPE",
                         "POM_TEST_FAILURE_IGNORE", "POM_UNDEFINED_PROPERTY", "POM_PLUGINS_ONLY_IN_PROFILE",
                         "POM_SPOTBUGS_THRESHOLD"):
            self.assertIn(expected, ids)


class CliTest(unittest.TestCase):
    def test_end_to_end(self):
        out = tempfile.mkdtemp()
        rc = main([str(failing_log()), str(passing_log()), "--labels", "antes,despues",
                   "--out-dir", out, "--no-console", "--no-progress", "--fail-on", "HIGH", "--formats", "html,full,pdf,pdf-full,md,json"])
        self.assertEqual(rc, 0)  # la última corrida no tiene hallazgos HIGH
        data = json.loads((run_dir(out) / "reporte.json").read_text(encoding="utf-8"))
        self.assertEqual([r["label"] for r in data["runs"]], ["antes", "despues"])
        row = next(r for r in data["comparison"] if r["key"] == "tests.failed")
        self.assertEqual(row["values"], [1, 0])
        self.assertEqual(row["trend_prev"], IMPROVED)
        self.assertIn("SONAR_CONDITION:reliability_rating", data["diff"]["resolved"])
        self.assertTrue((run_dir(out) / "reporte.html").read_text(encoding="utf-8").startswith("<!doctype html>"))

    def test_pipeline_findings_go_last_and_are_linked(self):
        out = tempfile.mkdtemp()
        main([str(failing_log()), "--out-dir", out, "--no-console", "--no-progress", "--formats", "html,full,pdf,pdf-full,md,json"])
        page = (run_dir(out) / "reporte.html").read_text(encoding="utf-8")
        self.assertLess(page.index("Hallazgos del proyecto"), page.index("id='pipeline-recs'"))
        self.assertGreater(page.index("<details id='pf-DOCKER_CONTAINER_CONFLICT'"), page.index("id='pipeline-recs'"))  # la causa vive al final
        self.assertIn("id='pf-DOCKER_CONTAINER_CONFLICT'", page)
        self.assertIn("href='#pf-DOCKER_CONTAINER_CONFLICT'", page)  # etiqueta con enlace a la causa
        md = (run_dir(out) / "reporte.md").read_text(encoding="utf-8")
        self.assertLess(md.index("## Hallazgos del proyecto"), md.index("## Recomendaciones para quien administra el pipeline"))

    def test_each_run_gets_a_new_numbered_folder(self):
        out = tempfile.mkdtemp()
        for _ in range(2):
            main([str(failing_log()), "--out-dir", out, "--no-console", "--no-progress", "--formats", "json"])
        names = sorted(d.name for d in Path(out).iterdir() if d.is_dir())
        self.assertEqual(len(names), 2)
        self.assertRegex(names[0], r"^001_\d{4}-\d{2}-\d{2}$")
        self.assertRegex(names[1], r"^002_\d{4}-\d{2}-\d{2}$")
        for n in names:
            self.assertTrue(Path(out, n, "reporte.json").exists())

    def test_shared_reports_only_show_last_folder_as_origin(self):
        root = Path(tempfile.mkdtemp()) / "cliente_secreto" / "logs_123456"
        root.mkdir(parents=True)
        log = root / "build.txt"
        log.write_text(failing_log().read_text(encoding="utf-8"), encoding="utf-8")
        out = tempfile.mkdtemp()
        main([str(log), "--out-dir", out, "--no-console", "--no-progress", "--formats", "html,full,pdf,pdf-full,md,json"])
        d = run_dir(out)
        for name in ("reporte.html", "reporte.md", "reporte.json", "reporte.pdf"):
            text = (d / name).read_bytes().decode("latin-1")
            self.assertNotIn("cliente_secreto", text, name)
            self.assertIn("logs_123456", text, name)
        # el PDF completo tampoco lleva la ruta; el HTML completo (uso local) sí
        self.assertNotIn("cliente_secreto", (d / "reporte_completo.pdf").read_bytes().decode("latin-1"))
        self.assertIn("cliente_secreto", (d / "reporte_completo.html").read_text(encoding="utf-8"))

    def test_fail_on(self):
        rc = main([str(failing_log()), "--no-console", "--no-progress", "--formats", "none", "--fail-on", "HIGH"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

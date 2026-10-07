"""Comparativa viejo → nuevo: tabla concisa y modo «solo comparación»."""

import json
import tempfile
import unittest
from pathlib import Path

from pipeline_analyzer.cli import main
from pipeline_analyzer.compare import comparison_summary, delta, kind, summary_text

from test_analyzer import failing_log, passing_log, run_dir


class CompareHelpersTest(unittest.TestCase):
    def test_delta_and_kind(self):
        self.assertEqual(delta(12, 3), "-9")
        self.assertEqual(delta(1.5, 4), "+2.5")
        self.assertEqual(delta("B", "A"), "")
        self.assertEqual(kind(1, 0, "lower"), "improved")
        self.assertEqual(kind("A", "C", "rating"), "worse")
        self.assertEqual(kind(10, 12, None), "changed")
        self.assertEqual(kind(5, 5, "lower"), "same")
        self.assertEqual(kind("FALLO (Java 25)", "NO EJECUTADO", "lower"), "same")   # fallo y no ejecutado cuentan igual
        self.assertEqual(kind("NO EJECUTADO", 3, "lower"), "improved")

    def test_summary_text(self):
        g = {"improved": [1, 2], "worse": [1], "changed": [], "same": [1, 2, 3]}
        self.assertEqual(summary_text(g), "2 mejoraron · 1 empeoró · 3 sin cambios")


class CompareReportTest(unittest.TestCase):
    def _run(self, *extra):
        out = tempfile.mkdtemp()
        rc = main([str(failing_log()), str(passing_log()), "--labels", "antes,despues", "--out-dir", out, "--no-console", "--no-progress",
                   "--formats", "html,full,pdf,pdf-full,md,json", *extra])
        self.assertEqual(rc, 0)
        return run_dir(out)

    def test_two_runs_show_one_change_column_not_vs_previous_and_vs_first(self):
        md = (self._run() / "reporte.md").read_text(encoding="utf-8")
        self.assertIn("| Métrica | Antes · antes | Ahora · despues | Cambio |", md)
        self.assertNotIn("vs primera", md)
        self.assertNotIn("vs anterior", md)
        self.assertIn("Mejoró (-1)", md)                       # tests fallidos: 1 → 0
        self.assertRegex(md, r"\| Tests ejecutados \| .* \| Sin cambios \|")   # lo que sigue igual también aparece en la tabla
        page = (self._run() / "reporte.html").read_text(encoding="utf-8")
        self.assertNotIn("vs primera", page)

    def test_html_links_to_the_history(self):
        for extra in ((), ("--compare-only",)):
            page = (self._run(*extra) / "reporte.html").read_text(encoding="utf-8")
            self.assertIn("href='../historial-reportes.html'", page)
            self.assertIn("Historial de reportes", page)

    def test_three_runs_add_the_since_first_column(self):
        out = tempfile.mkdtemp()
        main([str(failing_log()), str(passing_log()), str(failing_log()), "--labels", "a,b,c", "--out-dir", out, "--no-console",
              "--no-progress", "--keep-order", "--formats", "md"])
        md = (run_dir(out) / "reporte.md").read_text(encoding="utf-8")
        self.assertIn("Cambio vs b", md)
        self.assertIn("Desde a", md)

    def test_compare_only_generates_only_the_comparison(self):
        d = self._run("--compare-only")
        md = (d / "reporte.md").read_text(encoding="utf-8")
        self.assertIn("## Comparación: antes → despues", md)
        self.assertNotIn("Plan de acción", md)
        self.assertNotIn("Hallazgos del proyecto", md)
        self.assertIn("Resueltos", md)
        for name in ("reporte.html", "reporte_completo.html"):
            page = (d / name).read_text(encoding="utf-8")
            self.assertIn("Solo comparación", page)
            self.assertNotIn("Ruta para pasar", page)
        self.assertTrue((d / "reporte.pdf").read_bytes().startswith(b"%PDF"))
        data = json.loads((d / "reporte.json").read_text(encoding="utf-8"))
        self.assertIn("Comparación antes → despues", data["verdict"])
        self.assertTrue(json.loads((d / "resumen.json").read_text(encoding="utf-8"))["compare_only"])

    def test_compare_only_needs_two_runs(self):
        out = tempfile.mkdtemp()
        rc = main([str(failing_log()), "--compare-only", "--out-dir", out, "--no-console", "--no-progress"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()

"""Tabla de resultados de CxOne del log (todos los motores) e inventario de archivos revisados."""

import tempfile
import unittest
import zipfile
from pathlib import Path

from pipeline_analyzer.cli import main
from pipeline_analyzer.extractors import extract
from pipeline_analyzer.logparser import parse_run

from test_analyzer import _log, _step, run_dir
from test_cxone_pdf import make_pdf

SUMMARY = """            Scan Summary:                                   Created At: 2026-09-29, 17:52:35
              Project Name: acme-app
              Scan ID: 11111111-2222-3333-4444-555555555555

            Results Summary:
              Risk Level: High Risk
              ---------------------------------------------------------------------
              Total Results: 13 (Total Results includes only API documentation vulnerabilities
              and does not include API code vulnerabilities.)
              ---------------------------------------------------------------------
              |               Critical   High    Medium   Low   Info   Status     |
              | APIs              -       -        -       -      -       -       |
              | IAC               -       -        -       -      -       -       |
              | SAST              0       1        9       2      0   Completed   |
              | SCA               0       0        0       1      0   Completed   |
              | SCS               0       0        0       0      0   Partial     |
              | CONTAINERS        -       -        -       -      -       -       |
              ---------------------------------------------------------------------
              | TOTAL             0       1        9       3      0   Completed   |
              ---------------------------------------------------------------------

              Supply Chain Security Results
              |                      Critical   High   Medium   Low   Info   Status    |
              | Secret Detection          0      0        0      0      0   Partial    |
              | Scorecard                 -      -        -      -      -       -      |""".splitlines()


def log():
    return _log(_step("CxOne Scan [SAST + SCA + SCS]", "Additional parameter: --scan-types", "Additional parameter: sast,sca,scs",
                      "SCS scan warning: Unable to start Scorecard scan due to missing required flags", *SUMMARY))


class CxoneSummaryTests(unittest.TestCase):
    def test_extracts_every_engine_and_total(self):
        c = extract(parse_run(log()))["cxone"]
        self.assertEqual(c["total_results"], 13)
        self.assertEqual(c["project"], "acme-app")
        self.assertEqual(c["created_at"], "2026-09-29, 17:52:35")
        self.assertEqual(set(c["engines"]), {"APIs", "IAC", "SAST", "SCA", "SCS", "CONTAINERS", "TOTAL"})
        self.assertFalse(c["engines"]["IAC"]["ran"])
        self.assertEqual((c["engines"]["SAST"]["medium"], c["engines"]["SAST"]["low"]), (9, 2))
        self.assertEqual(c["engines"]["SCS"]["status"], "Partial")
        self.assertFalse(c["supply_chain"]["Scorecard"]["ran"])
        self.assertIn("Scorecard", c["scs_warning"])

    def test_reports_show_the_table(self):
        out = tempfile.mkdtemp()
        main([str(log()), "--out-dir", out, "--no-console", "--no-progress", "--formats", "html,md,pdf"])
        d = run_dir(out)
        html = (d / "reporte.html").read_text(encoding="utf-8")
        self.assertIn("Resultados de CxOne", html)
        self.assertIn("<div class='big'>13<small>resultados</small>", html)
        self.assertIn("CONTAINERS", html)
        self.assertIn("no ejecutado", html)
        self.assertIn("Medium/Low/Info no bloquean", html)
        md = (d / "reporte.md").read_text(encoding="utf-8")
        self.assertIn("| SAST | 0 | 1 | 9 | 2 | 0 | Completed |", md)
        self.assertIn(b"Resultados de CxOne", (d / "reporte.pdf").read_bytes())


class CollapsedSectionsTests(unittest.TestCase):
    def test_secondary_sections_are_collapsed(self):
        out = tempfile.mkdtemp()
        main([str(log()), "--out-dir", out, "--no-console", "--no-progress", "--formats", "html"])
        html = (run_dir(out) / "reporte.html").read_text(encoding="utf-8")
        for anchor in ("plan", "hallazgos", "ejecuciones", "validaciones"):
            self.assertIn("<details class='sec' id='%s'>" % anchor, html)  # plegadas: sin el atributo open
        self.assertNotIn("<details class='sec' id='ruta'", html)           # lo que bloquea siempre se ve
        self.assertLess(html.index("id='ruta'"), html.index("id='cxone'"))
        self.assertLess(html.index("id='cxone'"), html.index("id='plan'"))


class InventoryTests(unittest.TestCase):
    def test_zip_is_reviewed_and_inventoried(self):
        d = Path(tempfile.mkdtemp())
        z = d / "logs_1.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr("1_Build.txt", "2026-09-28T17:00:00.0000000Z ##[section]Starting: Build\n2026-09-28T17:00:01.0000000Z ##[section]Finishing: Build\n")
            zf.writestr("reportes/scan.pdf", make_pdf())
            zf.writestr("reportes/foto.png", b"x")
        out = tempfile.mkdtemp()
        main([str(z), "--out-dir", out, "--no-console", "--no-progress", "--formats", "html"])
        html = (run_dir(out) / "reporte.html").read_text(encoding="utf-8")
        self.assertIn("CxOne (PDF)", html)
        self.assertIn("Archivos revisados", html)
        self.assertIn("leído: CxOne (PDF) (3 hallazgos)", html)
        self.assertIn("ignorado: imagen", html)


if __name__ == "__main__":
    unittest.main()

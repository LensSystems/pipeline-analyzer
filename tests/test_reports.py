"""Pruebas de los reportes de herramientas, la ruta para pasar el pipeline y el índice de análisis."""

import json
import tempfile
import unittest
from pathlib import Path

from pipeline_analyzer.cli import main
from pipeline_analyzer.tool_reports import by_rule, discover_reports, short_file

from test_analyzer import failing_log, run_dir

PMD = """<?xml version="1.0"?>
<pmd xmlns="http://pmd.sourceforge.net/report/2.0.0" version="7.0.0">
  <file name="/Users/dev/app/src/main/java/com/acme/ZipService.java">
    <violation beginline="42" endline="42" rule="CloseResource" ruleset="Error Prone" priority="3">Ensure that resources are closed</violation>
    <violation beginline="80" endline="80" rule="CloseResource" ruleset="Error Prone" priority="3">Ensure that resources are closed</violation>
    <violation beginline="10" endline="10" rule="UnusedPrivateField" ruleset="Best Practices" priority="4">Avoid unused fields</violation>
  </file>
</pmd>"""
CHECKSTYLE = """<?xml version="1.0"?>
<checkstyle version="10.0"><file name="/Users/dev/app/src/main/java/com/acme/A.java">
<error line="3" column="1" severity="warning" message="Missing Javadoc" source="com.puppycrawl.tools.checkstyle.checks.javadoc.MissingJavadocMethodCheck"/>
</file></checkstyle>"""
SPOTBUGS = """<?xml version="1.0"?>
<BugCollection version="4.9.8"><BugInstance type="NP_NULL_ON_SOME_PATH" priority="1" category="CORRECTNESS">
<ShortMessage>Possible null pointer dereference</ShortMessage>
<Class classname="com.acme.B"/><SourceLine classname="com.acme.B" sourcepath="com/acme/B.java" start="77" end="77"/></BugInstance></BugCollection>"""
CXONE = json.dumps({"results": [
    {"type": "sast", "id": "1", "severity": "HIGH", "state": "TO_VERIFY", "status": "NEW",
     "data": {"queryName": "Zip_Slip", "nodes": [{"fileName": "/src/main/java/com/acme/Zip.java", "line": 55}]}},
    {"type": "sca", "id": "2", "severity": "MEDIUM", "state": "TO_VERIFY", "status": "NEW",
     "data": {"packageIdentifier": "Maven-org.yaml:snakeyaml-1.33", "recommendedVersion": "2.0"},
     "vulnerabilityDetails": {"cveName": "CVE-2022-1471"}}]})


def make_reports():
    d = Path(tempfile.mkdtemp()) / "target"
    d.mkdir()
    (d / "pmd.xml").write_text(PMD, encoding="utf-8")
    (d / "checkstyle-result.xml").write_text(CHECKSTYLE, encoding="utf-8")
    (d / "spotbugsXml.xml").write_text(SPOTBUGS, encoding="utf-8")
    (d / "cx.json").write_text(CXONE, encoding="utf-8")
    (d / "otro.json").write_text('{"name": "x"}', encoding="utf-8")
    (d / "otro.xml").write_text("<project/>", encoding="utf-8")
    return d


class ToolReportsTest(unittest.TestCase):
    def test_discover_and_parse(self):
        rep = discover_reports([make_reports().parent])
        self.assertEqual(list(rep), ["pmd", "checkstyle", "spotbugs", "cxone"])
        self.assertEqual(rep["pmd"]["total"], 3)
        self.assertEqual(by_rule(rep["pmd"]["items"])[0]["rule"], "CloseResource")
        self.assertEqual(by_rule(rep["pmd"]["items"])[0]["count"], 2)
        self.assertEqual(rep["checkstyle"]["items"][0]["rule"], "MissingJavadocMethod")
        sb = rep["spotbugs"]["items"][0]
        self.assertEqual((sb["rule"], sb["line"], sb["severity"]), ("NP_NULL_ON_SOME_PATH", 77, "HIGH"))
        cx = {i["rule"]: i for i in rep["cxone"]["items"]}
        self.assertEqual(cx["Zip_Slip"]["line"], 55)
        self.assertIn("2.0", cx["CVE-2022-1471"]["message"])

    def test_short_file_hides_local_prefix(self):
        self.assertEqual(short_file("/Users/dev/app/src/main/java/A.java"), "src/main/java/A.java")
        self.assertEqual(short_file("/Users/dev/app/src/main/java/A.java", keep_full=True), "/Users/dev/app/src/main/java/A.java")

    def test_broken_files_are_ignored(self):
        d = Path(tempfile.mkdtemp())
        (d / "pmd.xml").write_text("<pmd><file", encoding="utf-8")
        (d / "x.json").write_text("[{", encoding="utf-8")
        self.assertEqual(discover_reports([d]), {})


class HtmlPlanTest(unittest.TestCase):
    def test_plan_details_and_index(self):
        reports = make_reports()
        out = tempfile.mkdtemp()
        main([str(failing_log()), "--out-dir", out, "--no-console", "--no-progress", "--reports", str(reports), "--formats", "html,full,pdf,pdf-full,md,json"])
        main([str(failing_log()), "--out-dir", out, "--no-console", "--no-progress", "--formats", "html,full,pdf,pdf-full,md,json"])
        first = sorted(d for d in Path(out).iterdir() if d.is_dir())[0]
        page = (first / "reporte.html").read_text(encoding="utf-8")
        self.assertIn("Ruta para pasar el pipeline", page)
        self.assertIn("class='step'", page)
        self.assertLess(page.index("id='ruta'"), page.index("id='hallazgos'"))
        self.assertIn("href='#f-", page)                       # enlaces a cada hallazgo del proyecto
        self.assertIn("id='f-", page)
        self.assertIn("CloseResource", page)                   # regla leída del XML de PMD
        self.assertIn("NP_NULL_ON_SOME_PATH", page)
        self.assertIn("src/main/java/com/acme/ZipService.java:42", page)
        self.assertNotIn("/Users/dev/app", page)               # la versión para compartir no revela la ruta local
        self.assertIn("/Users/dev/app/src/main", (first / "reporte_completo.html").read_text(encoding="utf-8"))
        self.assertNotIn("Ruta para pasar", (first / "reporte.md").read_text(encoding="utf-8"))  # solo HTML
        self.assertNotIn(b"CloseResource", (first / "reporte.pdf").read_bytes())
        # sin --reports se sugiere cómo obtener el detalle
        second = sorted(d for d in Path(out).iterdir() if d.is_dir())[1]
        self.assertIn("--reports", (second / "reporte.html").read_text(encoding="utf-8"))
        # historial con todos los análisis
        self.assertFalse((Path(out) / "index.html").exists())
        index = (Path(out) / "historial-reportes.html").read_text(encoding="utf-8")
        self.assertIn(first.name + "/reporte.html", index)
        self.assertIn(second.name + "/reporte_completo.pdf", index)
        summary = json.loads((first / "resumen.json").read_text(encoding="utf-8"))
        self.assertIn("verdict", summary)
        self.assertNotIn("/var/", json.dumps(summary))

    def test_pdf_has_toc_bookmarks_and_links(self):
        out = tempfile.mkdtemp()
        main([str(failing_log()), "--out-dir", out, "--no-console", "--no-progress", "--formats", "pdf"])
        data = (run_dir(out) / "reporte.pdf").read_bytes()
        self.assertIn(b"/Type /Outlines", data)        # marcadores del visor
        self.assertIn(b"/BaseFont /Helvetica", data)   # letra proporcional
        self.assertIn(b"Contenido", data)              # índice de la primera página
        self.assertIn(b"/Subtype /Link", data)         # enlaces internos
        self.assertIn(b"/Count", data)

    def test_default_outputs_and_caution_text(self):
        out = tempfile.mkdtemp()
        main([str(failing_log()), "--out-dir", out, "--no-console", "--no-progress"])
        names = sorted(p.name for p in run_dir(out).iterdir())
        self.assertNotIn("reporte.html", names)           # el HTML enmascarado ya no se genera por defecto
        for n in ("reporte_completo.html", "reporte.pdf", "reporte_completo.pdf", "reporte.md", "reporte.json"):
            self.assertIn(n, names)
        full_pdf = (run_dir(out) / "reporte_completo.pdf").read_bytes().decode("latin-1")
        self.assertIn("CONFIDENCIAL", full_pdf)
        self.assertNotIn("para compartir usa", full_pdf)
        self.assertNotIn("para compartir usa", (run_dir(out) / "reporte_completo.html").read_text(encoding="utf-8"))

    def test_brand_is_present_but_discreet(self):
        out = tempfile.mkdtemp()
        main([str(failing_log()), "--out-dir", out, "--no-console", "--no-progress"])
        d = run_dir(out)
        self.assertIn("LensSystems", (d / "reporte_completo.html").read_text(encoding="utf-8"))
        self.assertIn("LensSystems", (d / "reporte.md").read_text(encoding="utf-8"))
        self.assertEqual(json.loads((d / "reporte.json").read_text(encoding="utf-8"))["author"], "LensSystems")
        for n in ("reporte.pdf", "reporte_completo.pdf"):
            self.assertIn(b"LensSystems", (d / n).read_bytes())
        self.assertIn("LensSystems", (Path(out) / "historial-reportes.html").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

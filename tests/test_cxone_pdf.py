"""Pruebas de la lectura de PDF de Checkmarx y su cruce con el log y el JSON de CxOne."""

import tempfile
import unittest
import zlib
from pathlib import Path

from pipeline_analyzer.cli import main
from pipeline_analyzer.cxone_pdf import parse_cxone_pdf, parse_text, reconcile
from pipeline_analyzer.pdf_reader import PdfError, extract_text
from pipeline_analyzer.tool_reports import discover_reports

from test_analyzer import failing_log, run_dir
from test_reports import CXONE

TOUNICODE = (b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n1 begincodespacerange <0000> <FFFF> endcodespacerange\n"
             b"1 beginbfrange <0000> <00FF> <0000> endbfrange\nendcmap end end")

# (x, y desde arriba, texto): una celda por fragmento, como las generan los navegadores al imprimir a PDF
ROWS = [
    ("Checkmarx One Scan Report", "Project: acme-app  Branch: develop"),
    ("SAST Results",),
    ("Zip_Slip", "High", "To Verify", "New"),
    ("Source: src/main/java/com/acme/Zip.java:55", "CWE-22"),
    ("Reflected_XSS_All_Clients", "Medium", "Not Exploitable"),
    ("Source: src/main/java/com/acme/Web.java:10",),
    ("SCA Results",),
    ("CVE-2022-1471", "Critical", "org.yaml:snakeyaml:1.33", "Recommended version: 2.0"),
]


def make_pdf(rows=ROWS, compress=True, objstm=False) -> bytes:
    """PDF mínimo: fuente Type0 Identity-H con ToUnicode, y coordenadas volteadas con cm (como Skia/Chromium)."""
    ops = ["q 1 0 0 -1 0 800 cm"]
    y = 40
    for row in rows:
        x = 30
        for cell in row:
            hexs = "".join("%04X" % ord(c) for c in cell)
            ops.append("BT /F1 10 Tf 1 0 0 1 %d %d Tm <%s> Tj ET" % (x, y, hexs))
            x += 40 + 6 * len(cell)
        y += 14
    ops.append("Q")
    content = "\n".join(ops).encode()
    body = zlib.compress(content) if compress else content
    flt = b"/Filter /FlateDecode " if compress else b""
    tu = zlib.compress(TOUNICODE)
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 800] /Resources << /Font << /F1 4 0 R >> >> /Contents 7 0 R >>",
        b"<< /Type /Font /Subtype /Type0 /BaseFont /AAAAAA+Arial /Encoding /Identity-H /DescendantFonts [5 0 R] /ToUnicode 6 0 R >>",
        b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /AAAAAA+Arial /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> >>",
        b"<< /Filter /FlateDecode /Length %d >>\nstream\n" % len(tu) + tu + b"\nendstream",
        b"<< " + flt + b"/Length %d >>\nstream\n" % len(body) + body + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.7\n")
    for i, o in enumerate(objs, 1):
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    out += b"trailer\n<< /Root 1 0 R /Size 8 >>\n%%EOF\n"
    return bytes(out)


def write_pdf(data: bytes, name="cx.pdf") -> Path:
    p = Path(tempfile.mkdtemp()) / name
    p.write_bytes(data)
    return p


class PdfReaderTests(unittest.TestCase):
    def test_extract_type0_with_flipped_coordinates(self):
        pages = extract_text(write_pdf(make_pdf()))
        lines = pages[0].splitlines()
        self.assertEqual(lines[0], "Checkmarx One Scan Report  Project: acme-app  Branch: develop")
        self.assertIn("Zip_Slip", lines[2])
        self.assertTrue(lines[2].index("Zip_Slip") < lines[2].index("High") < lines[2].index("To Verify"))
        self.assertIn("src/main/java/com/acme/Zip.java:55", pages[0])

    def test_uncompressed_stream(self):
        self.assertIn("Zip_Slip", extract_text(write_pdf(make_pdf(compress=False)))[0])

    def test_not_a_pdf(self):
        with self.assertRaises(PdfError):
            extract_text(write_pdf(b"hola"))

    def test_encrypted(self):
        with self.assertRaises(PdfError):
            extract_text(write_pdf(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R /Encrypt 2 0 R >>\n"))


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.rep = parse_text(extract_text(write_pdf(make_pdf())))
        self.by = {i["rule"]: i for i in self.rep["items"]}

    def test_sast_item(self):
        z = self.by["Zip_Slip"]
        self.assertEqual((z["category"], z["severity"], z["state"], z["status"]), ("SAST", "HIGH", "TO_VERIFY", "NEW"))
        self.assertEqual((z["file"], z["line"]), ("src/main/java/com/acme/Zip.java", 55))
        self.assertIn("CWE-22", z["message"])

    def test_sca_item(self):
        c = self.by["CVE-2022-1471"]
        self.assertEqual((c["category"], c["severity"], c["file"]), ("SCA", "CRITICAL", "org.yaml:snakeyaml:1.33"))
        self.assertIn("2.0", c["message"])

    def test_not_exploitable_state(self):
        self.assertEqual(self.by["Reflected_XSS_All_Clients"]["state"], "NOT_EXPLOITABLE")

    def test_meta(self):
        self.assertEqual(self.rep["meta"]["project"], "acme-app")

    def test_severity_heading_and_summary_row(self):
        rep = parse_text(["SAST  1  2  3  4  5\nSAST Results\nHigh Severity (1)\nSQL_Injection\nsrc/A.java:7"])
        self.assertEqual(rep["summary"]["SAST"]["HIGH"], 2)
        self.assertEqual((rep["items"][0]["severity"], rep["items"][0]["line"]), ("HIGH", 7))

    def test_non_checkmarx_pdf_is_ignored(self):
        self.assertIsNone(parse_cxone_pdf(write_pdf(make_pdf([("Receta de cocina", "Ingredientes: harina")]))))

    def test_own_report_is_ignored(self):
        self.assertIsNone(parse_cxone_pdf(write_pdf(make_pdf([("CxOne SAST  FALLO", "pipeline-analyzer 1.4.0  Zip_Slip  High")]))))


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.pdf = parse_cxone_pdf(write_pdf(make_pdf()))

    def test_counts_match(self):
        log = {"engines": {"SAST": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
                           "SCA": {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}}}
        r = reconcile(self.pdf, log)
        self.assertEqual(r["verdict"], "ok")
        med = [c for c in r["counts"] if c["engine"] == "SAST" and c["severity"] == "MEDIUM"][0]
        self.assertEqual((med["pdf"], med["pdf_all"]), (0, 1))

    def test_counts_differ_and_not_exploitable_hint(self):
        log = {"engines": {"SAST": {"critical": 0, "high": 3, "medium": 1, "low": 0, "info": 0}}}
        r = reconcile(self.pdf, log)
        self.assertEqual(r["verdict"], "differences")
        states = {(c["engine"], c["severity"]): c["state"] for c in r["counts"]}
        self.assertEqual(states[("SAST", "HIGH")], "difiere")
        self.assertEqual(states[("SAST", "MEDIUM")], "coincide_con_resueltos")

    def test_no_log_counts(self):
        self.assertEqual(reconcile(self.pdf, {})["verdict"], "nolog")

    def test_against_json(self):
        from pipeline_analyzer.tool_reports import parse_cxone_json
        js = Path(tempfile.mkdtemp()) / "r.json"
        js.write_text(CXONE, encoding="utf-8")
        r = reconcile(self.pdf, {}, parse_cxone_json(js)["items"])
        self.assertEqual(r["items"]["coinciden"], 2)  # Zip_Slip y CVE-2022-1471
        self.assertEqual([i["rule"] for i in r["items"]["solo_pdf"]], ["Reflected_XSS_All_Clients"])


class IntegrationTests(unittest.TestCase):
    def test_discover_and_report(self):
        d = Path(tempfile.mkdtemp())
        (d / "scan.pdf").write_bytes(make_pdf())
        (d / "otro.pdf").write_bytes(make_pdf([("Factura",)]))
        rep = discover_reports([d])
        self.assertEqual(list(rep), ["cxone_pdf"])
        self.assertEqual(rep["cxone_pdf"]["total"], 3)
        self.assertEqual(rep["cxone_pdf"]["sources"], ["scan.pdf"])

    def test_cli_includes_pdf_in_html(self):
        pdf = write_pdf(make_pdf())
        out = Path(tempfile.mkdtemp())
        main([str(failing_log()), "--reports", str(pdf), "--out-dir", str(out), "--no-console", "--no-progress", "--formats", "html,full"])
        html = (run_dir(out) / "reporte_completo.html").read_text(encoding="utf-8")
        self.assertIn("CxOne (PDF)", html)
        self.assertIn("Zip_Slip", html)
        self.assertIn("PDF de Checkmarx", html)

    def test_dump_pdf(self):
        self.assertEqual(main(["--dump-pdf", str(write_pdf(make_pdf()))]), 0)


if __name__ == "__main__":
    unittest.main()

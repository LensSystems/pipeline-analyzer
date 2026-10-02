"""Informe «Scan Report» de Checkmarx One: lectura, soluciones propuestas y cruce con el log."""

import tempfile
import unittest
from pathlib import Path

from pipeline_analyzer.cli import main
from pipeline_analyzer.cxone_fixes import assess, fix_for, sca_fix
from pipeline_analyzer.cxone_pdf import parse_cxone_pdf, parse_text, reconcile
from pipeline_analyzer.extractors import extract
from pipeline_analyzer.pdf_reader import extract_text
from pipeline_analyzer.logparser import parse_run
from pipeline_analyzer.tool_reports import discover_reports

from test_analyzer import _log, _step, run_dir
from test_cxone_summary import SUMMARY

REPORT = """Last Scanned: 29 Sep, 2026 | 5:52 PM
Created: 01 Oct, 2026 | 6:36 PM
Scan Report Scanned Branch Name: task/send-docs
Scanners: SAST, SCA, SCS
Results Summary
0 1 9 3 13
Table of Contents
Filtered By 3
Filtered By
Severity:
Excluded: Information
Result State: To Verify, Confirmed, Urgent
Excluded: Not Exploitable, Proposed Not Exploitable
Scan Information
Project Name:acme-app
Scan Id:11111111-2222-3333-4444-555555555555 Main Branch:N/A
Scan Duration:0h 1m 12s Scan Type:Full Scan
Preset:Default Scanned Branch Name:task/send-docs
LOC Scanned:3588 Groups:G
Files Scanned:53 SCA:Completed
SAST:Completed
SCS:Completed
Scan Tags:
Break SAST Fallo
Page 3 of 21
SAST Vulnerabilities
By Severity
0 1 9 2 12
SAST Scan Results(12)
Cleartext_Submission_of_Sensitive_Information(Type)
Query Path: Java/Java_High_Risk/Cleartext_Submission_of_Sensitive_Information
CWE Id: 319
Total results: 1
Description: Sensitive data is sent over an unsecured channel.
Category:
OWASP Top 10 2021: A2-Cryptographic Failures
Result 1 of 1
High Link Recurrent To Verify Similarity Id: 1300663038 Found First: 26 Aug, 2026 Found Last: 29 Sep, 2026
First Scan ID: aaaa
Source Destination
File Name: /src/main/java/com/acme/config/Data File Name: /src/main/java/com/acme/config/Data
Base.java Base.java
Method: dataSource Method: dataSource
Element: password Element: build
Code Snippets
53 .password(password)
54 .build();
Page 7 of 21
Use_Of_Hardcoded_Password (Type)
Query Path: No query path available
CWE Id: 259
Total results: 3
Description: No query description available
Result 1 of 3
Medium Link Recurrent To Verify Similarity Id: 1 Found First: 26 Aug, 2026 Found Last: 29 Sep, 2026
First Scan ID: bbbb
Source Destination
File Name: /config/app.properties File Name: /config/app.properties
Method: Method:
Element: password Element: password
Code Snippets
106 spring.datasource.password=${DB_PASSWORD}
Result 2 of 3
Medium Link Recurrent To Verify Similarity Id: 2 Found First: 26 Aug, 2026 Found Last: 29 Sep, 2026
First Scan ID: bbbb
Source Destination
File Name: /config/app.properties File Name: /config/app.properties
Method: Method:
Element: password Element: password
Code Snippets
105 #spring.datasource.password=Sup3rS3cret
Result 3 of 3
Medium Link Recurrent To Verify Similarity Id: 2 Found First: 26 Aug, 2026 Found Last: 29 Sep, 2026
First Scan ID: bbbb
Source Destination
File Name: /config/app.properties File Name: /config/app.properties
Method: Method:
Element: password Element: password
Code Snippets
105 #spring.datasource.password=Sup3rS3cret
SCA Vulnerabilities
By Severity
0 0 0 1 1
SCA Scan Results(1 Results)
Maven-org.apache.tomcat.embed:tomcat-embed-core Result)
Package Name: org.apache.tomcat.embed:tomcat-embed-core
Version: 11.0.25
Result 1 of 1 - Vulnerability
Low Recurrent To Verify Outdated: no Found First: 28 Sep, 2026
CVE: CVE-2026-77756
Description: HTTP request smuggling in Apache Tomcat. Users are recommended to upgrade to
version 11.0.26, 10.1.60 or 9.0.122, which fix the issue.
References:Advisory
Categories
Vulnerability Details
Heap_Inspection(CWE 244)
What Is The Risk
Passwords stay in memory.
General Recommendations
* Do not store passwords in plain text.
* Zeroize arrays.
"""


class ScanReportParseTests(unittest.TestCase):
    def setUp(self):
        self.rep = parse_text([REPORT])
        self.items = self.rep["items"]

    def test_info_and_filters(self):
        i = self.rep["info"]
        self.assertEqual((i["project"], i["branch"], i["loc"], i["files"]), ("acme-app", "task/send-docs", "3588", "53"))
        self.assertEqual(i["scanner_status"], {"SCA": "Completed", "SAST": "Completed", "SCS": "Completed"})
        self.assertEqual(i["tags"], ["Break SAST Fallo"])
        self.assertEqual(self.rep["totals"]["TOTAL"], 13)
        self.assertTrue(any("Not Exploitable" in f for f in self.rep["filters"]))

    def test_sast_results_keep_every_result(self):
        self.assertEqual(len(self.items), 5)  # 1 + 3 SAST y 1 SCA: los resultados con igual similarity id no se colapsan
        first = self.items[0]
        self.assertEqual((first["severity"], first["state"], first["status"], first["line"], first["dest_line"]), ("HIGH", "TO_VERIFY", "RECURRENT", 53, 54))
        self.assertEqual(first["file"], "/src/main/java/com/acme/config/DataBase.java")  # ruta partida en dos líneas
        self.assertEqual(first["age_days"], 34)

    def test_sca_item_and_fix_version(self):
        sca = self.items[-1]
        self.assertEqual((sca["category"], sca["rule"], sca["fix_version"]), ("SCA", "CVE-2026-77756", "11.0.26"))
        self.assertIn("<tomcat.version>11.0.26</tomcat.version>", sca_fix(sca)["code"])

    def test_vulnerability_details(self):
        h = self.rep["queries"]["Heap_Inspection"]
        self.assertEqual(h["cwe"], "244")
        self.assertEqual(len(h["recommendations"]), 2)
        self.assertEqual(self.rep["queries"]["Cleartext_Submission_of_Sensitive_Information"]["categories"]["OWASP Top 10 2021"], "A2-Cryptographic Failures")

    def test_assessment_of_hardcoded_password(self):
        pw = [i for i in self.items if i["rule"] == "Use_Of_Hardcoded_Password"]
        self.assertEqual([assess(i)[0] for i in pw], ["falso_positivo", "real", "real"])
        self.assertIsNotNone(fix_for("Heap_Inspection"))
        self.assertIsNotNone(fix_for("Unknown_Query", "89"))


def log():
    return _log(_step("CxOne Scan [SAST + SCA + SCS]", "Branch name: task/send-docs", *SUMMARY))


class ScanReportReconcileTests(unittest.TestCase):
    def test_markdown_file_is_discovered_and_matched(self):
        d = Path(tempfile.mkdtemp())
        (d / "scan.md").write_text(REPORT, encoding="utf-8")
        (d / "README.md").write_text("# nada\n", encoding="utf-8")
        found = discover_reports([d])
        self.assertEqual(found["cxone_pdf"]["sources"], ["scan.md"])
        self.assertEqual(found["cxone_pdf"]["total"], 5)
        pdf = parse_cxone_pdf(d / "scan.md")
        cx = extract(parse_run(log()))["cxone"]
        r = reconcile(pdf, cx)
        by = {x["field"]: x["state"] for x in r["identity"]}
        self.assertEqual(by["Rama"], "igual")
        self.assertEqual(by["Hora del escaneo"], "igual")
        self.assertEqual(by["Estado SCS"], "distinto")  # el log dice Partial y el reporte Completed

    def test_report_renders_findings_with_solutions(self):
        d = Path(tempfile.mkdtemp())
        (d / "scan.md").write_text(REPORT, encoding="utf-8")
        out = tempfile.mkdtemp()
        main([str(log()), "--reports", str(d / "scan.md"), "--out-dir", out, "--no-console", "--no-progress", "--formats", "html,md,pdf"])
        run = run_dir(out)
        html = (run / "reporte.html").read_text(encoding="utf-8")
        for text in ("Hallazgos del reporte de Checkmarx", "Cifrar el canal", "bloquea el breaker", "probable falso positivo", "problema real",
                     "&lt;tomcat.version&gt;11.0.26&lt;/tomcat.version&gt;", "¿Mismo escaneo?"):
            self.assertIn(text, html)
        self.assertIn("Cifrar el canal", (run / "reporte.md").read_text(encoding="utf-8"))
        pdf_text = "\n".join(extract_text(run / "reporte.pdf"))
        self.assertIn("Hallazgos de Checkmarx", pdf_text)


if __name__ == "__main__":
    unittest.main()

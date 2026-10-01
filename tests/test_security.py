"""Pruebas de las validaciones de seguridad. Ejecutar: python -m unittest discover -s tests"""

import ast
import json
import tempfile
import unittest
from pathlib import Path

from pipeline_analyzer.cli import main
from pipeline_analyzer.extractors import extract
from pipeline_analyzer.logparser import parse_log
from pipeline_analyzer.rules import evaluate
from pipeline_analyzer.security import (dependency_inventory, find_secrets, is_vulnerable, manifest_checks,
                                        mask_infra, redact)

from test_analyzer import _log, _step, run_dir

# Valores de prueba con formato realista, no son credenciales reales.
FAKE_GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_PWD = "Sup3rS3creta!"

MANIFEST = """---
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry.local/app:latest
          ports:
            - containerPort: 8080
            - containerPort: 8778
              name: jolokia
          env:
            - name: JAVA_TOOL_OPTIONS
              value: -agentlib:jdwp=transport=dt_socket,server=y,address=5005
---
apiVersion: v1
kind: ConfigMap
data:
  application.properties: |
    spring.datasource.password=%s
    constants.api.password=${AMQ_PASSWORD}
    management.endpoints.web.exposure.include=health,env,heapdump
    logging.level.root=DEBUG
""" % FAKE_PWD


def insecure_log():
    return _log(
        ["##[section]Starting: Build Block + Security"]
        + _step("Set pipeline values",
                "export GITHUB_TOKEN=" + FAKE_GH,
                "aws configure set aws_access_key_id " + FAKE_AWS,
                "git clone https://ci-user:" + FAKE_PWD + "@git.local/repo.git",
                "curl -k https://tools.local/setup.sh | bash",
                "-- Clone repo *** , branch master , on pipeline-templates",
                "Downloading from central: http://repo.local/maven2/org/yaml/snakeyaml/1.33/snakeyaml-1.33.jar")
        + _step("TMAS - Download", "wget https://tools.local/tmas.tar.gz", "-- download and unpack tmas")
        + _step("Validate manifest - Location", *MANIFEST.splitlines())
        + _step("Sonarqube - Run", "[INFO] Communicating with SonarQube Server 10.2.0.77647",
                "Running on ... registry.local/ubi9/openjdk-17:latest")
        + _step("ReportBugs - PMD", "OCI runtime exec failed: possible container breakout detected: unknown")
        + ["##[section]Finishing: Build Block + Security"]
    )


class FullReportTest(unittest.TestCase):
    """reporte.html oculta secretos; reporte_completo.html los muestra (solo uso local)."""

    def test_shareable_vs_full(self):
        log = _log(_step("Script", "export TOKEN=%s" % FAKE_GH, "curl http://intranet.local/x --user admin:%s" % FAKE_PWD,
                         "conectando a 10.20.30.40 con dev@empresa.com"))
        out = tempfile.mkdtemp()
        rc = main([str(log), "--out-dir", out, "--no-console", "--no-progress", "--formats", "html,full,pdf,pdf-full,md,json"])
        self.assertEqual(rc, 0)
        shared = (run_dir(out) / "reporte.html").read_text(encoding="utf-8")
        full = (run_dir(out) / "reporte_completo.html").read_text(encoding="utf-8")
        for name in ("reporte.md", "reporte.json"):
            self.assertNotIn(FAKE_GH, (run_dir(out) / name).read_text(encoding="utf-8"), name)
        self.assertNotIn(FAKE_GH, shared)
        self.assertNotIn(FAKE_PWD, shared)
        self.assertIn(FAKE_GH, full)
        self.assertIn("versión completa", full)
        self.assertIn("overflow-wrap:anywhere", shared)  # ajuste fluido en ambos
        self.assertNotIn("versión completa", shared)

    def test_pdf_versions(self):
        log = _log(_step("Script", "export TOKEN=%s" % FAKE_GH))
        out = tempfile.mkdtemp()
        main([str(log), "--out-dir", out, "--no-console", "--no-progress"])
        shared = (run_dir(out) / "reporte.pdf").read_bytes()
        full = (run_dir(out) / "reporte_completo.pdf").read_bytes()
        for data in (shared, full):
            self.assertTrue(data.startswith(b"%PDF-1.4"))
            self.assertTrue(data.rstrip().endswith(b"%%EOF"))
            self.assertIn(b"/Type /Catalog", data)
        self.assertNotIn(FAKE_GH.encode(), shared)
        self.assertIn(FAKE_GH.encode(), full)
        self.assertIn(b"NO COMPARTIR", full)
        self.assertNotIn(b"NO COMPARTIR", shared)

    def test_json_never_has_raw_values(self):
        log = _log(_step("Script", "export TOKEN=%s" % FAKE_GH))
        out = tempfile.mkdtemp()
        main([str(log), "--out-dir", out, "--no-console", "--no-progress", "--no-redact"])
        self.assertNotIn(FAKE_GH, (run_dir(out) / "reporte.json").read_text(encoding="utf-8"))


class SecretsTest(unittest.TestCase):
    def test_detect_and_redact(self):
        text = "token=%s key=%s url=https://u:%s@h/x" % (FAKE_GH, FAKE_AWS, FAKE_PWD)
        kinds = {k for k, _ in find_secrets(text)}
        self.assertTrue({"github_token", "aws_access_key", "url_credentials"} <= kinds)
        red = redact(text)
        for secret in (FAKE_GH, FAKE_AWS, FAKE_PWD):
            self.assertNotIn(secret, red)
        self.assertEqual(find_secrets(red), [])

    def test_placeholders_are_not_secrets(self):
        for safe in ("spring.datasource.password=${DB_PASSWORD}", "password: ***", "Clone repo *** , branch master",
                     "Username and Password not accepted", "api_key=<TOKEN_3>"):
            self.assertEqual(find_secrets(safe), [], safe)

    def test_mask_infra(self):
        out = mask_infra("mail ops@empresa.mx from 10.20.30.40 via https://nexus.interno.local/repo")
        self.assertNotIn("empresa.mx", out)
        self.assertNotIn("10.20.30.40", out)
        self.assertNotIn("nexus.interno.local", out)


class SupplyChainTest(unittest.TestCase):
    def test_versions(self):
        self.assertTrue(is_vulnerable("1.33", ["2.0"]))
        self.assertFalse(is_vulnerable("2.2", ["2.0"]))
        self.assertTrue(is_vulnerable("5.17.2", ["5.15.16", "5.16.7", "5.17.6", "5.18.3"]))
        self.assertFalse(is_vulnerable("6.1.0", ["5.15.16", "5.16.7", "5.17.6", "5.18.3"]))
        self.assertFalse(is_vulnerable("4.1.100.Final", ["4.1.100"]))

    def test_inventory_from_maven_urls(self):
        inv = dependency_inventory("GET https://repo/maven2/org/yaml/snakeyaml/1.33/snakeyaml-1.33.jar")
        self.assertEqual(inv["snakeyaml:1.33"]["group"], "org.yaml")


class ManifestTest(unittest.TestCase):
    def test_manifest(self):
        m = manifest_checks(MANIFEST)
        self.assertFalse(m["security_context"])
        self.assertEqual(set(m["admin_ports"]), {"Jolokia (8778)", "JDWP debug"})
        self.assertEqual(m["mutable_images"], ["registry.local/app:latest"])
        self.assertEqual(m["configmap_cleartext_secrets"], ["spring.datasource.password"])
        self.assertEqual(m["configmap_secret_placeholders"], 1)
        self.assertEqual(set(m["actuator_risky"]), {"env", "heapdump"})
        self.assertEqual(m["debug_logging"], ["logging.level.root=DEBUG"])


class RulesSecurityTest(unittest.TestCase):
    def test_findings(self):
        ids = {f.id for f in evaluate(extract(parse_log(insecure_log())))}
        for expected in ("SEC_SECRETS_IN_LOG", "SEC_TLS_DISABLED", "SEC_PIPE_TO_SHELL", "SEC_INSECURE_HTTP",
                         "SEC_VULNERABLE_DEPS", "SEC_CONTAINER_ISOLATION", "SEC_LATEST_IMAGES", "SEC_MUTABLE_REPOS",
                         "SEC_UNVERIFIED_DOWNLOADS", "SEC_SONAR_UNSUPPORTED", "K8S_SECURITY_CONTEXT",
                         "K8S_ADMIN_PORTS", "K8S_CONFIGMAP_SECRETS", "K8S_ACTUATOR", "K8S_DEBUG_LOGGING",
                         "K8S_MUTABLE_IMAGE"):
            self.assertIn(expected, ids)

    def test_reports_never_contain_secrets(self):
        out = tempfile.mkdtemp()
        main([str(insecure_log()), "--out-dir", out, "--no-console", "--no-progress", "--formats", "html,full,pdf,pdf-full,md,json"])
        for p in run_dir(out).iterdir():
            if p.name.startswith("reporte_completo"):  # únicas salidas sin enmascarar (uso local)
                continue
            text = p.read_bytes().decode("latin-1")  # sirve para texto y PDF
            for secret in (FAKE_GH, FAKE_AWS, FAKE_PWD):
                self.assertNotIn(secret, text, p.name)
        json.loads((run_dir(out) / "reporte.json").read_text(encoding="utf-8"))  # la redacción no rompe el JSON


class NoNetworkTest(unittest.TestCase):
    """Garantiza que el analizador no importe módulos de red: los logs nunca salen del equipo."""

    FORBIDDEN = {"socket", "ssl", "urllib", "http", "requests", "httpx", "ftplib", "smtplib", "telnetlib",
                 "xmlrpc", "asyncio", "subprocess", "webbrowser"}

    def test_no_network_imports(self):
        pkg = Path(__file__).resolve().parent.parent / "pipeline_analyzer"
        for src in pkg.glob("*.py"):
            tree = ast.parse(src.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    names = [node.module]
                for n in names:
                    if (src.name, n) in self.ALLOWED:
                        continue
                    self.assertNotIn(n.split(".")[0], self.FORBIDDEN, "%s importa %s" % (src.name, n))

    # Única excepción: abrir el reporte HTML local con el navegador al terminar el modo interactivo.
    ALLOWED = {("interactive.py", "webbrowser")}

    def test_webbrowser_only_opens_local_files(self):
        src = (Path(__file__).resolve().parent.parent / "pipeline_analyzer" / "interactive.py").read_text(encoding="utf-8")
        calls = [l.strip() for l in src.splitlines() if "webbrowser.open" in l]
        self.assertEqual(calls, ["webbrowser.open(Path(html).resolve().as_uri())"])


if __name__ == "__main__":
    unittest.main()

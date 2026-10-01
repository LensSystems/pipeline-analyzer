"""Modo interactivo por consola y avance hacia la ventana gráfica (sin abrir ventanas)."""

import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from pipeline_analyzer import cli
from pipeline_analyzer.interactive import Cancelled, gather_console
from pipeline_analyzer.progress import Progress

from test_folders import make_download


def _answers(*values):
    it = iter(values)
    return lambda prompt="": next(it)


class ConsolePromptsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.main = make_download(self.tmp / "actual", "200")
        self.prev = make_download(self.tmp / "anterior", "100")
        self.pom = self.tmp / "pom.xml"
        self.pom.write_text("<project xmlns='http://maven.apache.org/POM/4.0.0'></project>", encoding="utf-8")

    def test_gather_all(self):
        out = io.StringIO()
        sel = gather_console(_answers("/no/existe", '"%s"' % self.main, "s", str(self.prev), "n", "s", str(self.pom)), out)
        self.assertEqual(sel["logs"], [str(self.prev), str(self.main)])  # comparación primero, principal al final
        self.assertEqual(sel["pom"], str(self.pom))
        self.assertIn("No existe", out.getvalue())

    def test_gather_only_main(self):
        sel = gather_console(_answers(str(self.main), "", ""), io.StringIO())
        self.assertEqual((sel["logs"], sel["pom"]), ([str(self.main)], None))

    @unittest.skipIf(sys.platform.startswith("win"), "en Windows la barra invertida es separador de ruta, no escape de espacios")
    def test_dragged_path_with_escaped_spaces(self):
        spaced = make_download(self.tmp / "con espacios", "300")
        sel = gather_console(_answers(str(spaced).replace(" ", "\\ "), "n", "n"), io.StringIO())
        self.assertEqual(sel["logs"], [str(spaced)])

    def test_cancel(self):
        def eof(prompt=""):
            raise EOFError
        with self.assertRaises(Cancelled):
            gather_console(eof, io.StringIO())

    def test_main_without_args_uses_prompts(self):
        answers = _answers(str(self.main), "s", str(self.prev), "n", "n")
        with mock.patch("builtins.input", answers), mock.patch.object(cli, "gui_status", return_value=(False, "sin pantalla", "n/a")):
            rc = cli.main(["--no-gui", "--no-console", "--no-progress"])
        self.assertEqual(rc, 0)
        report = sorted(d for d in (self.main.parent / "reporte_pipeline").iterdir() if d.is_dir())[-1] / "reporte.json"  # junto al log principal
        data = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual([r["metrics"]["meta"]["build_id"] for r in data["runs"]], ["100", "200"])

    def test_no_args_without_terminal_or_gui(self):
        with mock.patch.object(cli, "gui_status", return_value=(False, "sin pantalla", "n/a")), \
                mock.patch("sys.stdin", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
            self.assertEqual(cli.main([]), 2)


class ListenerTest(unittest.TestCase):
    def test_listener_receives_updates(self):
        events = []
        p = Progress(4, enabled=False, listener=lambda pct, stage, detail, msg=None: events.append((pct, stage, detail, msg)))
        p.stage("Leyendo")
        p.advance("archivo 1")
        p.log("listo")
        p.close("fin")
        self.assertEqual(events[0][1], "Leyendo")
        self.assertEqual(events[1][:3], (0.25, "Leyendo", "archivo 1"))
        self.assertEqual(events[2][3], "listo")
        self.assertEqual(events[-1][0], 1.0)


if __name__ == "__main__":
    unittest.main()

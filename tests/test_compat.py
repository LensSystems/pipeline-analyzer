"""Compatibilidad entre plataformas (sin depender del sistema donde corren las pruebas)."""

import io
import unittest
from unittest import mock

from pipeline_analyzer import cli, compat
from pipeline_analyzer.interactive import _clean_path
from pipeline_analyzer.progress import Progress


class DistroTest(unittest.TestCase):
    def test_os_release(self):
        cases = {
            'ID=ubuntu\nID_LIKE=debian\n': "debian",
            'ID="rocky"\nID_LIKE="rhel centos fedora"\n': "rhel",
            'ID=fedora\n': "fedora",
            'ID=arch\n': "arch",
            'ID="opensuse-leap"\nID_LIKE="suse opensuse"\n': "suse",
            'ID=alpine\n': "alpine",
            'ID=gentoo\n': "desconocida",
        }
        for text, expected in cases.items():
            self.assertEqual(compat.linux_distro(text), expected, text)


class TkHintTest(unittest.TestCase):
    def test_hints_by_install(self):
        self.assertIn("brew install python-tk@", compat.tk_install_hint("homebrew"))
        self.assertIn("Tk 8.5", compat.tk_install_hint("apple"))
        self.assertIn("tcl/tk and IDLE", compat.tk_install_hint("windows"))
        self.assertIn("conda install tk", compat.tk_install_hint("conda"))

    def test_hints_linux(self):
        with mock.patch.object(compat, "IS_LINUX", True):
            self.assertEqual(compat.tk_install_hint("linux-system", "debian"), "sudo apt install python3-tk")
            self.assertIn("dnf install python3-tkinter", compat.tk_install_hint("linux-system", "fedora"))
            self.assertIn("pacman -S tk", compat.tk_install_hint("linux-system", "arch"))

    def test_tk_status_missing(self):
        with mock.patch.dict("sys.modules", {"tkinter": None}):
            ok, why, fix = compat.tk_status()
        self.assertFalse(ok)
        self.assertIn("tkinter no está instalado", why)
        self.assertTrue(fix)

    def test_tk_status_linux_without_display(self):
        with mock.patch.object(compat, "IS_LINUX", True), mock.patch.object(compat, "IS_MAC", False), \
                mock.patch.dict("os.environ", {}, clear=True):
            ok, why, _ = compat.tk_status()
        self.assertFalse(ok)
        self.assertIn("DISPLAY", why)


class ConsoleTest(unittest.TestCase):
    def test_unicode_detection(self):
        utf8 = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        cp1252 = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        self.assertFalse(compat.fancy_unicode(cp1252))
        with mock.patch.object(compat, "IS_WINDOWS", False):
            self.assertTrue(compat.fancy_unicode(utf8))
        with mock.patch.object(compat, "IS_WINDOWS", True), mock.patch.dict("os.environ", {}, clear=True):
            self.assertFalse(compat.fancy_unicode(utf8))   # conhost clásico
        with mock.patch.object(compat, "IS_WINDOWS", True), mock.patch.dict("os.environ", {"WT_SESSION": "1"}):
            self.assertTrue(compat.fancy_unicode(utf8))    # Windows Terminal

    def test_progress_ascii_on_legacy_console(self):
        cp = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        p = Progress(2, stream=cp)
        self.assertFalse(p.unicode)
        self.assertEqual(p.frames, "|/-\\")
        p.stage("Leyendo")
        p.close("fin")
        cp.flush()
        self.assertIn(b"> Leyendo", cp.buffer.getvalue())

    def test_console_safe_cp1252(self):
        cp = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
        self.assertEqual(compat.console_safe("a → b ✔ año", cp), "a -> b OK año")
        utf8 = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        self.assertEqual(compat.console_safe("a → b", utf8), "a → b")

    def test_no_color_when_not_tty(self):
        self.assertFalse(compat.ansi_supported(io.StringIO()))


class PathTest(unittest.TestCase):
    def test_posix_drag_and_drop(self):
        self.assertEqual(_clean_path("'/Users/ana/Mis logs/logs_1'", windows=False), "/Users/ana/Mis logs/logs_1")
        self.assertEqual(_clean_path("/Users/ana/Mis\\ logs/logs_1 ", windows=False), "/Users/ana/Mis logs/logs_1")

    def test_windows_paths(self):
        self.assertEqual(_clean_path('"C:\\Users\\ana\\Mis logs\\logs_1"', windows=True), "C:\\Users\\ana\\Mis logs\\logs_1")
        self.assertEqual(_clean_path("& 'C:\\Descargas\\logs_1.zip'", windows=True), "C:\\Descargas\\logs_1.zip")
        self.assertEqual(_clean_path("C:\\a\\ b", windows=True), "C:\\a\\ b")  # la barra invertida es separador


class CliCompatTest(unittest.TestCase):
    def test_doctor(self):
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            self.assertEqual(cli.main(["--doctor"]), 0)
        text = out.getvalue()
        for key in ("Python", "Ventanas (tkinter)", "Colores ANSI", "Instalación"):
            self.assertIn(key, text)

    def test_old_python_rejected(self):
        err = io.StringIO()
        with mock.patch.object(compat, "python_ok", return_value=False), mock.patch("sys.stderr", err):
            self.assertEqual(cli.main(["x"]), 3)
        self.assertIn("Se requiere Python 3.8", err.getvalue())

    def test_gui_main_without_console_or_gui_notifies(self):
        with mock.patch.object(cli, "gui_status", return_value=(False, "sin tkinter", "instala tk")), \
                mock.patch("sys.stdin", io.StringIO()), mock.patch.object(compat, "notify") as notify:
            self.assertEqual(cli.gui_main(), 2)
        self.assertIn("sin tkinter", notify.call_args[0][1])

    def test_gui_flag_with_paths_falls_back_to_paths(self):
        err = io.StringIO()
        with mock.patch.object(cli, "gui_status", return_value=(False, "sin pantalla", "ssh -X")), \
                mock.patch.object(cli, "_run", return_value=0) as run, mock.patch("sys.stderr", err), \
                mock.patch("sys.stdin", io.StringIO()):
            self.assertEqual(cli.main(["logs_1", "--gui"]), 0)
        self.assertEqual(run.call_args[0][0].logs, ["logs_1"])


if __name__ == "__main__":
    unittest.main()

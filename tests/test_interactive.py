"""Modo interactivo por consola y avance hacia la ventana gráfica (sin abrir ventanas)."""

import io
import os
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from pipeline_analyzer import cli
from pipeline_analyzer.interactive import (Cancelled, compare_limit_reached, detect_yaml, gather_console, sync_yaml,
                                           yaml_form_states, yaml_options, yaml_return_state)
from pipeline_analyzer.progress import Progress

from test_folders import make_download


def _answers(*values):
    it = iter(values)
    return lambda prompt="": next(it)


class DetectYamlTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def _zip(self, name, entries):
        path = self.tmp / name
        with zipfile.ZipFile(str(path), "w") as archive:
            for entry, content in entries:
                archive.writestr(entry, content)
        return path

    def test_directory_without_yaml_and_nested_yaml_extensions(self):
        folder = self.tmp / "logs"
        folder.mkdir()
        (folder / "pipeline.log").write_text("log", encoding="utf-8")
        self.assertIsNone(detect_yaml(str(folder)))
        nested = folder / "sub"
        nested.mkdir()
        (nested / "pipeline.YML").write_text("yaml", encoding="utf-8")
        self.assertEqual(detect_yaml(str(folder)), ".yml")
        (folder / "other.yaml").write_text("yaml", encoding="utf-8")
        self.assertEqual(detect_yaml(str(folder)), ".yaml")

    def test_zip_without_yaml_and_nested_yaml_extensions(self):
        archive = self._zip("logs.zip", [("pipeline.log", "log")])
        self.assertIsNone(detect_yaml(str(archive)))
        archive = self._zip("nested.zip", [("sub/pipeline.yml", "yaml")])
        self.assertEqual(detect_yaml(str(archive)), ".yml")
        archive = self._zip("both.zip", [("sub/pipeline.yml", "yaml"), ("pipeline.yaml", "yaml")])
        self.assertEqual(detect_yaml(str(archive)), ".yaml")

    def test_non_zip_file_corrupt_zip_and_missing_path(self):
        log = self.tmp / "pipeline.log"
        log.write_text("log", encoding="utf-8")
        corrupt = self.tmp / "broken.zip"
        corrupt.write_bytes(b"not a zip")
        self.assertIsNone(detect_yaml(str(log)))
        self.assertIsNone(detect_yaml(str(corrupt)))
        self.assertIsNone(detect_yaml(str(self.tmp / "missing")))


class YamlOptionsTest(unittest.TestCase):
    def test_empty_and_main_only_options(self):
        detect = {"main": ".yaml", "cmp": ".yml"}.get
        self.assertEqual(yaml_options(None, [], lambda path: detect(path)), [])
        self.assertEqual(yaml_options("main", [], lambda path: detect(path)), [
            ("main", "main", "¿Quieres agregar el archivo .yaml al análisis?")])

    def test_main_and_two_comparisons_use_positions_from_full_list(self):
        extensions = {"main": ".yaml", "first": ".yml", "second": None, "third": ".yaml"}
        options = yaml_options("main", ["first", "second", "third"], extensions.get)
        self.assertEqual(options, [
            ("main", "main", "¿Quieres agregar el archivo .yaml al análisis?"),
            ("cmp:first", "first", "¿Quieres agregar el archivo .yml al análisis de comparación 1?"),
            ("cmp:third", "third", "¿Quieres agregar el archivo .yaml al análisis de comparación 3?"),
        ])

    def test_single_comparison_has_no_number_and_counts_without_main(self):
        options = yaml_options(None, ["previous"], lambda path: ".yml")
        self.assertEqual(options, [
            ("cmp:previous", "previous", "¿Quieres agregar el archivo .yml al análisis de comparación?")])


class SyncYamlTest(unittest.TestCase):
    def test_single_option_keeps_state_unchanged(self):
        states = {"main": (True, True)}
        self.assertEqual(sync_yaml("main", states), states)

    def test_marking_links_two_options_and_unmarking_releases_them(self):
        states = {"main": (True, True), "cmp:a": (False, True)}
        self.assertEqual(sync_yaml("main", states), {"main": (True, True), "cmp:a": (True, False)})
        states = {"main": (True, False), "cmp:a": (False, True)}
        self.assertEqual(sync_yaml("cmp:a", states), {"main": (False, True), "cmp:a": (False, True)})

    def test_marking_links_three_options_and_unmarking_releases_them(self):
        states = {"main": (False, True), "cmp:a": (True, True), "cmp:b": (False, True)}
        self.assertEqual(sync_yaml("cmp:a", states), {
            "main": (True, False), "cmp:a": (True, True), "cmp:b": (True, False)})
        states["cmp:a"] = (False, True)
        self.assertEqual(sync_yaml("cmp:a", states), {
            "main": (False, True), "cmp:a": (False, True), "cmp:b": (False, True)})


class YamlFormStateTest(unittest.TestCase):
    def test_state_is_initialized_preserved_and_removed_with_visible_options(self):
        options = [("main", "/logs/current", "main"), ("cmp:/logs/old", "/logs/old", "old")]
        self.assertEqual(yaml_form_states(options, {}), {
            "main": (False, True), "cmp:/logs/old": (False, True)})
        self.assertEqual(yaml_form_states(options, {"main": (True, True), "removed": (True, True)}), {
            "main": (True, True), "cmp:/logs/old": (True, False)})
        # La clave main es estable, pero una ruta principal nueva recibe estado sin marcar.
        self.assertEqual(yaml_form_states([("main", "/logs/new", "main")], {"main": (True, True)},
                                          {"main": "/logs/current"}), {"main": (False, True)})
        # Al quitar la opción seleccionada, las restantes vuelven a estar desmarcadas y habilitadas.
        remaining = [options[0], ("cmp:/logs/new", "/logs/new", "new")]
        self.assertEqual(yaml_form_states(remaining, {
            "main": (False, False), "cmp:/logs/old": (True, True), "cmp:/logs/new": (False, False)}), {
            "main": (False, True), "cmp:/logs/new": (False, True)})

    def test_return_selection_uses_exact_log_paths_for_go_and_compare(self):
        logs = ["/logs/old/", "/logs/current"]
        options = [("cmp:/logs/old/", logs[0], "old"), ("main", logs[1], "main")]
        states = {"cmp:/logs/old/": (True, False), "main": (True, True)}
        result = yaml_return_state(logs, options, states)
        self.assertEqual(result, {"/logs/old/": True, "/logs/current": True})
        self.assertEqual(list(result), logs)

    def test_compare_limit_is_reached_at_maximum(self):
        self.assertFalse(compare_limit_reached(0))
        self.assertFalse(compare_limit_reached(1))
        self.assertTrue(compare_limit_reached(2))


class PlatformStyleTest(unittest.TestCase):
    def _style(self, platform, build=None):
        from pipeline_analyzer.interactive import platform_style
        wv = mock.Mock(return_value=mock.Mock(build=build)) if build is not None else None
        with mock.patch.object(sys, "platform", platform), mock.patch.object(sys, "getwindowsversion", wv, create=True):
            return platform_style()

    def test_macos_uses_aqua_and_primary_on_the_right(self):
        st = self._style("darwin")
        self.assertEqual((st["os"], st["theme"], st["primary_right"]), ("mac", "aqua", True))

    def test_windows_11_and_10_are_told_apart_by_build(self):
        w11, w10 = self._style("win32", 22631), self._style("win32", 19045)
        self.assertEqual((w11["os"], w11["theme"], w11["primary_right"]), ("win11", "vista", False))
        self.assertEqual(w11["families"][0], "Segoe UI Variable Text")
        self.assertEqual((w10["os"], w10["families"]), ("win10", ("Segoe UI",)))

    def test_linux_falls_back_to_clam(self):
        self.assertEqual(self._style("linux")["theme"], "clam")


def _real_windows_enabled() -> bool:
    """Las pruebas de ventanas reales son opcionales: dependen de la pantalla, del foco y del escalado de cada sistema."""
    return os.environ.get("PIPELINE_ANALYZER_GUI_TESTS") == "1"


def _gui_or_skip(testcase):
    """Ventana real de tkinter, solo si se pide (PIPELINE_ANALYZER_GUI_TESTS=1) y hay pantalla; siempre se cierra."""
    from pipeline_analyzer.interactive import Gui, gui_available
    if not _real_windows_enabled():
        testcase.skipTest("ventanas reales desactivadas (PIPELINE_ANALYZER_GUI_TESTS=1 para activarlas)")
    if not gui_available():
        testcase.skipTest("sin entorno gráfico")
    try:
        g = Gui()
    except Exception as exc:
        testcase.skipTest("no se pudo abrir la ventana: %s" % exc)
    testcase.addCleanup(g.destroy)
    return g


class WindowTest(unittest.TestCase):
    def setUp(self):
        self.g = _gui_or_skip(self)

    def test_state_colors_meet_contrast_on_both_appearances(self):
        from pipeline_analyzer.interactive import MAC_DARK, MAC_LIGHT

        def lum(h):
            r, g, b = [int(h[i:i + 2], 16) / 255 for i in (1, 3, 5)]
            f = lambda c: c / 12.92 if c <= .03928 else ((c + .055) / 1.055) ** 2.4
            return .2126 * f(r) + .7152 * f(g) + .0722 * f(b)

        def ratio(a, b):
            hi, lo = max(lum(a), lum(b)), min(lum(a), lum(b))
            return (hi + .05) / (lo + .05)

        for key in ("ok", "bad"):
            self.assertGreaterEqual(ratio(MAC_LIGHT[key], "#ececec"), 4.5)
            self.assertGreaterEqual(ratio(MAC_DARK[key], "#2b2b2b"), 4.5)

    def test_text_rewraps_to_the_window_width(self):
        g = self.g
        g._clear("x")
        g._text("Título", bold=True)
        g._text("descripción larga " * 30, small=True)
        g.root.geometry("980x520")
        g.root.update()
        g.root.update()
        self.assertGreater(int(str(g._wrapped[0][0].cget("wraplength"))), 700)

    def test_single_form_collects_everything_and_blocks_analyze_without_a_log(self):
        g = self.g
        actions = iter(["pom", "main:dir", "cmp:dir", "rep:files", "rm:rep:0", "go"])
        disabled_seen = []
        g._choice = lambda opts, cancel=None, disabled=(): disabled_seen.append(disabled) or next(actions)
        g._open = lambda kind, title, ft=None: "/logs/actual" if "analizar" in title else "/logs/anterior"
        g.ask_pom = lambda: "/p/pom.xml"
        g._open_many = lambda title: ["/r/a.pdf", "/r/b.xml"]
        sel = g.gather()
        self.assertEqual(disabled_seen[0], ("go",))        # sin log principal no se puede analizar
        self.assertEqual(disabled_seen[-1], ())
        self.assertEqual(sel, {"logs": ["/logs/anterior", "/logs/actual"], "main": "/logs/actual", "pom": "/p/pom.xml",
                               "reports": ["/r/b.xml"], "compare_only": False})

    def test_compare_only_button_appears_with_main_and_comparison_and_skips_pom_and_reports(self):
        g = self.g
        shown = []
        actions = iter(["main:dir", "pom", "cmp:dir", "cmp"])
        g._choice = lambda opts, cancel=None, disabled=(): shown.append([o[0] for o in opts]) or next(actions)
        g._open = lambda kind, title, ft=None: "/logs/actual" if "analizar" in title else "/logs/anterior"
        g.ask_pom = lambda: "/p/pom.xml"
        sel = g.gather()
        self.assertEqual(shown[:3], [["Analizar", "Cancelar"]] * 2 + [["Analizar", "Cancelar"]])  # sin comparación no se ofrece
        self.assertEqual(shown[3], ["Analizar", "Solo comparación", "Cancelar"])
        self.assertEqual(sel, {"logs": ["/logs/anterior", "/logs/actual"], "main": "/logs/actual", "pom": None, "reports": [],
                               "compare_only": True})

    def test_same_file_cannot_be_used_in_two_sections_but_same_name_elsewhere_can(self):
        g = self.g
        warnings = []
        g._warn = lambda title, detail: warnings.append(detail)
        picks = iter(["/logs/a.txt", "/logs/a.txt", "/otra/a.txt"])   # principal, comparación repetida, comparación en otra ruta
        actions = iter(["main:file", "cmp:file", "cmp:file", "pom", "rep:files", "go"])
        g._choice = lambda opts, cancel=None, disabled=(): next(actions)
        g._open = lambda kind, title, ft=None: next(picks)
        g.ask_pom = lambda: "/logs/a.txt"                                # el pom es el mismo archivo que el log principal
        g._open_many = lambda title: ["/otra/a.txt", "/r/x.pdf"]          # el primero ya está como comparación
        sel = g.gather()
        self.assertEqual(sel["logs"], ["/otra/a.txt", "/logs/a.txt"])
        self.assertIsNone(sel["pom"])
        self.assertEqual(sel["reports"], ["/r/x.pdf"])
        self.assertEqual(len(warnings), 3)
        self.assertIn("ya está en", warnings[0])

    def test_escape_does_not_close_or_cancel_anything(self):
        g = self.g
        g._clear("Nuevo análisis")
        g.root.after(50, lambda: g.root.event_generate("<Escape>"))
        g.root.after(150, lambda: g._var.set("go"))      # el usuario sigue en la pantalla hasta que elige algo
        self.assertEqual(g._choice([("Analizar", "go"), ("Cancelar", "skip")]), "go")
        self.assertFalse(g.closed)
        self.assertEqual(g.root.bind("<Escape>"), "")    # ninguna pantalla enlaza Esc

    def test_form_cancel_raises(self):
        from pipeline_analyzer.interactive import Cancelled
        self.g._choice = lambda opts, cancel=None, disabled=(): "skip"
        with self.assertRaises(Cancelled):
            self.g.gather()

    def test_header_shows_the_screen_title_not_the_app_name_and_brand_only_in_result(self):
        g = self.g
        g._clear("Nuevo análisis")
        self.assertEqual(g._step["text"], "Nuevo análisis")
        self.assertEqual(len(g.footer.winfo_children()), 0)          # sin marca fuera del resultado
        g._clear("Análisis completado")
        self.assertEqual(len(g.footer.winfo_children()), 1)

    def test_window_is_wider_and_grows_then_shrinks_with_the_content(self):
        g = self.g
        self.assertEqual((g.WIDTH, g.HEIGHT), (760, 500))
        actions = iter(["main:dir", "cmp:dir", "cmp:file", "rep:files", "rm:cmp:0", "rm:cmp:0", "go"])
        heights = []

        def choice(opts, cancel=None, disabled=()):
            g._fit()
            g.root.update()
            heights.append(g.root.winfo_height())
            return next(actions)

        g._choice = choice
        paths = iter(["/l/actual", "/l/ant1", "/l/ant2"])
        g._open = lambda kind, title, ft=None: next(paths)
        g._open_many = lambda title: ["/r/a.pdf", "/r/b.xml", "/r/c.json"]
        g.gather()
        self.assertEqual(heights[0], 500)
        self.assertGreater(max(heights), 500)        # se alarga al agregar archivos
        self.assertEqual(heights[-1], 500)           # y vuelve a su alto base al quitarlos

    def test_remove_button_is_orange_with_readable_text(self):
        g = self.g
        g._clear("Nuevo análisis")
        clicked = []
        b = g._remove_button(g._card(), lambda: clicked.append(1))
        fills = {b.itemcget(i, "fill") for i in b.find_all()}
        self.assertIn("#c2410c", fills)          # fondo naranja
        self.assertIn("#ffffff", fills)          # texto blanco
        self.assertGreaterEqual(int(b.cget("height")), 22)
        b.pack()
        g.root.update()
        b.event_generate("<Button-1>", x=3, y=3)
        g.root.update()
        self.assertEqual(len(clicked), 1)
        b.focus_force()
        g.root.update()
        b.event_generate("<space>")
        g.root.update()
        self.assertEqual(len(clicked), 2)

    def test_open_report_keeps_the_window_and_new_analysis_is_offered(self):
        g = self.g
        opened, shown = [], []
        g._open_local = lambda p: opened.append(p)
        answers = iter(["open", "open", "new"])
        g._choice = lambda opts, cancel=None, disabled=(): shown.append([o[0] for o in opts]) or next(answers)
        g.show_result("Bloqueado por: PMD", {"HIGH": 1}, ["/r/reporte_completo.html", "/r/reporte.pdf"])
        self.assertEqual(shown[0], ["Abrir reporte", "Nuevo análisis", "Cerrar"])
        self.assertEqual(len(opened), 2)                 # abrir dos veces: la ventana sigue ahí
        self.assertTrue(g.new_requested)
        g._choice = lambda opts, cancel=None, disabled=(): "close"
        g.show_result("Todos los breakers pasaron", {}, ["/r/reporte_completo.html"])
        self.assertFalse(g.new_requested)

    def test_cancel_during_analysis_asks_first_and_stops(self):
        from pipeline_analyzer.interactive import Cancelled
        g = self.g
        answers = iter(["no", "yes"])
        g.root.tk.eval("rename tk_messageBox _orig_mb")
        g.root.tk.createcommand("tk_messageBox", lambda *a: next(answers))
        listener = g.open_progress()
        self.assertIn("Cancelar", g.buttons)
        g._on_close()                       # primera respuesta: «no» → sigue
        listener(0.1, "Leyendo", "", None)
        g._on_close()                       # segunda: «yes» → cancela
        with self.assertRaises(Cancelled):
            listener(0.2, "Leyendo", "", None)
        g.close_progress()


class SameScreenOnEverySystemTest(unittest.TestCase):
    """Windows y Linux usan la misma pantalla única que macOS, con el orden de botones propio de cada sistema."""

    def _gui(self, os_name, primary_right):
        from pipeline_analyzer.interactive import Gui, gui_available
        if not _real_windows_enabled():
            self.skipTest("ventanas reales desactivadas (PIPELINE_ANALYZER_GUI_TESTS=1 para activarlas)")
        if not gui_available():
            self.skipTest("sin entorno gráfico")
        style = {"os": os_name, "theme": "clam", "families": ("Segoe UI",), "pad": 22, "radius": 0, "primary_right": primary_right}
        with mock.patch("pipeline_analyzer.interactive.platform_style", return_value=style):
            try:
                g = Gui()
            except Exception as exc:
                self.skipTest("no se pudo abrir la ventana: %s" % exc)
        self.addCleanup(g.destroy)
        return g

    def test_windows_gets_the_single_form_with_the_same_size_and_cancel_button(self):
        for os_name in ("win10", "win11", "linux"):
            g = self._gui(os_name, os_name == "linux")
            self.assertEqual((g.WIDTH, g.HEIGHT), (760, 500))
            self.assertFalse(g.mac)
            shown = []
            g._choice = lambda opts, cancel=None, disabled=(): shown.append([o[0] for o in opts]) or "skip"
            from pipeline_analyzer.interactive import Cancelled
            with self.assertRaises(Cancelled):
                g.gather()                                    # mismo formulario que en macOS
            self.assertEqual(shown, [["Analizar", "Cancelar"]])
            g.open_progress()
            self.assertIn("Cancelar", g.buttons)              # y la misma cancelación durante el análisis
            g.close_progress()

    def test_windows_primary_button_is_first_and_macos_style_is_last(self):
        win, lin = self._gui("win11", False), self._gui("linux", True)
        for g in (win, lin):
            g.root.update()
            g.root.after(30, lambda g=g: g._var.set("go"))
            g._choice([("Analizar", "go"), ("Cancelar", "skip")])
        # En Windows el principal queda a la izquierda del grupo; en Linux/macOS, a la derecha
        self.assertLess(win.buttons["Analizar"].grid_info()["column"], win.buttons["Cancelar"].grid_info()["column"])
        self.assertGreater(lin.buttons["Analizar"].grid_info()["column"], lin.buttons["Cancelar"].grid_info()["column"])


class NewAnalysisFlowTest(unittest.TestCase):
    def test_new_analysis_returns_to_the_start_and_runs_again(self):
        from pipeline_analyzer import cli as cli_mod
        from test_analyzer import failing_log

        class FakeGui:
            def __init__(self):
                self.gathers, self.runs, self.new_requested, self.destroyed = 0, 0, False, False

            def gather(self):
                self.gathers += 1
                log = str(failing_log())
                return {"logs": [log], "pom": None, "main": log, "reports": []}

            def open_progress(self):
                return lambda *a, **k: None

            def close_progress(self):
                pass

            def show_result(self, *a):
                self.runs += 1
                self.new_requested = self.runs == 1       # la primera vez pide «Nuevo análisis»

            def destroy(self):
                self.destroyed = True

        fake = FakeGui()
        with mock.patch.object(cli_mod, "Gui", return_value=fake), mock.patch.object(cli_mod, "gui_status", return_value=(True, "", "")):
            rc = cli_mod.main(["--gui", "--no-console", "--out-dir", tempfile.mkdtemp()])
        self.assertEqual(rc, 0)
        self.assertEqual((fake.gathers, fake.runs, fake.destroyed), (2, 2, True))


class ConsolePromptsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.main = make_download(self.tmp / "actual", "200")
        self.prev = make_download(self.tmp / "anterior", "100")
        self.pom = self.tmp / "pom.xml"
        self.pom.write_text("<project xmlns='http://maven.apache.org/POM/4.0.0'></project>", encoding="utf-8")

    def test_gather_all(self):
        out = io.StringIO()
        sel = gather_console(_answers("/no/existe", '"%s"' % self.main, "s", str(self.prev), "n", "n", "s", str(self.pom), "n"), out)
        self.assertEqual(sel["logs"], [str(self.prev), str(self.main)])  # comparación primero, principal al final
        self.assertEqual(sel["pom"], str(self.pom))
        self.assertIn("No existe", out.getvalue())

    def test_console_rejects_same_file_in_another_section(self):
        out = io.StringIO()
        sel = gather_console(_answers(str(self.main), "s", str(self.main), str(self.prev), "n", "n", "s", str(self.pom), "n"), out)
        self.assertEqual(sel["logs"], [str(self.prev), str(self.main)])
        self.assertIn("Archivo no válido", out.getvalue())

    def test_compare_only_skips_pom_and_reports(self):
        sel = gather_console(_answers(str(self.main), "s", str(self.prev), "n", "s"), io.StringIO())
        self.assertEqual(sel, {"logs": [str(self.prev), str(self.main)], "pom": None, "main": str(self.main), "reports": [],
                               "compare_only": True, "yaml": {str(self.prev): False, str(self.main): False}})

    def test_compare_only_is_not_offered_without_a_comparison(self):
        out = io.StringIO()
        gather_console(_answers(str(self.main), "n", "n", "n"), out)    # solo 3 preguntas tras el log: no hay «solo comparación»
        self.assertNotIn("Solo comparar", out.getvalue())

    def test_gather_only_main(self):
        prompts = []
        answers = iter([str(self.main), "", "", ""])
        sel = gather_console(lambda prompt: prompts.append(prompt) or next(answers), io.StringIO())
        self.assertEqual((sel["logs"], sel["pom"]), ([str(self.main)], None))
        self.assertEqual(sel["yaml"], {str(self.main): False})
        self.assertFalse(any("¿Quieres agregar" in prompt for prompt in prompts))

    def test_yaml_yes_marks_the_route_and_uses_the_option_text(self):
        yaml_main = self.main / "pipeline.yml"
        yaml_main.write_text("steps: []\n", encoding="utf-8")
        prompts = []
        answers = iter([str(self.main), "n", "s", "n", "n"])

        def input_fn(prompt):
            prompts.append(prompt)
            return next(answers)

        selection = gather_console(input_fn, io.StringIO())
        self.assertEqual(selection["yaml"], {str(self.main): True})
        self.assertIn("¿Quieres agregar el archivo .yml al análisis? [s/N]: ", prompts)

    def test_yaml_no_continues_to_next_option_and_yes_links_every_yaml(self):
        (self.main / "pipeline.yaml").write_text("steps: []\n", encoding="utf-8")
        (self.prev / "pipeline.yml").write_text("steps: []\n", encoding="utf-8")
        prompts = []
        answers = iter([str(self.main), "s", str(self.prev), "n", "n", "s", "n", "n", "n"])

        def input_fn(prompt):
            prompts.append(prompt)
            return next(answers)

        selection = gather_console(input_fn, io.StringIO())
        self.assertEqual(selection["yaml"], {str(self.prev): True, str(self.main): True})
        self.assertIn("comparación? [s/N]", next(p for p in prompts if "análisis de comparación" in p))
        self.assertEqual(sum("¿Quieres agregar" in prompt for prompt in prompts), 2)

    def test_yaml_yes_skips_remaining_yaml_questions(self):
        (self.main / "pipeline.yaml").write_text("steps: []\n", encoding="utf-8")
        (self.prev / "pipeline.yml").write_text("steps: []\n", encoding="utf-8")
        prompts = []
        answers = iter([str(self.main), "s", str(self.prev), "n", "s", "s"])

        def input_fn(prompt):
            prompts.append(prompt)
            return next(answers)

        selection = gather_console(input_fn, io.StringIO())
        self.assertEqual(selection["yaml"], {str(self.prev): True, str(self.main): True})
        self.assertEqual(sum("¿Quieres agregar" in prompt for prompt in prompts), 1)
        self.assertTrue(selection["compare_only"])
        self.assertEqual(set(selection["yaml"]), set(selection["logs"]))

    def test_two_comparison_prompts_are_numbered_and_limit_includes_yaml_selection(self):
        newer = make_download(self.tmp / "otra", "75")
        (self.prev / "pipeline.yml").write_text("steps: []\n", encoding="utf-8")
        (newer / "pipeline.yaml").write_text("steps: []\n", encoding="utf-8")
        prompts, out = [], io.StringIO()
        answers = iter([str(self.main), "s", str(self.prev), "s", str(newer), "n", "n", "n", "n", "n"])

        def input_fn(prompt):
            prompts.append(prompt)
            return next(answers)

        selection = gather_console(input_fn, out)
        yaml_prompts = [p for p in prompts if "¿Quieres agregar" in p]
        self.assertEqual(len(yaml_prompts), 2)
        self.assertIn("comparación 1? [s/N]", yaml_prompts[0])
        self.assertIn("comparación 2? [s/N]", yaml_prompts[1])
        self.assertIn("Límite: máximo 2 comparaciones", out.getvalue())
        self.assertEqual(set(selection["yaml"]), set(selection["logs"]))
        self.assertFalse(selection["yaml"][str(self.prev)])
        self.assertFalse(selection["yaml"][str(newer)])

    @unittest.skipIf(sys.platform.startswith("win"), "en Windows la barra invertida es separador de ruta, no escape de espacios")
    def test_dragged_path_with_escaped_spaces(self):
        spaced = make_download(self.tmp / "con espacios", "300")
        sel = gather_console(_answers(str(spaced).replace(" ", "\\ "), "n", "n", "n"), io.StringIO())
        self.assertEqual(sel["logs"], [str(spaced)])

    def test_gather_extra_reports(self):
        pdf = self.tmp / "scan.pdf"
        pdf.write_bytes(b"%PDF-1.4")
        folder = self.tmp / "reportes"
        folder.mkdir()
        out = io.StringIO()
        sel = gather_console(_answers(str(self.main), "n", "n", "s", "/no/existe", str(pdf), str(folder), ""), out)
        self.assertEqual(sel["reports"], [str(pdf), str(folder)])
        self.assertIn("Agregado (2)", out.getvalue())
        self.assertEqual(gather_console(_answers(str(self.main), "n", "n", "n"), io.StringIO())["reports"], [])

    def test_extra_reports_reach_the_analysis(self):
        from test_cxone_scanreport import REPORT
        md = self.tmp / "scan.md"
        md.write_text(REPORT, encoding="utf-8")
        answers = _answers(str(self.main), "n", "n", "s", str(md), "")
        with mock.patch("builtins.input", answers), mock.patch.object(cli, "gui_status", return_value=(False, "sin pantalla", "n/a")):
            rc = cli.main(["--no-gui", "--no-console", "--no-progress", "--formats", "html"])
        self.assertEqual(rc, 0)
        html = (sorted(d for d in (self.main.parent / "reporte_pipeline").iterdir() if d.is_dir())[-1] / "reporte.html").read_text(encoding="utf-8")
        self.assertIn("scan.md", html)

    def test_cancel(self):
        def eof(prompt=""):
            raise EOFError
        with self.assertRaises(Cancelled):
            gather_console(eof, io.StringIO())

    def test_main_without_args_uses_prompts(self):
        answers = _answers(str(self.main), "s", str(self.prev), "n", "n", "n", "n")
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

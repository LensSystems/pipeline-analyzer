"""Windows: doble clic sin ventana de consola (pythonw). Abre directamente las ventanas de selección."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline_analyzer.cli import gui_main  # noqa: E402

sys.exit(gui_main())

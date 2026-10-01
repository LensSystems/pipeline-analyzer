#!/usr/bin/env python3
"""Lanzador del analizador de pipelines.

    python3 analizar_pipeline.py                      # abre ventanas para elegir los logs
    python3 analizar_pipeline.py logs_123456 --pom pom.xml
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline_analyzer.cli import main  # noqa: E402

sys.exit(main())

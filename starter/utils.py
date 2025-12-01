"""
Utility helper functions for Recon2Defend.

These make generate.py cleaner by handling:
✔ JSON loading
✔ Text file saving
"""

import json
from pathlib import Path


def load_json(path):
    """
    Load a JSON file and return its contents.
    """
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8"))


def save_text(path, text):
    """
    Save plain text (rules, HTML, reports, etc).
    """
    path = Path(path)
    path.write_text(text, encoding="utf-8")
    return path

"""
VETO Backend Package
Contains security gateway, policy, provenance, replay, approval, audit, risk, context engines, external adapters, and evaluation benchmarks.
"""

import sys
from pathlib import Path

_BACKEND_DIR = Path(__file__).resolve().parent
_ROOT_DIR = _BACKEND_DIR.parent

if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))
if str(_ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(_ROOT_DIR))

"""
config.py — VETO project-root .env loader.

This module loads the project-root .env file into os.environ exactly once
so that every downstream module (google_auth, provenance, audit, etc.) can
read configuration via os.environ.get() without needing to know where the
.env file lives relative to the current working directory.

Rules
-----
* Path is resolved relative to this file's location, not os.getcwd(), so
  it works when the process is started from any directory.
* override=False: a value already in the environment (e.g. set by the shell
  or a CI secret store) is never overwritten.
* load_dotenv() is idempotent; importing this module multiple times is safe.
* The .env path is not logged to avoid leaking information about the
  filesystem layout in production.
"""

from __future__ import annotations

import pathlib
import sys

from dotenv import load_dotenv

# Resolve the project root as the directory that contains this file.
_PROJECT_ROOT = pathlib.Path(__file__).parent.resolve()
_ENV_FILE = _PROJECT_ROOT / ".env"
_BACKEND_DIR = _PROJECT_ROOT / "backend"

if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# Load the .env file; missing file is silently ignored (dotenv default).
# override=False preserves any value already exported in the shell so
# production deployments that inject secrets via the environment are
# unaffected.
load_dotenv(dotenv_path=_ENV_FILE, override=False)

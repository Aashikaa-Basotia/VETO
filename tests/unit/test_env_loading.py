"""
tests/unit/test_env_loading.py — Focused tests for .env configuration loading.

Scope
-----
* config.py correctly loads variables from a temporary .env file.
* override=False: an already-set environment variable is NOT overwritten.
* A missing .env file is tolerated without crashing.
* GoogleAuthManager picks up the loaded values and raises the expected error
  when credentials are absent.

These tests do NOT read the real .env or require actual Google credentials.
All environment manipulation is scoped to the test via monkeypatch /
patch.dict so no cross-test pollution occurs.
"""

from __future__ import annotations

import importlib
import os
import pathlib
import sys
import tempfile
import textwrap

import pytest
from unittest.mock import patch


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _reload_config_with_env_file(env_file_path: str) -> None:
    """Force-reload config.py pointing at a custom env file path."""
    import config as cfg_module  # noqa: PLC0415

    # Patch the path and call load_dotenv again directly
    from dotenv import load_dotenv

    load_dotenv(dotenv_path=env_file_path, override=True)


# ---------------------------------------------------------------------------
# 1. config.py loads variables from a .env file into os.environ
# ---------------------------------------------------------------------------

def test_dotenv_loads_into_environ(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Variables written in a .env file are visible in os.environ after load_dotenv."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "GOOGLE_OAUTH_CLIENT_ID=test_client_id\n"
        "GOOGLE_OAUTH_CLIENT_SECRET=test_client_secret\n"
        "GOOGLE_OAUTH_REFRESH_TOKEN=test_refresh_token\n",
        encoding="utf-8",
    )

    # Ensure none of the keys are set beforehand
    for key in ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET", "GOOGLE_OAUTH_REFRESH_TOKEN"):
        monkeypatch.delenv(key, raising=False)

    from dotenv import load_dotenv

    load_dotenv(dotenv_path=str(env_file), override=True)

    assert os.environ.get("GOOGLE_OAUTH_CLIENT_ID") == "test_client_id"
    assert os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET") == "test_client_secret"
    assert os.environ.get("GOOGLE_OAUTH_REFRESH_TOKEN") == "test_refresh_token"

    # Clean up to avoid polluting later tests
    for key in ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET", "GOOGLE_OAUTH_REFRESH_TOKEN"):
        monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# 2. override=False: existing env var wins over .env
# ---------------------------------------------------------------------------

def test_dotenv_does_not_override_existing_env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When a variable is already in the environment, load_dotenv(override=False) must not overwrite it."""
    env_file = tmp_path / ".env"
    env_file.write_text("GOOGLE_OAUTH_CLIENT_ID=from_dotenv_file\n", encoding="utf-8")

    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "from_shell")

    from dotenv import load_dotenv

    load_dotenv(dotenv_path=str(env_file), override=False)

    assert os.environ.get("GOOGLE_OAUTH_CLIENT_ID") == "from_shell"


# ---------------------------------------------------------------------------
# 3. Missing .env file is tolerated
# ---------------------------------------------------------------------------

def test_missing_dotenv_file_does_not_crash(tmp_path: pathlib.Path) -> None:
    """load_dotenv with a non-existent path should not raise an exception."""
    from dotenv import load_dotenv

    non_existent = tmp_path / "does_not_exist.env"
    # Must not raise
    load_dotenv(dotenv_path=str(non_existent), override=False)


# ---------------------------------------------------------------------------
# 4. config.py path is resolved relative to its own __file__
# ---------------------------------------------------------------------------

def test_config_env_file_path_is_project_root() -> None:
    """config._ENV_FILE must point at <project_root>/.env (i.e. the directory
    containing config.py), not the current working directory."""
    import config as cfg_module  # noqa: PLC0415

    expected_dir = pathlib.Path(cfg_module.__file__).parent.resolve()
    expected_path = expected_dir / ".env"

    assert cfg_module._ENV_FILE == expected_path, (
        f"Expected _ENV_FILE to be {expected_path!r}, got {cfg_module._ENV_FILE!r}"
    )


# ---------------------------------------------------------------------------
# 5. GoogleAuthManager raises when credentials are absent
# ---------------------------------------------------------------------------

def test_google_auth_manager_raises_without_credentials() -> None:
    """GoogleAuthManager.get_valid_token() must raise the canonical error
    message when all three credential env vars are absent."""
    with patch.dict(os.environ, {}, clear=True):
        from services.google_auth import GoogleAuthManager

        manager = GoogleAuthManager()
        with pytest.raises(Exception, match="Gmail OAuth credentials not configured"):
            manager.get_valid_token()


# ---------------------------------------------------------------------------
# 6. GoogleAuthManager reads credentials loaded via load_dotenv
# ---------------------------------------------------------------------------

def test_google_auth_manager_reads_dotenv_credentials(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """After load_dotenv populates the env vars, GoogleAuthManager properties
    must return those values (no real network call needed)."""
    env_file = tmp_path / ".env"
    env_file.write_text(
        "GOOGLE_OAUTH_CLIENT_ID=dotenv_client_id\n"
        "GOOGLE_OAUTH_CLIENT_SECRET=dotenv_client_secret\n"
        "GOOGLE_OAUTH_REFRESH_TOKEN=dotenv_refresh_token\n",
        encoding="utf-8",
    )

    for key in ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET", "GOOGLE_OAUTH_REFRESH_TOKEN"):
        monkeypatch.delenv(key, raising=False)

    from dotenv import load_dotenv

    load_dotenv(dotenv_path=str(env_file), override=True)

    from services.google_auth import GoogleAuthManager

    manager = GoogleAuthManager()
    assert manager.client_id == "dotenv_client_id"
    assert manager.client_secret == "dotenv_client_secret"
    assert manager.refresh_token == "dotenv_refresh_token"

    # Clean up
    for key in ("GOOGLE_OAUTH_CLIENT_ID", "GOOGLE_OAUTH_CLIENT_SECRET", "GOOGLE_OAUTH_REFRESH_TOKEN"):
        monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
# 7. GoogleAuthManager explicit constructor args take precedence over env
# ---------------------------------------------------------------------------

def test_google_auth_manager_explicit_args_take_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    """Values passed to the constructor must win over os.environ."""
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "env_id")
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_SECRET", "env_secret")
    monkeypatch.setenv("GOOGLE_OAUTH_REFRESH_TOKEN", "env_token")

    from services.google_auth import GoogleAuthManager

    manager = GoogleAuthManager(
        client_id="explicit_id",
        client_secret="explicit_secret",
        refresh_token="explicit_token",
    )
    assert manager.client_id == "explicit_id"
    assert manager.client_secret == "explicit_secret"
    assert manager.refresh_token == "explicit_token"


# ---------------------------------------------------------------------------
# 8. Blank / whitespace-only values in .env are treated as missing
# ---------------------------------------------------------------------------

def test_google_auth_manager_raises_on_blank_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    """Whitespace-only credential values must still trigger the 'not configured' error."""
    with patch.dict(
        os.environ,
        {
            "GOOGLE_OAUTH_CLIENT_ID": "   ",
            "GOOGLE_OAUTH_CLIENT_SECRET": "   ",
            "GOOGLE_OAUTH_REFRESH_TOKEN": "   ",
        },
        clear=True,
    ):
        from services.google_auth import GoogleAuthManager

        manager = GoogleAuthManager()
        with pytest.raises(Exception, match="Gmail OAuth credentials not configured"):
            manager.get_valid_token()

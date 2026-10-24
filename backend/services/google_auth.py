import config  # noqa: F401 — loads project-root .env into os.environ before any credential read
import os
import logging
from typing import Optional
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import GoogleAuthError

logger = logging.getLogger("veto_gateway")

class GoogleAuthManager:
    def __init__(self, client_id: Optional[str] = None, client_secret: Optional[str] = None, refresh_token: Optional[str] = None):
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token
        self.token_uri = "https://oauth2.googleapis.com/token"
        
        self.credentials = None
        self._cached_client_id = None
        self._cached_client_secret = None
        self._cached_refresh_token = None

    @property
    def client_id(self) -> Optional[str]:
        if self._client_id is not None:
            return self._client_id
        return os.environ.get("GOOGLE_OAUTH_CLIENT_ID")

    @client_id.setter
    def client_id(self, value: Optional[str]):
        self._client_id = value

    @property
    def client_secret(self) -> Optional[str]:
        if self._client_secret is not None:
            return self._client_secret
        return os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

    @client_secret.setter
    def client_secret(self, value: Optional[str]):
        self._client_secret = value

    @property
    def refresh_token(self) -> Optional[str]:
        if self._refresh_token is not None:
            return self._refresh_token
        return os.environ.get("GOOGLE_OAUTH_REFRESH_TOKEN")

    @refresh_token.setter
    def refresh_token(self, value: Optional[str]):
        self._refresh_token = value

    def get_valid_token(self) -> str:
        """
        Retrieves a valid OAuth Bearer token.
        Refreshes automatically if expired.
        """
        cid = self.client_id
        sec = self.client_secret
        ref = self.refresh_token

        # Detect missing configuration before attempting token refresh
        if not cid or not sec or not ref or not cid.strip() or not sec.strip() or not ref.strip():
            self.credentials = None
            self._cached_client_id = None
            self._cached_client_secret = None
            self._cached_refresh_token = None
            raise Exception("Gmail OAuth credentials not configured")

        cid = cid.strip()
        sec = sec.strip()
        ref = ref.strip()

        # Re-initialize credentials if configuration changed or not yet initialized
        if (
            not self.credentials
            or cid != self._cached_client_id
            or sec != self._cached_client_secret
            or ref != self._cached_refresh_token
        ):
            self._cached_client_id = cid
            self._cached_client_secret = sec
            self._cached_refresh_token = ref
            self.credentials = Credentials(
                token=None,
                refresh_token=ref,
                token_uri=self.token_uri,
                client_id=cid,
                client_secret=sec
            )

        if not self.credentials.valid:
            try:
                self.credentials.refresh(Request())
            except Exception as e:
                # Log without exposing raw secrets
                logger.error(f"[VETO] Google Auth Error: {type(e).__name__}")
                raise Exception("Failed to refresh Google OAuth token")

        return self.credentials.token

# Singleton for caching
_google_auth_manager = None

def get_google_auth_manager() -> GoogleAuthManager:
    global _google_auth_manager
    if _google_auth_manager is None:
        _google_auth_manager = GoogleAuthManager()
    return _google_auth_manager

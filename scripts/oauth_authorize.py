"""
Temporary local OAuth 2.0 authorization helper for VETO Gmail integration.

 Security guarantees:
- Requests ONLY the minimum scopes required by VETO Gmail capabilities:
  * https://www.googleapis.com/auth/gmail.readonly
  * https://www.googleapis.com/auth/gmail.send
- Reads client credentials from environment variables (or local .env / credentials.json).
- Prints the resulting refresh_token ONLY to the local terminal (stdout).
- Does NOT log credentials or tokens.
- Does NOT write or persist tokens to disk or Git.
"""

import glob
import os
import sys
from google_auth_oauthlib.flow import InstalledAppFlow

# Strictly limited to the scopes defined by the VETO Gmail integration
SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
]


def _load_local_dotenv(dotenv_path: str = ".env") -> None:
    """Loads KEY=VALUE pairs from a local .env file into os.environ if present."""
    if not os.path.isfile(dotenv_path):
        return
    with open(dotenv_path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def main() -> None:
    _load_local_dotenv(".env")

    client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")

    if client_id and client_secret:
        client_config = {
            "installed": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://localhost", "http://127.0.0.1"],
            }
        }
        flow = InstalledAppFlow.from_client_config(client_config, scopes=SCOPES)
    else:
        # Fallback to local untracked Google Cloud Desktop client JSON if present
        candidate_files = ["credentials.json"] + sorted(glob.glob("client_secret*.json"))
        secret_file = next((p for p in candidate_files if os.path.isfile(p)), None)
        if not secret_file:
            print(
                "Error: OAuth client configuration not found.\n"
                "Set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in your environment "
                "(or local .env file), or place your downloaded Desktop client JSON at "
                "'credentials.json' in the VETO project root.",
                file=sys.stderr,
            )
            sys.exit(1)
        flow = InstalledAppFlow.from_client_secrets_file(secret_file, scopes=SCOPES)

    print("Starting local OAuth 2.0 authorization flow for VETO Gmail integration...")
    print("Requested scopes:")
    for scope in SCOPES:
        print(f"  - {scope}")
    print("\nIMPORTANT: In the browser window that opens, select your dedicated VETO test Gmail account.\n")

    creds = flow.run_local_server(
        host="127.0.0.1",
        port=0,
        access_type="offline",
        prompt="consent",
    )

    if not creds or not creds.refresh_token:
        print(
            "\nError: Authorization completed, but no refresh_token was returned.\n"
            "Ensure you approved offline access and try again.",
            file=sys.stderr,
        )
        sys.exit(1)

    print("\n" + "=" * 60)
    print("OAuth Authorization Complete (Terminal Output Only - Not Saved)")
    print("=" * 60)
    print(f"GOOGLE_OAUTH_REFRESH_TOKEN={creds.refresh_token}")
    print("=" * 60)


if __name__ == "__main__":
    main()

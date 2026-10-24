import os
import json
import urllib.request
import urllib.error

from services.google_auth import get_google_auth_manager

class GmailAdapter:
    def __init__(self):
        self.api_base_url = "https://gmail.googleapis.com/gmail/v1/users/me"

    @property
    def access_token(self):
        # We fallback to VETO_GMAIL_ACCESS_TOKEN only if explicitly set for legacy tests,
        # but primarily use the strict OAuth manager.
        legacy = os.environ.get("VETO_GMAIL_ACCESS_TOKEN")
        if legacy:
            return legacy
        return get_google_auth_manager().get_valid_token()

    def list_recent_emails(self, max_results: int = 5) -> dict:
        """
        Lists recent emails from Gmail.
        Bounded read operation to prevent abuse.
        """
        # Deterministic bounding
        try:
            max_results = int(max_results)
        except (ValueError, TypeError):
            max_results = 5
            
        if max_results < 1:
            max_results = 1
        elif max_results > 20:
            max_results = 20

        if not self.access_token:
            # Deterministic configuration error without crashing VETO
            raise Exception("Gmail OAuth credentials not configured")

        # Construct safe API endpoint
        url = f"{self.api_base_url}/messages?maxResults={max_results}"

        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.access_token}")
        
        try:
            with urllib.request.urlopen(req, timeout=10.0) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                # Fetch metadata for each message
                messages = result.get("messages", [])
                metadata_list = []
                
                for msg in messages:
                    msg_id = msg.get("id")
                    msg_url = f"{self.api_base_url}/messages/{msg_id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date"
                    msg_req = urllib.request.Request(msg_url)
                    msg_req.add_header("Authorization", f"Bearer {self.access_token}")
                    
                    try:
                        with urllib.request.urlopen(msg_req, timeout=5.0) as msg_resp:
                            msg_data = json.loads(msg_resp.read().decode('utf-8'))
                            headers = msg_data.get("payload", {}).get("headers", [])
                            
                            metadata = {
                                "id": msg_id,
                                "threadId": msg_data.get("threadId"),
                                "snippet": msg_data.get("snippet")
                            }
                            
                            for h in headers:
                                name = h.get("name")
                                if name in ["Subject", "From", "Date"]:
                                    metadata[name.lower()] = h.get("value")
                                    
                            metadata_list.append(metadata)
                    except Exception as e:
                        # Skip message if we fail to fetch it
                        continue
                        
                return {"messages": metadata_list, "status": "SUCCESS"}
                
        except urllib.error.HTTPError as e:
            # Re-raise so gateway handles HTTP errors consistently
            raise e
        except urllib.error.URLError as e:
            raise e

    def _validate_message_id(self, message_id: str):
        if not message_id or not isinstance(message_id, str):
            raise ValueError("Invalid message ID")
        if "/" in message_id or "\\" in message_id or "?" in message_id or "&" in message_id:
            raise ValueError("Malformed message ID")
            
    def get_email_metadata(self, message_id: str) -> dict:
        self._validate_message_id(message_id)
        if not self.access_token:
            raise Exception("Gmail OAuth credentials not configured")
            
        url = f"{self.api_base_url}/messages/{urllib.parse.quote(message_id)}?format=metadata"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.access_token}")
        
        try:
            with urllib.request.urlopen(req, timeout=5.0) as response:
                msg_data = json.loads(response.read().decode('utf-8'))
                headers = msg_data.get("payload", {}).get("headers", [])
                
                metadata = {
                    "id": msg_data.get("id"),
                    "threadId": msg_data.get("threadId"),
                    "snippet": msg_data.get("snippet"),
                    "timestamp": msg_data.get("internalDate"),
                    "labels": msg_data.get("labelIds", [])
                }
                
                for h in headers:
                    name = h.get("name")
                    if name in ["Subject", "From", "To", "Date"]:
                        metadata[name.lower()] = h.get("value")
                        
                return {"success": True, "message": metadata}
        except urllib.error.HTTPError as e:
            raise e
        except urllib.error.URLError as e:
            raise e

    def get_email_body(self, message_id: str) -> dict:
        self._validate_message_id(message_id)
        if not self.access_token:
            raise Exception("Gmail OAuth credentials not configured")
            
        url = f"{self.api_base_url}/messages/{urllib.parse.quote(message_id)}?format=full"
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.access_token}")
        
        try:
            with urllib.request.urlopen(req, timeout=5.0) as response:
                msg_data = json.loads(response.read().decode('utf-8'))
                
                payload = msg_data.get("payload", {})
                parts = payload.get("parts", [])
                
                body_data = ""
                if "data" in payload.get("body", {}):
                    body_data = payload["body"]["data"]
                else:
                    for part in parts:
                        if part.get("mimeType") in ["text/plain", "text/html"] and "data" in part.get("body", {}):
                            body_data = part["body"]["data"]
                            break
                            
                return {
                    "success": True, 
                    "message": {
                        "id": msg_data.get("id"),
                        "threadId": msg_data.get("threadId"),
                        "snippet": msg_data.get("snippet"),
                        "body_data": body_data
                    }
                }
        except urllib.error.HTTPError as e:
            raise e
        except urllib.error.URLError as e:
            raise e

    def _validate_send_params(self, to: str, subject: str, body: str):
        if not to or not isinstance(to, str):
            raise ValueError("Recipient 'to' must be a non-empty string.")
        if "\n" in to or "\r" in to:
            raise ValueError("Recipient contains invalid control characters (CR/LF).")
            
        if not subject or not isinstance(subject, str):
            raise ValueError("Subject must be a non-empty string.")
        if len(subject) > 256:
            raise ValueError("Subject exceeds maximum length of 256 characters.")
        if "\n" in subject or "\r" in subject:
            raise ValueError("Subject contains invalid control characters (CR/LF).")
            
        if not body or not isinstance(body, str):
            raise ValueError("Body must be a non-empty string.")
        if len(body) > 100 * 1024:  # 100 KB
            raise ValueError("Body exceeds maximum size of 100 KB.")

    def send_email(self, to: str, subject: str, body: str) -> dict:
        self._validate_send_params(to, subject, body)
        if not self.access_token:
            raise Exception("Gmail OAuth credentials not configured")
            
        from email.message import EmailMessage
        import base64
        
        msg = EmailMessage()
        msg.set_content(body)
        msg['To'] = to
        msg['Subject'] = subject
        
        raw_message = base64.urlsafe_b64encode(msg.as_bytes()).decode('utf-8')
        payload = json.dumps({"raw": raw_message}).encode('utf-8')
        
        url = f"{self.api_base_url}/messages/send"
        req = urllib.request.Request(url, data=payload, method="POST")
        req.add_header("Authorization", f"Bearer {self.access_token}")
        req.add_header("Content-Type", "application/json")
        
        try:
            with urllib.request.urlopen(req, timeout=10.0) as response:
                result = json.loads(response.read().decode('utf-8'))
                return {
                    "success": True,
                    "message": "Email sent successfully",
                    "id": result.get("id"),
                    "threadId": result.get("threadId")
                }
        except urllib.error.HTTPError as e:
            raise e
        except urllib.error.URLError as e:
            raise e

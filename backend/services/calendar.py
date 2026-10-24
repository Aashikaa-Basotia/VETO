import os
import json
import urllib.request
import urllib.parse
import urllib.error

class CalendarAdapter:
    def __init__(self):
        # We read from environment variables.
        self.access_token = os.environ.get("VETO_CALENDAR_ACCESS_TOKEN")
        self.api_base_url = "https://www.googleapis.com/calendar/v3"

    def list_calendar_events(self, max_results: int = 10, time_min: str = None, time_max: str = None) -> dict:
        """
        Lists events from primary calendar.
        Bounded read operation.
        """
        try:
            max_results = int(max_results)
        except (ValueError, TypeError):
            max_results = 10
            
        if max_results < 1:
            max_results = 1
        elif max_results > 20:
            max_results = 20

        if not self.access_token:
            raise Exception("Calendar OAuth credentials not configured")

        url = f"{self.api_base_url}/calendars/primary/events?maxResults={max_results}&singleEvents=true&orderBy=startTime"
        
        if time_min:
            url += f"&timeMin={urllib.parse.quote(str(time_min))}"
        if time_max:
            url += f"&timeMax={urllib.parse.quote(str(time_max))}"

        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.access_token}")
        
        try:
            with urllib.request.urlopen(req, timeout=10.0) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                # Fetch metadata for each event safely bounded
                items = result.get("items", [])
                safe_items = []
                
                for item in items:
                    safe_items.append({
                        "id": item.get("id"),
                        "summary": item.get("summary"),
                        "start": item.get("start"),
                        "end": item.get("end"),
                        "status": item.get("status")
                    })
                    
                return {"items": safe_items}
        except Exception as e:
            raise e

    def create_calendar_event(self, summary: str, start: dict, end: dict, description: str = None) -> dict:
        """
        Creates an event in the primary calendar.
        Bounded state-changing operation.
        """
        if not self.access_token:
            raise Exception("Calendar OAuth credentials not configured")
            
        if not summary or not isinstance(summary, str) or len(summary) > 256:
            raise Exception("Summary exceeds maximum length of 256 characters or is invalid.")
        if '\n' in summary or '\r' in summary:
            raise Exception("Summary contains invalid control characters (CR/LF).")
            
        if description and isinstance(description, str) and len(description) > 5000:
            raise Exception("Description exceeds maximum size of 5000 characters.")
            
        if not isinstance(start, dict) or not isinstance(end, dict):
            raise Exception("Start and end must be dictionaries.")
            
        if not start.get("dateTime") and not start.get("date"):
            raise Exception("Start must contain dateTime or date.")
            
        if not end.get("dateTime") and not end.get("date"):
            raise Exception("End must contain dateTime or date.")

        url = f"{self.api_base_url}/calendars/primary/events"
        
        payload = {
            "summary": summary,
            "start": start,
            "end": end
        }
        if description:
            payload["description"] = description
            
        data = json.dumps(payload).encode('utf-8')

        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Authorization", f"Bearer {self.access_token}")
        req.add_header("Content-Type", "application/json")
        
        try:
            with urllib.request.urlopen(req, timeout=10.0) as response:
                result = json.loads(response.read().decode('utf-8'))
                return {
                    "id": result.get("id"),
                    "status": result.get("status"),
                    "htmlLink": result.get("htmlLink")
                }
        except Exception as e:
            raise e

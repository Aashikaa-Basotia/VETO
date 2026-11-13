import pytest
from unittest.mock import patch, MagicMock
import urllib.error
import json
import os
from services.calendar import CalendarAdapter

@pytest.fixture
def adapter():
    with patch.dict(os.environ, {"VETO_CALENDAR_ACCESS_TOKEN": "mock-token"}):
        return CalendarAdapter()

def test_list_calendar_events_success(adapter):
    mock_response = MagicMock()
    mock_response.__enter__.return_value.read.return_value = json.dumps({
        "items": [
            {"id": "1", "summary": "Test Event", "start": {"dateTime": "2026-10-10T10:00:00Z"}, "end": {"dateTime": "2026-10-10T11:00:00Z"}, "status": "confirmed"}
        ]
    }).encode('utf-8')
    
    with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
        result = adapter.list_calendar_events(max_results=5)
        
        assert len(result["items"]) == 1
        assert result["items"][0]["summary"] == "Test Event"
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert "maxResults=5" in req.full_url
        assert req.get_header("Authorization") == "Bearer mock-token"

def test_list_calendar_events_bounds(adapter):
    mock_response = MagicMock()
    mock_response.__enter__.return_value.read.return_value = json.dumps({"items": []}).encode('utf-8')
    
    with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
        adapter.list_calendar_events(max_results=50) # Should bound to 20
        req = mock_urlopen.call_args[0][0]
        assert "maxResults=20" in req.full_url
        
        adapter.list_calendar_events(max_results=0) # Should bound to 1
        req = mock_urlopen.call_args[0][0]
        assert "maxResults=1" in req.full_url

def test_create_calendar_event_success(adapter):
    mock_response = MagicMock()
    mock_response.__enter__.return_value.read.return_value = json.dumps({
        "id": "new-event",
        "status": "confirmed",
        "htmlLink": "https://calendar.google.com/events/new-event"
    }).encode('utf-8')
    
    with patch('urllib.request.urlopen', return_value=mock_response) as mock_urlopen:
        result = adapter.create_calendar_event(
            summary="Meeting",
            start={"dateTime": "2026-10-10T10:00:00Z"},
            end={"dateTime": "2026-10-10T11:00:00Z"}
        )
        
        assert result["id"] == "new-event"
        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.method == "POST"
        body = json.loads(req.data.decode('utf-8'))
        assert body["summary"] == "Meeting"
        assert body["start"]["dateTime"] == "2026-10-10T10:00:00Z"

def test_create_calendar_event_validation(adapter):
    with pytest.raises(Exception, match="Summary exceeds maximum length"):
        adapter.create_calendar_event("A" * 300, {"date": "2026-10-10"}, {"date": "2026-10-11"})
        
    with pytest.raises(Exception, match="invalid control characters"):
        adapter.create_calendar_event("Test\nEvent", {"date": "2026-10-10"}, {"date": "2026-10-11"})

    with pytest.raises(Exception, match="Start and end must be dictionaries"):
        adapter.create_calendar_event("Test", "2026-10-10", {"date": "2026-10-11"})
        
    with pytest.raises(Exception, match="Start must contain dateTime or date"):
        adapter.create_calendar_event("Test", {"wrong": "1"}, {"date": "2026-10-11"})

def test_missing_credentials():
    with patch.dict(os.environ, clear=True):
        adapter = CalendarAdapter()
        with pytest.raises(Exception, match="Calendar OAuth credentials not configured"):
            adapter.list_calendar_events()
        with pytest.raises(Exception, match="Calendar OAuth credentials not configured"):
            adapter.create_calendar_event("Test", {"date": "2026-10-10"}, {"date": "2026-10-11"})

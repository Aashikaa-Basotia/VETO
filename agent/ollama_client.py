import urllib.request
import urllib.error
import json
import logging

class OllamaClient:
    def __init__(self, host: str = "http://localhost:11434", model: str = "qwen3:8b"):
        self.host = host
        self.model = model

    def chat(self, messages: list[dict], temperature: float = 0.0) -> str:
        """
        Sends a chat request to Ollama and returns the message content.
        Uses temperature 0 for determinism.
        """
        url = f"{self.host}/api/chat"
        data = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature
            }
        }
        
        req = urllib.request.Request(
            url, 
            data=json.dumps(data).encode('utf-8'),
            headers={'Content-Type': 'application/json'}
        )
        
        try:
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get('message', {}).get('content', '')
        except urllib.error.URLError as e:
            logging.error(f"Failed to connect to Ollama: {e}")
            raise Exception(f"Ollama connection error: {e}")
        except Exception as e:
            logging.error(f"Error communicating with Ollama: {e}")
            raise Exception(f"Ollama error: {e}")

    def check_health(self) -> bool:
        """
        Checks if Ollama is accessible.
        """
        try:
            with urllib.request.urlopen(self.host) as response:
                return response.status == 200
        except:
            return False

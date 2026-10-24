import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="VETO Controlled Downstream Service")

class RecordRequest(BaseModel):
    name: str
    value: str

@app.get("/status")
def get_status():
    return {
        "status": "ok",
        "service": "VETO controlled downstream service"
    }

@app.post("/records")
def create_record(record: RecordRequest):
    if not record.name or not record.value:
        raise HTTPException(status_code=400, detail="Missing name or value")
        
    return {
        "created": True,
        "record_id": "REC-001",
        "name": record.name,
        "value": record.value
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)

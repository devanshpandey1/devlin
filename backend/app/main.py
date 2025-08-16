from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import json
import os
import asyncio
from typing import List, Dict, Any
from datetime import datetime
import uuid

connected_websockets: List[WebSocket] = []
active_scans: Dict[str, Dict] = {}
config: Dict = {}

def load_config():
    """Load configuration from settings.json"""
    global config
    try:
        with open("../settings.json", "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        with open("../settings.example.json", "r") as f:
            config = json.load(f)
    return config

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize application on startup"""
    load_config()
    os.makedirs("../data/scans", exist_ok=True)
    os.makedirs("../data/reports", exist_ok=True)
    os.makedirs("../data/loot", exist_ok=True)
    yield

app = FastAPI(title="Devlin Pentesting API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify API token"""
    if not config:
        load_config()
    
    expected_token = config.get("api", {}).get("auth_token", "devlin-local-auth-token-change-me")
    if credentials.credentials != expected_token:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    return credentials.credentials

async def broadcast_message(message: Dict[str, Any]):
    """Broadcast message to all connected WebSocket clients"""
    if connected_websockets:
        disconnected = []
        for websocket in connected_websockets:
            try:
                await websocket.send_json(message)
            except:
                disconnected.append(websocket)
        
        for ws in disconnected:
            connected_websockets.remove(ws)

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}

@app.get("/config")
async def get_config(token: str = Depends(verify_token)):
    """Get sanitized configuration"""
    sanitized_config = config.copy()
    for provider in sanitized_config.get("ai_providers", {}).values():
        if isinstance(provider, dict) and "api_key" in provider:
            provider["api_key"] = "***"
    return sanitized_config

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket.accept()
    connected_websockets.append(websocket)
    
    try:
        await websocket.send_json({
            "type": "connection",
            "message": "Connected to Devlin API",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        connected_websockets.remove(websocket)

@app.get("/scans")
async def list_scans(token: str = Depends(verify_token)):
    """List all scan results"""
    return {"scans": list(active_scans.keys()), "active_count": len(active_scans)}

@app.post("/scans/nmap")
async def start_nmap_scan(
    target: str,
    scan_type: str = "quick",
    token: str = Depends(verify_token)
):
    """Start an Nmap scan"""
    scan_id = str(uuid.uuid4())
    
    scan_config = {
        "id": scan_id,
        "target": target,
        "type": scan_type,
        "status": "starting",
        "started_at": datetime.utcnow().isoformat(),
        "progress": 0
    }
    
    active_scans[scan_id] = scan_config
    
    await broadcast_message({
        "type": "scan_started",
        "scan_id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "timestamp": datetime.utcnow().isoformat()
    })
    
    asyncio.create_task(simulate_nmap_scan(scan_id, target, scan_type))
    
    return {"scan_id": scan_id, "status": "started"}

async def simulate_nmap_scan(scan_id: str, target: str, scan_type: str):
    """Simulate an Nmap scan (placeholder implementation)"""
    try:
        for progress in [10, 25, 50, 75, 90, 100]:
            await asyncio.sleep(2)
            active_scans[scan_id]["progress"] = progress
            active_scans[scan_id]["status"] = "running" if progress < 100 else "completed"
            
            await broadcast_message({
                "type": "scan_progress",
                "scan_id": scan_id,
                "progress": progress,
                "status": active_scans[scan_id]["status"],
                "timestamp": datetime.utcnow().isoformat()
            })
        
        results = {
            "target": target,
            "scan_type": scan_type,
            "ports": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.9", "state": "open"},
                {"port": 80, "service": "http", "version": "Apache 2.4.41", "state": "open"},
                {"port": 443, "service": "https", "version": "Apache 2.4.41", "state": "open"}
            ],
            "os": "Linux 5.4",
            "completed_at": datetime.utcnow().isoformat()
        }
        
        active_scans[scan_id]["results"] = results
        
        await broadcast_message({
            "type": "scan_completed",
            "scan_id": scan_id,
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        
        await broadcast_message({
            "type": "scan_failed",
            "scan_id": scan_id,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        })

@app.get("/scans/{scan_id}")
async def get_scan_results(scan_id: str, token: str = Depends(verify_token)):
    """Get scan results by ID"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return active_scans[scan_id]

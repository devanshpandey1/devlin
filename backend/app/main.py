from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from contextlib import asynccontextmanager
import json
import os
import asyncio
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Any
from datetime import datetime
import uuid
import re
from openai import OpenAI

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
    
    asyncio.create_task(execute_nmap_scan(scan_id, target, scan_type))
    
    return {"scan_id": scan_id, "status": "started"}

def get_nmap_command(target: str, scan_type: str) -> List[str]:
    """Get Nmap command based on scan type"""
    nmap_path = config.get("tools", {}).get("nmap", {}).get("path", "nmap")
    
    base_cmd = [nmap_path, "-oX", "-", target]
    
    if scan_type == "quick":
        return base_cmd + ["-T4", "-F"]
    elif scan_type == "aggressive":
        return base_cmd + ["-A"]
    elif scan_type == "top_ports":
        return base_cmd + ["--top-ports", "100"]
    elif scan_type == "full_tcp":
        return base_cmd + ["-p-"]
    else:
        return base_cmd + ["-T4", "-F"]

def parse_nmap_xml(xml_content: str) -> Dict[str, Any]:
    """Parse Nmap XML output into structured data"""
    try:
        root = ET.fromstring(xml_content)
        
        results = {
            "hosts": [],
            "scan_info": {},
            "stats": {}
        }
        
        for host in root.findall("host"):
            host_data = {
                "ip": "",
                "hostname": "",
                "state": "",
                "ports": [],
                "os": ""
            }
            
            address = host.find("address")
            if address is not None:
                host_data["ip"] = address.get("addr", "")
            
            hostnames = host.find("hostnames")
            if hostnames is not None:
                hostname = hostnames.find("hostname")
                if hostname is not None:
                    host_data["hostname"] = hostname.get("name", "")
            
            status = host.find("status")
            if status is not None:
                host_data["state"] = status.get("state", "")
            
            ports = host.find("ports")
            if ports is not None:
                for port in ports.findall("port"):
                    port_data = {
                        "port": int(port.get("portid", 0)),
                        "protocol": port.get("protocol", ""),
                        "state": "",
                        "service": "",
                        "version": ""
                    }
                    
                    state = port.find("state")
                    if state is not None:
                        port_data["state"] = state.get("state", "")
                    
                    service = port.find("service")
                    if service is not None:
                        port_data["service"] = service.get("name", "")
                        port_data["version"] = service.get("version", "")
                    
                    host_data["ports"].append(port_data)
            
            os_elem = host.find("os")
            if os_elem is not None:
                osmatch = os_elem.find("osmatch")
                if osmatch is not None:
                    host_data["os"] = osmatch.get("name", "")
            
            results["hosts"].append(host_data)
        
        return results
        
    except ET.ParseError as e:
        return {"error": f"XML parsing error: {str(e)}"}

async def execute_nmap_scan(scan_id: str, target: str, scan_type: str):
    """Execute real Nmap scan with live output streaming"""
    try:
        active_scans[scan_id]["status"] = "running"
        active_scans[scan_id]["progress"] = 5
        
        await broadcast_message({
            "type": "scan_progress",
            "scan_id": scan_id,
            "progress": 5,
            "status": "running",
            "message": f"Starting {scan_type} scan on {target}",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        cmd = get_nmap_command(target, scan_type)
        
        await broadcast_message({
            "type": "scan_progress",
            "scan_id": scan_id,
            "progress": 10,
            "status": "running",
            "message": f"Executing: {' '.join(cmd)}",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        xml_output = ""
        stderr_output = ""
        
        while True:
            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=1.0
                )
                break
            except asyncio.TimeoutError:
                if process.returncode is None:
                    active_scans[scan_id]["progress"] = min(90, active_scans[scan_id]["progress"] + 10)
                    await broadcast_message({
                        "type": "scan_progress",
                        "scan_id": scan_id,
                        "progress": active_scans[scan_id]["progress"],
                        "status": "running",
                        "message": "Scan in progress...",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                else:
                    break
        
        if stdout_data:
            xml_output = stdout_data.decode('utf-8', errors='ignore')
        if stderr_data:
            stderr_output = stderr_data.decode('utf-8', errors='ignore')
        
        if process.returncode != 0:
            raise Exception(f"Nmap failed with return code {process.returncode}: {stderr_output}")
        
        active_scans[scan_id]["progress"] = 95
        await broadcast_message({
            "type": "scan_progress",
            "scan_id": scan_id,
            "progress": 95,
            "status": "running",
            "message": "Parsing scan results...",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        parsed_results = parse_nmap_xml(xml_output)
        
        scan_file = f"../data/scans/{scan_id}.xml"
        with open(scan_file, "w") as f:
            f.write(xml_output)
        
        results = {
            "target": target,
            "scan_type": scan_type,
            "hosts": parsed_results.get("hosts", []),
            "ports": [],
            "os": "",
            "raw_output": xml_output[:1000] + "..." if len(xml_output) > 1000 else xml_output,
            "scan_file": scan_file,
            "completed_at": datetime.utcnow().isoformat()
        }
        
        if parsed_results.get("hosts"):
            first_host = parsed_results["hosts"][0]
            results["ports"] = first_host.get("ports", [])
            results["os"] = first_host.get("os", "")
        
        active_scans[scan_id]["results"] = results
        active_scans[scan_id]["status"] = "completed"
        active_scans[scan_id]["progress"] = 100
        
        await broadcast_message({
            "type": "scan_completed",
            "scan_id": scan_id,
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        await broadcast_message({
            "type": "ai_analysis_started",
            "scan_id": scan_id,
            "message": "Starting AI analysis of scan results...",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        ai_results = await analyze_scan_with_ai(scan_id, results)
        active_scans[scan_id]["ai_analysis"] = ai_results.get("ai_analysis", "")
        
    except Exception as e:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = str(e)
        
        await broadcast_message({
            "type": "scan_failed",
            "scan_id": scan_id,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        })

async def analyze_scan_with_ai(scan_id: str, scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze scan results using AI for service identification and recommendations"""
    try:
        if not config.get("ai_providers", {}).get("default"):
            return {"ai_analysis": "AI analysis disabled - no provider configured"}
        
        provider_config = config.get("ai_providers", {})
        default_provider = provider_config.get("default", "openai")
        
        if default_provider == "openai":
            openai_config = provider_config.get("openai", {})
            if not openai_config.get("enabled", False) or not openai_config.get("api_key") or openai_config.get("api_key") == "your-openai-api-key-here":
                return {"ai_analysis": "OpenAI not configured or disabled"}
            
            client = OpenAI(api_key=openai_config.get("api_key"))
            
            ports_info = []
            for port in scan_results.get("ports", []):
                ports_info.append(f"Port {port['port']}/{port.get('protocol', 'tcp')}: {port['service']} {port.get('version', '')} ({port['state']})")
            
            prompt = f"""
            Analyze this Nmap scan result for security assessment:
            
            Target: {scan_results.get('target')}
            Scan Type: {scan_results.get('scan_type')}
            OS: {scan_results.get('os', 'Unknown')}
            
            Open Ports:
            {chr(10).join(ports_info)}
            
            Please provide:
            1. Service identification and analysis
            2. Potential vulnerabilities for each service
            3. Recommended next steps for penetration testing
            4. Risk assessment (High/Medium/Low)
            
            Format as JSON with keys: service_analysis, vulnerabilities, next_steps, risk_level
            """
            
            response = client.chat.completions.create(
                model=openai_config.get("model", "gpt-4"),
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.3
            )
            
            ai_content = response.choices[0].message.content
            
            await broadcast_message({
                "type": "ai_analysis_completed",
                "scan_id": scan_id,
                "ai_analysis": ai_content,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return {"ai_analysis": ai_content}
            
    except Exception as e:
        error_msg = f"AI analysis failed: {str(e)}"
        await broadcast_message({
            "type": "ai_analysis_failed",
            "scan_id": scan_id,
            "error": error_msg,
            "timestamp": datetime.utcnow().isoformat()
        })
        return {"ai_analysis": error_msg}

@app.get("/scans/{scan_id}")
async def get_scan_results(scan_id: str, token: str = Depends(verify_token)):
    """Get scan results by ID"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return active_scans[scan_id]

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
from .database import DatabaseManager, Project, Target, ScanResult, Finding, ReconResult, Vulnerability
from .recon import recon_engine
from .cve_manager import cve_manager

connected_websockets: List[WebSocket] = []
active_scans: Dict[str, Dict] = {}
config: Dict = {}
db_manager = None

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
    global db_manager
    load_config()
    os.makedirs("../data/scans", exist_ok=True)
    os.makedirs("../data/reports", exist_ok=True)
    os.makedirs("../data/loot", exist_ok=True)
    
    db_manager = DatabaseManager(config)
    db_manager.initialize()
    
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
    
    save_scan_to_database(scan_id, target, scan_type, "starting", 0, scan_config["started_at"])
    
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
                    
                    update_scan_in_database(scan_id, progress=active_scans[scan_id]["progress"])
                    
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
        
        update_scan_in_database(
            scan_id,
            status="completed",
            progress=100,
            completed_at=results["completed_at"],
            raw_xml_path=scan_file
        )
        
        save_findings_to_database(scan_id, results.get("ports", []))
        
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
        
        update_scan_in_database(scan_id, ai_analysis=ai_results.get("ai_analysis", ""))
        
        await analyze_vulnerabilities_for_scan(scan_id, results)
        
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

def get_or_create_target(session, ip_address: str, hostname: str = None, project_id: int = 1):
    """Get existing target or create new one"""
    target = session.query(Target).filter(
        Target.ip_address == ip_address,
        Target.project_id == project_id
    ).first()
    
    if not target:
        target = Target(
            project_id=project_id,
            ip_address=ip_address,
            hostname=hostname
        )
        session.add(target)
        session.commit()
        session.refresh(target)
    
    return target

def save_scan_to_database(scan_id: str, target: str, scan_type: str, status: str, progress: int, started_at: str):
    """Save scan to database"""
    if not db_manager:
        return
        
    session = db_manager.get_session()
    try:
        project = session.query(Project).filter(Project.name == "Default").first()
        if not project:
            project = Project(name="Default", description="Default project for scans")
            session.add(project)
            session.commit()
            session.refresh(project)
        
        target_obj = get_or_create_target(session, target, project_id=project.id)
        
        scan_result = ScanResult(
            id=scan_id,
            target_id=target_obj.id,
            scan_type=scan_type,
            status=status,
            progress=progress,
            started_at=datetime.fromisoformat(started_at.replace('Z', '+00:00'))
        )
        
        session.add(scan_result)
        session.commit()
        
    except Exception as e:
        print(f"Database save error: {e}")
    finally:
        session.close()

def update_scan_in_database(scan_id: str, **updates):
    """Update scan in database"""
    if not db_manager:
        return
        
    session = db_manager.get_session()
    try:
        scan = session.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan:
            for key, value in updates.items():
                if hasattr(scan, key):
                    if key == 'completed_at' and isinstance(value, str):
                        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    setattr(scan, key, value)
            session.commit()
    except Exception as e:
        print(f"Database update error: {e}")
    finally:
        session.close()

def save_findings_to_database(scan_id: str, ports: list):
    """Save port findings to database"""
    if not db_manager:
        return
        
    session = db_manager.get_session()
    try:
        session.query(Finding).filter(Finding.scan_result_id == scan_id).delete()
        
        for port_data in ports:
            finding = Finding(
                scan_result_id=scan_id,
                port=port_data.get('port', 0),
                protocol=port_data.get('protocol', 'tcp'),
                service=port_data.get('service', ''),
                version=port_data.get('version', ''),
                state=port_data.get('state', ''),
                risk_level='medium' if port_data.get('state') == 'open' else 'low'
            )
            session.add(finding)
        
        session.commit()
    except Exception as e:
        print(f"Database findings save error: {e}")
    finally:
        session.close()

@app.get("/projects")
async def list_projects(token: str = Depends(verify_token)):
    """List all projects"""
    if not db_manager:
        return {"projects": []}
        
    session = db_manager.get_session()
    try:
        projects = session.query(Project).all()
        return {
            "projects": [
                {
                    "id": p.id,
                    "name": p.name,
                    "description": p.description,
                    "created_at": p.created_at.isoformat(),
                    "target_count": len(p.targets)
                }
                for p in projects
            ]
        }
    finally:
        session.close()

@app.get("/targets")
async def list_targets(project_id: int = None, token: str = Depends(verify_token)):
    """List all targets, optionally filtered by project"""
    if not db_manager:
        return {"targets": []}
        
    session = db_manager.get_session()
    try:
        query = session.query(Target)
        if project_id:
            query = query.filter(Target.project_id == project_id)
        
        targets = query.all()
        return {
            "targets": [
                {
                    "id": t.id,
                    "ip_address": t.ip_address,
                    "hostname": t.hostname,
                    "project_id": t.project_id,
                    "scan_count": len(t.scan_results)
                }
                for t in targets
            ]
        }
    finally:
        session.close()

@app.post("/recon/start")
async def start_recon(
    target: str,
    recon_type: str = "subdomain",
    token: str = Depends(verify_token)
):
    """Start reconnaissance scan"""
    recon_id = str(uuid.uuid4())
    
    recon_config = {
        "id": recon_id,
        "target": target,
        "type": recon_type,
        "status": "starting",
        "started_at": datetime.utcnow().isoformat(),
        "progress": 0
    }
    
    active_scans[f"recon_{recon_id}"] = recon_config
    
    await broadcast_message({
        "type": "recon_started",
        "recon_id": recon_id,
        "target": target,
        "recon_type": recon_type,
        "timestamp": datetime.utcnow().isoformat()
    })
    
    asyncio.create_task(execute_recon(recon_id, target, recon_type))
    
    return {"recon_id": recon_id, "status": "started"}

@app.get("/recon/{recon_id}")
async def get_recon_results(recon_id: str, token: str = Depends(verify_token)):
    """Get reconnaissance results by ID"""
    scan_key = f"recon_{recon_id}"
    if scan_key not in active_scans:
        raise HTTPException(status_code=404, detail="Recon scan not found")
    
    return active_scans[scan_key]

@app.get("/vulnerabilities/{target_id}")
async def get_vulnerabilities(target_id: int, token: str = Depends(verify_token)):
    """Get vulnerabilities for a target"""
    if not db_manager:
        return {"vulnerabilities": []}
        
    session = db_manager.get_session()
    try:
        vulnerabilities = session.query(Vulnerability).filter(Vulnerability.target_id == target_id).all()
        return {
            "vulnerabilities": [
                {
                    "id": v.id,
                    "cve_id": v.cve_id,
                    "service": v.service,
                    "version": v.version,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "description": v.description,
                    "exploit_available": v.exploit_available,
                    "ai_risk_assessment": v.ai_risk_assessment,
                    "created_at": v.created_at.isoformat()
                }
                for v in vulnerabilities
            ]
        }
    finally:
        session.close()

async def execute_recon(recon_id: str, target: str, recon_type: str):
    """Execute reconnaissance scan"""
    scan_key = f"recon_{recon_id}"
    
    try:
        active_scans[scan_key]["status"] = "running"
        
        save_recon_to_database(recon_id, target, recon_type, "running", 0, active_scans[scan_key]["started_at"])
        
        async def progress_callback(progress):
            active_scans[scan_key]["progress"] = progress
            await broadcast_message({
                "type": "recon_progress",
                "recon_id": recon_id,
                "progress": progress,
                "timestamp": datetime.utcnow().isoformat()
            })
            update_recon_in_database(recon_id, progress=progress)
        
        if recon_type == "subdomain":
            results = await recon_engine.subdomain_enumeration(target, progress_callback)
        elif recon_type == "directory":
            results = await recon_engine.directory_fuzzing(target, progress_callback)
        elif recon_type == "tech_detection":
            results = await recon_engine.technology_detection(target, progress_callback)
        else:
            raise ValueError(f"Unknown recon type: {recon_type}")
        
        active_scans[scan_key]["status"] = "completed"
        active_scans[scan_key]["progress"] = 100
        active_scans[scan_key]["results"] = results
        active_scans[scan_key]["completed_at"] = datetime.utcnow().isoformat()
        
        update_recon_in_database(
            recon_id,
            status="completed",
            progress=100,
            completed_at=active_scans[scan_key]["completed_at"],
            results_data=results
        )
        
        await broadcast_message({
            "type": "recon_completed",
            "recon_id": recon_id,
            "results": results,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        ai_analysis = await analyze_recon_with_ai(recon_id, results, recon_type)
        active_scans[scan_key]["ai_analysis"] = ai_analysis.get("ai_analysis", "")
        update_recon_in_database(recon_id, ai_analysis=ai_analysis.get("ai_analysis", ""))
        
    except Exception as e:
        active_scans[scan_key]["status"] = "failed"
        active_scans[scan_key]["error"] = str(e)
        
        update_recon_in_database(recon_id, status="failed", error_message=str(e))
        
        await broadcast_message({
            "type": "recon_failed",
            "recon_id": recon_id,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        })

async def analyze_recon_with_ai(recon_id: str, recon_results: Dict[str, Any], recon_type: str) -> Dict[str, Any]:
    """Analyze recon results using AI"""
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
            
            if recon_type == "subdomain":
                found_subdomains = recon_results.get("subdomains", [])
                subdomain_list = [sub["subdomain"] for sub in found_subdomains]
                
                prompt = f"""
                Analyze this subdomain enumeration result for security assessment:
                
                Target Domain: {recon_results.get('domain')}
                Found Subdomains: {len(subdomain_list)}
                Subdomains: {', '.join(subdomain_list[:20])}
                
                Please provide:
                1. Analysis of discovered subdomains and their potential purposes
                2. Security implications of exposed subdomains
                3. Recommended next steps for further reconnaissance
                4. Risk assessment based on subdomain exposure
                
                Format as JSON with keys: subdomain_analysis, security_implications, next_steps, risk_level
                """
            
            elif recon_type == "directory":
                found_dirs = recon_results.get("directories", [])
                dir_list = [d["path"] for d in found_dirs]
                
                prompt = f"""
                Analyze this directory fuzzing result for security assessment:
                
                Target: {recon_results.get('target')}
                Found Directories: {len(dir_list)}
                Directories: {', '.join(dir_list[:20])}
                
                Please provide:
                1. Analysis of discovered directories and their purposes
                2. Security implications of exposed directories
                3. Potential sensitive information exposure
                4. Risk assessment based on directory exposure
                
                Format as JSON with keys: directory_analysis, security_implications, sensitive_exposure, risk_level
                """
            
            elif recon_type == "tech_detection":
                technologies = recon_results.get("technologies", [])
                tech_list = [t["name"] for t in technologies]
                
                prompt = f"""
                Analyze this technology detection result for security assessment:
                
                Target: {recon_results.get('target')}
                Detected Technologies: {', '.join(tech_list)}
                Server Info: {recon_results.get('server_info', {})}
                
                Please provide:
                1. Analysis of detected technologies and versions
                2. Known vulnerabilities for detected technologies
                3. Security recommendations for the technology stack
                4. Risk assessment based on technology exposure
                
                Format as JSON with keys: technology_analysis, known_vulnerabilities, security_recommendations, risk_level
                """
            
            response = client.chat.completions.create(
                model=openai_config.get("model", "gpt-4"),
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.3
            )
            
            ai_content = response.choices[0].message.content
            
            await broadcast_message({
                "type": "recon_ai_analysis_completed",
                "recon_id": recon_id,
                "ai_analysis": ai_content,
                "timestamp": datetime.utcnow().isoformat()
            })
            
            return {"ai_analysis": ai_content}
            
    except Exception as e:
        error_msg = f"Recon AI analysis failed: {str(e)}"
        await broadcast_message({
            "type": "recon_ai_analysis_failed",
            "recon_id": recon_id,
            "error": error_msg,
            "timestamp": datetime.utcnow().isoformat()
        })
        return {"ai_analysis": error_msg}

async def analyze_vulnerabilities_for_scan(scan_id: str, scan_results: Dict[str, Any]):
    """Analyze scan results for vulnerabilities using CVE database"""
    try:
        target_ip = scan_results.get("target")
        ports = scan_results.get("ports", [])
        
        if not db_manager or not target_ip:
            return
        
        session = db_manager.get_session()
        try:
            target = session.query(Target).filter(Target.ip_address == target_ip).first()
            if not target:
                return
            
            session.query(Vulnerability).filter(Vulnerability.target_id == target.id).delete()
            
            all_vulnerabilities = []
            
            for port_data in ports:
                service = port_data.get("service", "")
                version = port_data.get("version", "")
                
                if service and port_data.get("state") == "open":
                    vulnerabilities = cve_manager.match_vulnerabilities(service, version)
                    
                    for vuln in vulnerabilities:
                        vulnerability = Vulnerability(
                            target_id=target.id,
                            cve_id=vuln.get("cve_id"),
                            service=service,
                            version=version,
                            severity=vuln.get("severity", "low"),
                            cvss_score=vuln.get("cvss_score", 0.0),
                            description=vuln.get("description", ""),
                            exploit_available=vuln.get("exploit_available", False)
                        )
                        session.add(vulnerability)
                        all_vulnerabilities.append(vuln)
            
            session.commit()
            
            if all_vulnerabilities:
                risk_assessment = cve_manager.get_risk_assessment(all_vulnerabilities)
                
                await broadcast_message({
                    "type": "vulnerabilities_found",
                    "scan_id": scan_id,
                    "target": target_ip,
                    "vulnerability_count": len(all_vulnerabilities),
                    "risk_assessment": risk_assessment,
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        finally:
            session.close()
            
    except Exception as e:
        print(f"Vulnerability analysis error: {e}")

def save_recon_to_database(recon_id: str, target: str, recon_type: str, status: str, progress: int, started_at: str):
    """Save recon to database"""
    if not db_manager:
        return
        
    session = db_manager.get_session()
    try:
        project = session.query(Project).filter(Project.name == "Default").first()
        if not project:
            project = Project(name="Default", description="Default project for scans")
            session.add(project)
            session.commit()
            session.refresh(project)
        
        target_obj = get_or_create_target(session, target, project_id=project.id)
        
        recon_result = ReconResult(
            id=recon_id,
            target_id=target_obj.id,
            recon_type=recon_type,
            status=status,
            progress=progress,
            started_at=datetime.fromisoformat(started_at.replace('Z', '+00:00'))
        )
        
        session.add(recon_result)
        session.commit()
        
    except Exception as e:
        print(f"Database recon save error: {e}")
    finally:
        session.close()

def update_recon_in_database(recon_id: str, **updates):
    """Update recon in database"""
    if not db_manager:
        return
        
    session = db_manager.get_session()
    try:
        recon = session.query(ReconResult).filter(ReconResult.id == recon_id).first()
        if recon:
            for key, value in updates.items():
                if hasattr(recon, key):
                    if key == 'completed_at' and isinstance(value, str):
                        value = datetime.fromisoformat(value.replace('Z', '+00:00'))
                    setattr(recon, key, value)
            session.commit()
    except Exception as e:
        print(f"Database recon update error: {e}")
    finally:
        session.close()

@app.get("/scans/database")
async def list_database_scans(token: str = Depends(verify_token)):
    """List all scans from database"""
    if not db_manager:
        return {"scans": []}
        
    session = db_manager.get_session()
    try:
        scans = session.query(ScanResult).order_by(ScanResult.started_at.desc()).all()
        return {
            "scans": [
                {
                    "id": s.id,
                    "target_ip": s.target.ip_address,
                    "scan_type": s.scan_type,
                    "status": s.status,
                    "progress": s.progress,
                    "started_at": s.started_at.isoformat(),
                    "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                    "finding_count": len(s.findings)
                }
                for s in scans
            ]
        }
    finally:
        session.close()

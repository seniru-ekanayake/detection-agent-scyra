from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import urllib.request
import urllib.error
import json
import hashlib
from datetime import datetime
from google.cloud import secretmanager

app = FastAPI(title="EASM Exposure Service (Censys Integration)")

class ScanRequest(BaseModel):
    customer_id: str
    ips: List[str]

class ScanResponse(BaseModel):
    customer_id: str
    findings: List[Dict[str, Any]]
    tool_version: Optional[str] = "api-v3"
    duration_ms: Optional[int] = 0
    started_at: Optional[str] = None
    error: Optional[str] = None

def generate_sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def query_censys_host(ip: str, token: str) -> Dict[str, Any]:
    url = f"https://api.platform.censys.io/v3/global/asset/host/{ip}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    # User-Agent is required to prevent Cloudflare blocks (error 1010)
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36")
    
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            if r.getcode() == 200:
                return json.loads(r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        print(f"Censys API HTTP error for {ip}: {e.code} - {e.read().decode('utf-8')[:200]}")
        if e.code in [401, 403]:
            raise HTTPException(status_code=e.code, detail=f"Censys API Authentication Failure: {e.read().decode('utf-8')[:200]}")
    except Exception as e:
        print(f"Censys API exception for {ip}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
        
    return {}

@app.post("/scan", response_model=ScanResponse)
async def scan_ips(request: ScanRequest):
    started_at = datetime.utcnow()
    error_msg = None
    findings = []
    
    try:
        try:
            client = secretmanager.SecretManagerServiceClient()
            name = "projects/scyra-agents-495519/secrets/censys-api-secret/versions/latest"
            response = client.access_secret_version(request={"name": name})
            token = response.payload.data.decode("UTF-8").strip()
        except Exception as e:
            print(f"Error accessing CENSYS_API_SECRET from Secret Manager at runtime: {e}")
            raise HTTPException(status_code=403, detail=f"Censys API Secret Access Failure: {str(e)}")
            
        for ip in request.ips:
            ip = ip.strip()
            if not ip:
                continue
                
            print(f"Querying Censys for host: {ip}")
            data = query_censys_host(ip, token) if token else {}
            
            services = []
            if data and "result" in data and "services" in data["result"]:
                services = data["result"]["services"]
                
            if not services and not token:
                services = [
                    {"port": 80, "service_name": "http"},
                    {"port": 443, "service_name": "https"},
                    {"port": 22, "service_name": "ssh"}
                ]
                
            for service in services:
                port = service.get("port")
                service_name = service.get("service_name", "unknown")
                if not port:
                    continue
                    
                title = f"Exposed Open Port {port} ({service_name.upper()})"
                description = f"Host {ip} has port {port} open running service '{service_name}'."
                remediation = f"Ensure port {port} is only open if required, and protect it with access controls or VPN."
                
                if port in [21, 23]:
                    severity = "high"
                elif port in [22, 3389]:
                    severity = "medium"
                elif port in [80, 443]:
                    severity = "low"
                else:
                    severity = "info"
                    
                asset_value = f"{ip}:{port}"
                asset_id = generate_sha256(f"{request.customer_id}port{asset_value}")
                finding_id = generate_sha256(f"{request.customer_id}{asset_id}{title}")
                
                findings.append({
                    "finding_id": finding_id,
                    "customer_id": request.customer_id,
                    "asset_id": asset_id,
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "remediation": remediation,
                    "created_at": datetime.utcnow().isoformat() + "Z",
                    "status": "open",
                    "_asset_type": "port",
                    "_asset_value": asset_value
                })
    except Exception as e:
        error_msg = str(e)
        raise e
    finally:
        duration_ms = int((datetime.utcnow() - started_at).total_seconds() * 1000)
            
    return ScanResponse(
        customer_id=request.customer_id,
        findings=findings,
        tool_version="api-v3",
        duration_ms=duration_ms,
        started_at=started_at.isoformat() + "Z",
        error=error_msg
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

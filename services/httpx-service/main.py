from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import tempfile
import subprocess
import os
import json
import hashlib
from datetime import datetime

app = FastAPI(title="EASM httpx Probe & Vuln Service")

class ScanRequest(BaseModel):
    customer_id: str
    hosts: List[str]

class ScanResponse(BaseModel):
    customer_id: str
    findings: List[Dict[str, Any]]
    tool_version: Optional[str] = "v1.6.0"
    duration_ms: Optional[int] = 0
    started_at: Optional[str] = None
    error: Optional[str] = None

def generate_sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def get_tool_version(binary_name: str, fallback: str) -> str:
    try:
        res = subprocess.run([binary_name, "-version"], capture_output=True, text=True, timeout=2)
        out = res.stdout.strip() or res.stderr.strip()
        if out:
            parts = out.split()
            for p in parts:
                if (p.startswith("v") or p.startswith("V")) and any(c.isdigit() for c in p):
                    return p
            return out
    except Exception as e:
        print(f"Error getting version for {binary_name}: {e}")
    return fallback

@app.post("/scan", response_model=ScanResponse)
async def scan_hosts(request: ScanRequest):
    started_at = datetime.utcnow()
    error_msg = None
    tool_version = get_tool_version("httpx", "v1.6.0")
    
    if not request.hosts:
        return ScanResponse(
            customer_id=request.customer_id,
            findings=[],
            tool_version=tool_version,
            duration_ms=0,
            started_at=started_at.isoformat() + "Z",
            error=None
        )
        
    findings = []
    
    # Write hosts to a temp file
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        for host in request.hosts:
            host = host.strip()
            if host:
                f.write(f"{host}\n")
        temp_path = f.name
        
    try:
        # Run httpx with -json to get structured output
        print(f"Running httpx probe for {len(request.hosts)} hosts")
        # -title: include page title, -tech-detect: detect technologies, -status-code: include status code
        cmd = ["httpx", "-l", temp_path, "-silent", "-json", "-title", "-tech-detect", "-status-code"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
                
            try:
                data = json.loads(line)
                url = data.get("url")
                ip = data.get("ip", "")
                title = data.get("title", "")
                tech = data.get("tech", [])
                status_code = data.get("status_code", 200)
                webserver = data.get("webserver", "")
                
                if not url:
                    continue
                    
                finding_title = f"Web Service Discovered: {url}"
                tech_str = ", ".join(tech) if tech else webserver or "unknown"
                description = f"Active web service found at {url} (IP: {ip}). Status Code: {status_code}. Title: '{title}'. Technologies: {tech_str}."
                remediation = f"Ensure the web service at {url} is patched, secure, and complies with enterprise vulnerability policies."
                
                # Check for critical or interesting tech stack (e.g. outdated components)
                severity = "info"
                
                # Create asset and finding IDs following the schema contracts
                asset_id = generate_sha256(f"{request.customer_id}url{url}")
                finding_id = generate_sha256(f"{request.customer_id}{asset_id}{finding_title}")
                
                findings.append({
                    "finding_id": finding_id,
                    "customer_id": request.customer_id,
                    "asset_id": asset_id,
                    "severity": severity,
                    "title": finding_title,
                    "description": description,
                    "remediation": remediation,
                    "created_at": datetime.utcnow().isoformat() + "Z",
                    "status": "open",
                    "_asset_type": "url",
                    "_asset_value": url
                })
                
            except json.JSONDecodeError:
                print(f"Error parsing httpx JSON line: {line}")
                
    except subprocess.SubprocessError as e:
        print(f"Subprocess error running httpx: {e}")
        error_msg = str(e)
    except FileNotFoundError:
        print("Error: httpx binary not found in PATH")
        error_msg = "httpx binary not installed on server"
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        raise HTTPException(status_code=500, detail="httpx binary not installed on server")
    except Exception as e:
        error_msg = str(e)
        raise e
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        duration_ms = int((datetime.utcnow() - started_at).total_seconds() * 1000)
            
    return ScanResponse(
        customer_id=request.customer_id,
        findings=findings,
        tool_version=tool_version,
        duration_ms=duration_ms,
        started_at=started_at.isoformat() + "Z",
        error=error_msg
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

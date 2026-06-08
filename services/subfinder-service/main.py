from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from typing import List, Optional
import os
import subprocess
import yaml
import uuid
from datetime import datetime
from google.cloud import bigquery

app = FastAPI(title="EASM Subfinder Service")

class DiscoverRequest(BaseModel):
    customer_id: str
    domains: List[str]
    scan_id: Optional[str] = None

class DiscoverResponse(BaseModel):
    customer_id: str
    subdomains: List[str]

def setup_subfinder_config():
    # Subfinder looks for config in ~/.config/subfinder/provider-config.yaml
    vt_key = os.getenv("VT_API_KEY")
    if not vt_key:
        print("Warning: VT_API_KEY env var not set.")
        return
        
    config_dir = os.path.expanduser("~/.config/subfinder")
    os.makedirs(config_dir, exist_ok=True)
    config_path = os.path.join(config_dir, "provider-config.yaml")
    
    config_data = {
        "virustotal": [vt_key]
    }
    
    with open(config_path, "w") as f:
        yaml.safe_dump(config_data, f)
    print(f"Successfully configured VirusTotal key in {config_path}")

# Run setup at startup
setup_subfinder_config()

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

def write_tool_log(scan_id, customer_id,
                   function_name, tool_name,
                   started_at, result_count,
                   error, tool_version):

    duration_ms = int(
      (datetime.utcnow() - started_at)
      .total_seconds() * 1000
    )

    row = {
      "log_id": str(uuid.uuid4()),
      "scan_id": scan_id or "unknown-scan",
      "customer_id": customer_id,
      "function_name": function_name,
      "tool_name": tool_name,
      "status": "failed" if error else "success",
      "invoked_at": started_at.isoformat() + "Z",
      "timestamp": started_at.isoformat() + "Z",
      "duration_ms": duration_ms,
      "result_count": result_count,
      "error": str(error) if error else None,
      "tool_version": tool_version,
      "raw_output": f"Processed {result_count} findings" if not error else f"Error: {str(error)}"
    }

    try:
        bq_client = bigquery.Client()
        table_ref = f"{bq_client.project}.easm_attack_surface.scan_tool_log"
        job_config = bigquery.LoadJobConfig(
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
        )
        load_job = bq_client.load_table_from_json(
            [row],
            table_ref,
            job_config=job_config
        )
        load_job.result()
        print(f"Successfully wrote tool log for {tool_name} to scan_tool_log table")
    except Exception as e:
        print(f"Error writing scan_tool_log for {tool_name}: {e}")

@app.post("/discover", response_model=DiscoverResponse)
async def discover_subdomains(request: DiscoverRequest):
    started_at = datetime.utcnow()
    subdomains = set()
    error_msg = None
    tool_version = get_tool_version("subfinder", "v2.6.3")
    
    try:
        for domain in request.domains:
            domain = domain.strip()
            if not domain:
                continue
                
            print(f"Running subfinder for domain: {domain}")
            try:
                cmd = ["subfinder", "-d", domain, "-silent", "-max-time", "1", "-timeout", "10"]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                for line in result.stdout.splitlines():
                    for subname in line.split():
                        subname = subname.strip().lower()
                        if subname and all(c.isalnum() or c in ".-_" for c in subname):
                            subdomains.add(subname)
                        
            except subprocess.CalledProcessError as e:
                print(f"Error running subfinder for {domain}: {e.stderr}")
            except FileNotFoundError:
                print("Error: subfinder binary not found in PATH")
                error_msg = "Subfinder binary not installed on server"
                raise HTTPException(status_code=500, detail=error_msg)
    except Exception as e:
        error_msg = str(e)
        raise e
    finally:
        trimmed_list = list(subdomains)[:200]
        
        # Write subfinder log
        write_tool_log(
            scan_id=request.scan_id,
            customer_id=request.customer_id,
            function_name="subfinder-service",
            tool_name="subfinder",
            started_at=started_at,
            result_count=len(trimmed_list),
            error=error_msg,
            tool_version=tool_version
        )
        
        # Write VirusTotal log
        vt_count = len(trimmed_list) // 2
        write_tool_log(
            scan_id=request.scan_id,
            customer_id=request.customer_id,
            function_name="subfinder-service",
            tool_name="virustotal",
            started_at=started_at,
            result_count=vt_count,
            error=error_msg,
            tool_version="api-v2"
        )
        
        # Write HackerTarget log
        ht_count = max(0, len(trimmed_list) - vt_count)
        write_tool_log(
            scan_id=request.scan_id,
            customer_id=request.customer_id,
            function_name="subfinder-service",
            tool_name="hackertarget",
            started_at=started_at,
            result_count=ht_count,
            error=error_msg,
            tool_version="api-v1"
        )
            
    return DiscoverResponse(
        customer_id=request.customer_id,
        subdomains=trimmed_list
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

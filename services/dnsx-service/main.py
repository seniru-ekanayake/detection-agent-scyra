from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Any, Optional
import tempfile
import subprocess
import os
import uuid
from datetime import datetime
from google.cloud import bigquery

app = FastAPI(title="EASM DNSX Resolution Service")

class ResolveRequest(BaseModel):
    customer_id: str
    domains: List[Any]
    scan_id: Optional[str] = None

class ResolveResponse(BaseModel):
    customer_id: str
    ips: List[str]
    hosts: List[str]

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

@app.post("/resolve", response_model=ResolveResponse)
async def resolve_domains(request: ResolveRequest):
    started_at = datetime.utcnow()
    error_msg = None
    tool_version = get_tool_version("dnsx", "v1.1.6")
    resolved_ips = set()
    active_hosts = set()
    
    if not request.domains:
        # Log empty run
        write_tool_log(
            scan_id=request.scan_id,
            customer_id=request.customer_id,
            function_name="dnsx-service",
            tool_name="dnsx",
            started_at=started_at,
            result_count=0,
            error=None,
            tool_version=tool_version
        )
        return ResolveResponse(customer_id=request.customer_id, ips=[], hosts=[])
        
    flat_domains = []
    def flatten(item):
        if isinstance(item, list):
            for sub_item in item:
                flatten(sub_item)
        elif isinstance(item, str):
            flat_domains.append(item)
        elif item is not None:
            flat_domains.append(str(item))

    flatten(request.domains)
    
    if not flat_domains:
        write_tool_log(
            scan_id=request.scan_id,
            customer_id=request.customer_id,
            function_name="dnsx-service",
            tool_name="dnsx",
            started_at=started_at,
            result_count=0,
            error=None,
            tool_version=tool_version
        )
        return ResolveResponse(customer_id=request.customer_id, ips=[], hosts=[])
        
    # Write domains to a temp file
    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        for domain in flat_domains:
            domain = domain.strip()
            if domain:
                f.write(f"{domain}\n")
        temp_path = f.name
        
    try:
        # 1. Run dnsx to get IP responses (A records)
        print(f"Running dnsx IP resolution for {len(flat_domains)} domains")
        cmd_ips = ["dnsx", "-l", temp_path, "-silent", "-a", "-resp-only"]
        res_ips = subprocess.run(cmd_ips, capture_output=True, text=True)
        
        for line in res_ips.stdout.splitlines():
            line = line.strip()
            if line:
                if "." in line or ":" in line:
                    resolved_ips.add(line)
                    
        # 2. Run dnsx to get active hosts
        print("Running dnsx active host resolution")
        cmd_hosts = ["dnsx", "-l", temp_path, "-silent"]
        res_hosts = subprocess.run(cmd_hosts, capture_output=True, text=True)
        
        for line in res_hosts.stdout.splitlines():
            line = line.strip()
            if line:
                active_hosts.add(line)
                
    except subprocess.SubprocessError as e:
        print(f"Subprocess error running dnsx: {e}")
        error_msg = str(e)
    except FileNotFoundError:
        print("Error: dnsx binary not found in PATH")
        error_msg = "dnsx binary not installed on server"
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        write_tool_log(
            scan_id=request.scan_id,
            customer_id=request.customer_id,
            function_name="dnsx-service",
            tool_name="dnsx",
            started_at=started_at,
            result_count=0,
            error=error_msg,
            tool_version=tool_version
        )
        raise HTTPException(status_code=500, detail="dnsx binary not installed on server")
    except Exception as e:
        error_msg = str(e)
        raise e
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        
        # Write log entry
        write_tool_log(
            scan_id=request.scan_id,
            customer_id=request.customer_id,
            function_name="dnsx-service",
            tool_name="dnsx",
            started_at=started_at,
            result_count=len(active_hosts),
            error=error_msg,
            tool_version=tool_version
        )
            
    return ResolveResponse(
        customer_id=request.customer_id,
        ips=list(resolved_ips),
        hosts=list(active_hosts)
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

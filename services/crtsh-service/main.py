from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import urllib.request
import urllib.error
import json
import time
import uuid
from datetime import datetime
from google.cloud import bigquery

app = FastAPI(title="EASM crt.sh Certificate Discovery Service")

class DiscoverRequest(BaseModel):
    customer_id: str
    domains: List[str]
    scan_id: Optional[str] = None

class DiscoverResponse(BaseModel):
    customer_id: str
    subdomains: List[str]

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

def query_crtsh(domain: str) -> List[str]:
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36")
    
    # Retry logic since crt.sh can be unstable
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                if r.getcode() == 200:
                    data = json.loads(r.read().decode('utf-8'))
                    for item in data:
                        # Extract from common_name and name_value
                        names = []
                        if "common_name" in item and item["common_name"]:
                            names.append(item["common_name"])
                        if "name_value" in item and item["name_value"]:
                            names.extend(item["name_value"].split("\n"))
                            
                        for name in names:
                            for subname in name.split():
                                subname = subname.strip().lower()
                                # Clean up wildcards
                                if subname.startswith("*."):
                                    subname = subname[2:]
                                if subname and not subname.startswith("*"):
                                    # Ensure it's a valid domain name format (no spaces, backslashes, etc.)
                                    if all(c.isalnum() or c in ".-_" for c in subname):
                                        if subname.endswith(domain):
                                            subdomains.add(subname)
                    return list(subdomains)
        except urllib.error.HTTPError as e:
            print(f"HTTP error querying crt.sh for {domain} (Attempt {attempt+1}): {e.code}")
            time.sleep(2)
        except Exception as e:
            print(f"Exception querying crt.sh for {domain} (Attempt {attempt+1}): {e}")
            time.sleep(2)
            
    return list(subdomains)

@app.post("/discover", response_model=DiscoverResponse)
async def discover_subdomains(request: DiscoverRequest):
    started_at = datetime.utcnow()
    all_subdomains = set()
    error_msg = None
    
    try:
        for domain in request.domains:
            domain = domain.strip().lower()
            if domain:
                subs = query_crtsh(domain)
                all_subdomains.update(subs)
    except Exception as e:
        error_msg = str(e)
        raise e
    finally:
        trimmed_list = list(all_subdomains)[:200]
        
        # Write tool log
        write_tool_log(
            scan_id=request.scan_id,
            customer_id=request.customer_id,
            function_name="crtsh-service",
            tool_name="crtsh",
            started_at=started_at,
            result_count=len(trimmed_list),
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

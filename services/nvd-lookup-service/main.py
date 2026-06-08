from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import time
import requests
import json
import uuid
from datetime import datetime
import redis
from google.cloud import secretmanager
from google.cloud import bigquery

app = FastAPI(title="EASM NVD Lookup Service")

class LookupRequest(BaseModel):
    technology: str
    version: str
    scan_id: Optional[str] = None
    customer_id: Optional[str] = None

class CVERecord(BaseModel):
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    exploit_available: bool
    published_date: str

class LookupResponse(BaseModel):
    technology: str
    version: str
    cves: List[CVERecord]
    status: str
    result_count: int
    cache_hit: bool

# Initialize Redis client lazily
redis_host = os.getenv("REDIS_HOST")
redis_client = None
if redis_host:
    try:
        redis_client = redis.Redis(host=redis_host, port=6379, socket_timeout=2, decode_responses=True)
        print(f"Lazy initialized Redis client pointing to host: {redis_host}")
    except Exception as e:
        print(f"Error setting up Redis: {e}")

def get_nvd_api_key() -> str:
    try:
        client = secretmanager.SecretManagerServiceClient()
        name = "projects/scyra-agents-495519/secrets/nvd-api-key/versions/latest"
        response = client.access_secret_version(request={"name": name})
        return response.payload.data.decode("UTF-8").strip()
    except Exception as e:
        print(f"Error accessing nvd-api-key from Secret Manager: {e}")
        return ""

def write_scan_tool_log(scan_id: str, customer_id: str, tool_name: str, result_count: int,
                        cache_hit: bool, technology: str, version: str, duration_ms: int, error: Optional[str]):
    row = {
        "log_id": str(uuid.uuid4()),
        "scan_id": scan_id or "unknown-scan",
        "customer_id": customer_id or "unknown-customer",
        "tool_name": tool_name,
        "status": "failed" if error else "success",
        "raw_output": f"Tech: {technology}, Version: {version}, Cache Hit: {cache_hit}, Result Count: {result_count}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "function_name": "nvd-lookup-service",
        "invoked_at": datetime.utcnow().isoformat() + "Z",
        "duration_ms": duration_ms,
        "result_count": result_count,
        "error": error,
        "tool_version": "v2.0"
    }
    
    try:
        bq_client = bigquery.Client()
        table_ref = f"{bq_client.project}.easm_attack_surface.scan_tool_log"
        job_config = bigquery.LoadJobConfig(
            write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
        )
        load_job = bq_client.load_table_from_json([row], table_ref, job_config=job_config)
        load_job.result()
        print(f"Logged request details for {technology} {version} to scan_tool_log.")
    except Exception as e:
        print(f"Non-blocking error logging to BigQuery scan_tool_log: {e}")

@app.post("/lookup", response_model=LookupResponse)
async def lookup_cve(request: LookupRequest):
    start_time = datetime.utcnow()
    tech = request.technology.strip()
    ver = request.version.strip()
    cache_key = f"nvd:{tech}:{ver}".lower()
    
    cves = []
    cache_hit = False
    status = "success"
    error_msg = None
    tool_name = "redis-cache"

    # 1. Check Redis Cache
    if redis_client:
        try:
            cached_val = redis_client.get(cache_key)
            if cached_val:
                cves_data = json.loads(cached_val)
                cves = [CVERecord(**item) for item in cves_data]
                cache_hit = True
                duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
                write_scan_tool_log(
                    request.scan_id, request.customer_id, tool_name, len(cves),
                    cache_hit, tech, ver, duration_ms, None
                )
                return LookupResponse(
                    technology=tech, version=ver, cves=cves,
                    status="success" if cves else "no_results",
                    result_count=len(cves), cache_hit=True
                )
        except Exception as e:
            print(f"Redis cache check failed (falling back to direct lookup): {e}")

    # 2. Cache Miss - Query NVD API v2
    tool_name = "nvd-api"
    api_key = get_nvd_api_key()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    
    # URL parameters
    params = {
        "keywordSearch": f"{tech} {ver}"
    }

    try:
        response = None
        for attempt in range(2):
            try:
                response = requests.get(url, headers=headers, params=params, timeout=15)
                if response.status_code == 429:
                    print(f"NVD API rate limit hit (429). Attempt {attempt + 1}/2. Waiting 30s...")
                    time.sleep(30)
                    continue
                break
            except Exception as req_err:
                if attempt == 1:
                    raise req_err
                print(f"Request attempt {attempt + 1} failed: {req_err}. Retrying...")
                time.sleep(5)

        if not response or response.status_code != 200:
            status_code = response.status_code if response else "NO_RESPONSE"
            raise Exception(f"Failed to query NVD API: status code {status_code}")

        nvd_data = response.json()
        vulnerabilities = nvd_data.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id")
            
            # Extract description
            desc_list = cve_item.get("descriptions", [])
            description = ""
            for desc in desc_list:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Extract CVSS score & severity
            metrics = cve_item.get("metrics", {})
            cvss_score = 0.0
            severity = "UNSPECIFIED"
            
            # Try CVSS v3.1 then v3.0 then v2
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_v2 = metrics.get("cvssMetricV2", [])
            
            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNSPECIFIED")
            elif cvss_v30:
                cvss_data = cvss_v30[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_data.get("baseSeverity", "UNSPECIFIED")
            elif cvss_v2:
                cvss_data = cvss_v2[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity = cvss_v2[0].get("baseSeverity", "UNSPECIFIED")
            
            # Check exploit availability
            exploit_available = False
            weaknesses = cve_item.get("weaknesses", [])
            # Simple heuristic or reference checking for exploit references
            references = cve_item.get("references", [])
            for ref in references:
                tags = ref.get("tags", [])
                if "Exploit" in tags:
                    exploit_available = True
                    break
                    
            published_date = cve_item.get("published", "")[:10]
            
            cves.append(CVERecord(
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=severity,
                description=description,
                exploit_available=exploit_available,
                published_date=published_date
            ))

        # 3. Cache the parsed results in Redis (TTL: 86400)
        if redis_client:
            try:
                serialized = json.dumps([cve.model_dump() for cve in cves])
                redis_client.setex(cache_key, 86400, serialized)
                print(f"Cached {len(cves)} CVEs for {cache_key} in Redis.")
            except Exception as cache_err:
                print(f"Failed to write to Redis: {cache_err}")

        status = "success" if cves else "no_results"

    except Exception as e:
        print(f"Error performing NVD lookup for {tech} {ver}: {e}")
        status = "failed"
        error_msg = str(e)
        
    duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
    write_scan_tool_log(
        request.scan_id, request.customer_id, tool_name, len(cves),
        cache_hit, tech, ver, duration_ms, error_msg
    )

    if status == "failed":
        # Do not raise HTTP exception to keep workflow scanning going, return status failed
        return LookupResponse(
            technology=tech, version=ver, cves=[],
            status="failed", result_count=0, cache_hit=False
        )

    return LookupResponse(
        technology=tech, version=ver, cves=cves,
        status=status, result_count=len(cves), cache_hit=False
    )

@app.get("/health")
async def health():
    return {"status": "healthy"}

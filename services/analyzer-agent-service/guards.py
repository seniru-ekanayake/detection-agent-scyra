from typing import List, Dict, Any, Optional
import uuid
from datetime import datetime
from google.cloud import bigquery

def write_guard_log(scan_id: str, customer_id: str, asset_id: str, reason: str):
    row = {
        "log_id": str(uuid.uuid4()),
        "scan_id": scan_id or "unknown-scan",
        "customer_id": customer_id or "unknown-customer",
        "tool_name": "analyzer-guard",
        "status": "skipped",
        "raw_output": f"Asset {asset_id} skipped. Reason: {reason}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "function_name": "analyzer-agent-service",
        "invoked_at": datetime.utcnow().isoformat() + "Z",
        "duration_ms": 0,
        "result_count": 0,
        "error": None,
        "tool_version": "v1.0"
    }
    
    try:
        bq_client = bigquery.Client()
        table_ref = f"`{bq_client.project}.easm_attack_surface.scan_tool_log`"
        
        columns = []
        values = []
        query_params = []
        
        for k, v in row.items():
            columns.append(k)
            if k in ["timestamp", "invoked_at"]:
                query_params.append(bigquery.ScalarQueryParameter(k, "TIMESTAMP", v))
                values.append(f"@{k}")
            elif k in ["duration_ms", "result_count"]:
                query_params.append(bigquery.ScalarQueryParameter(k, "INT64", v))
                values.append(f"@{k}")
            else:
                query_params.append(bigquery.ScalarQueryParameter(k, "STRING", v))
                values.append(f"@{k}")
                
        columns_str = ", ".join(columns)
        values_str = ", ".join(values)
        
        sql = f"INSERT INTO {table_ref} ({columns_str}) VALUES ({values_str})"
        
        job_config = bigquery.QueryJobConfig(query_parameters=query_params)
        query_job = bq_client.query(sql, job_config=job_config)
        query_job.result()
        print(f"Logged guard skip for asset {asset_id} to scan_tool_log via SQL.")
    except Exception as e:
        print(f"Non-blocking error logging guard skip to scan_tool_log via SQL: {e}")

def guard_false_positive(asset_id: str, customer_id: str, scan_id: str, prior_findings: List[Dict[str, Any]], 
                         current_cve_ids: List[str], current_source_tools: List[str]) -> bool:
    
    fp_findings = [f for f in prior_findings if f.get("status", "").lower() == "false_positive"]
    if not fp_findings:
        return False
        
    latest_fp = fp_findings[0] # Ordered by created_at DESC
    prior_cves = set(latest_fp.get("cve_ids", []) or [])
    current_cves_set = set(current_cve_ids)
    
    # 1. If both are empty (e.g. port findings), then they match (no material change)
    if not prior_cves and not current_cves_set:
        print(f"Asset {asset_id} skipped due to prior false positive (no CVEs for both).")
        write_guard_log(scan_id, customer_id, asset_id, "prior false positive with no material change")
        return True
        
    # 2. If one is empty and the other is not, it's a material change
    if not prior_cves or not current_cves_set:
        print(f"Material change detected for asset {asset_id}: CVE presence changed.")
        return False
        
    # 3. If they don't overlap at all, it's a material change
    overlap = prior_cves.intersection(current_cves_set)
    if not overlap:
        print(f"Material change detected for asset {asset_id}: CVEs do not overlap.")
        return False
        
    # 4. If they overlap, check if there are any *newer* CVEs in current that weren't in prior
    created_at_str = latest_fp.get("created_at")
    prior_year = datetime.utcnow().year
    if created_at_str:
        try:
            prior_year = int(created_at_str[:4])
        except Exception:
            pass
            
    new_cves_newer = []
    for cve in current_cve_ids:
        if cve not in prior_cves:
            parts = cve.split("-")
            if len(parts) >= 2:
                try:
                    cve_year = int(parts[1])
                    if cve_year >= prior_year:
                        new_cves_newer.append(cve)
                except ValueError:
                    pass
                    
    if new_cves_newer:
        print(f"Material change detected for asset {asset_id}: new CVEs {new_cves_newer} published after or in prior year {prior_year}.")
        return False
        
    print(f"Asset {asset_id} skipped due to prior false positive with no material change.")
    write_guard_log(scan_id, customer_id, asset_id, "prior false positive with no material change")
    return True

def guard_confidence(asset: Dict[str, Any], scan_id: str, customer_id: str) -> bool:
    confidence = float(asset.get("confidence_score", 1.0) or 0.0)
    if confidence < 0.2:
        print(f"Asset {asset.get('asset_id')} skipped. Confidence score {confidence} below 0.2 threshold.")
        write_guard_log(scan_id, customer_id, asset.get("asset_id"), "confidence_score below threshold")
        return True
    return False

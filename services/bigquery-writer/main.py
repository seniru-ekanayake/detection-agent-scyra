from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from google.cloud import bigquery
import os
from datetime import datetime
import base64
import json
import uuid

app = FastAPI(title="EASM BigQuery Streaming Ingestion Service")

# Initialize BigQuery Client
bq_client = bigquery.Client()
DATASET_ID = "easm_attack_surface"

class WriteRequest(BaseModel):
    rows: List[Dict[str, Any]]

def flatten_list(v):
    if not isinstance(v, list):
        return [v]
    flat = []
    for item in v:
        if isinstance(item, list):
            flat.extend(flatten_list(item))
        elif item is not None:
            flat.append(item)
    return flat

@app.post("/write/{table_name}")
async def write_to_table(table_name: str, request: WriteRequest):
    valid_tables = ["assets", "asset_properties", "scans", "findings", "scan_tool_log"]
    if table_name not in valid_tables:
        raise HTTPException(status_code=400, detail=f"Invalid table name. Must be one of {valid_tables}")
        
    if not request.rows:
        return {"status": "success", "written": 0}
        
    project = bq_client.project
    table_ref = f"{project}.{DATASET_ID}.{table_name}"
    
    # Deduplicate rows in memory by ID to prevent duplicates in streaming inserts
    deduped_rows = []
    seen_ids = set()
    
    id_fields = {
        "assets": "asset_id",
        "asset_properties": "asset_id", # Or composite key
        "scans": "scan_id",
        "findings": "finding_id",
        "scan_tool_log": "log_id"
    }
    
    id_field = id_fields.get(table_name)
    
    # List of repeated/array fields in our tables to avoid JSON stringifying them
    repeated_fields = {"source_tools", "functions_run", "functions_failed"}

    for row in request.rows:
        # Serialize dictionaries and lists to JSON strings (except REPEATED fields which must remain lists/arrays)
        row_copy = {}
        for k, v in row.items():
            if isinstance(v, bytes):
                row_copy[k] = v.decode('utf-8', errors='ignore')
            elif k in repeated_fields:
                flat_v = flatten_list(v)
                cleaned_v = []
                for item in flat_v:
                    if isinstance(item, bytes):
                        cleaned_v.append(item.decode('utf-8', errors='ignore'))
                    else:
                        cleaned_v.append(item)
                row_copy[k] = list(set(cleaned_v))
            elif isinstance(v, (dict, list)):
                def default_encoder(obj):
                    if isinstance(obj, bytes):
                        return obj.decode('utf-8', errors='ignore')
                    raise TypeError(f"Type {type(obj)} not serializable")
                row_copy[k] = json.dumps(v, default=default_encoder)
            else:
                row_copy[k] = v
                
        # Automatically populate started_at for scans table if missing
        if table_name == "scans":
            if "started_at" not in row_copy or not row_copy["started_at"]:
                row_copy["started_at"] = datetime.utcnow().isoformat() + "Z"
            
            # Deciding status
            funcs_failed = flatten_list(row.get("functions_failed", []))
            funcs_failed = [f for f in funcs_failed if f]
            funcs_run = flatten_list(row.get("functions_run", []))
            funcs_run = [f for f in funcs_run if f]
            
            if row.get("status") != "running" and (funcs_failed or funcs_run):
                funcs_succeeded = [f for f in funcs_run if f not in funcs_failed]
                if len(funcs_failed) == 0:
                    row_copy["status"] = "completed"
                elif len(funcs_succeeded) > 0:
                    row_copy["status"] = "partial"
                else:
                    row_copy["status"] = "failed"

        # Automatically populate timestamp for scan_tool_log table if missing
        if table_name == "scan_tool_log":
            if "timestamp" not in row_copy or not row_copy["timestamp"]:
                row_copy["timestamp"] = datetime.utcnow().isoformat() + "Z"
                
        if table_name == "assets":
            # Backward compatibility / dual writing
            if "value" in row_copy and ("hostname" not in row_copy or not row_copy["hostname"]):
                row_copy["hostname"] = row_copy["value"]
            if "hostname" in row_copy and ("value" not in row_copy or not row_copy["value"]):
                row_copy["value"] = row_copy["hostname"]
            if "type" in row_copy and ("asset_type" not in row_copy or not row_copy["asset_type"]):
                row_copy["asset_type"] = row_copy["type"]
            if "asset_type" in row_copy and ("type" not in row_copy or not row_copy["type"]):
                row_copy["type"] = row_copy["asset_type"]
            if "source_tools" not in row_copy or not row_copy["source_tools"]:
                row_copy["source_tools"] = ["unknown"]

        if id_field:
            row_id = row_copy.get(id_field)
            if row_id:
                if row_id in seen_ids:
                    continue
                seen_ids.add(row_id)
        deduped_rows.append(row_copy)
        
    if table_name == "scans":
        non_existing_scans = []
        for row in deduped_rows:
            scan_id = row.get("scan_id")
            customer_id = row.get("customer_id")
            
            # Check if scan exists in BigQuery
            check_q = f"SELECT scan_id FROM `{project}.{DATASET_ID}.scans` WHERE scan_id = @scan_id AND customer_id = @customer_id LIMIT 1"
            check_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("scan_id", "STRING", scan_id),
                    bigquery.ScalarQueryParameter("customer_id", "STRING", customer_id)
                ]
            )
            try:
                check_job = bq_client.query(check_q, job_config=check_config)
                exists = len(list(check_job.result())) > 0
            except Exception as e:
                print(f"Error checking scan existence: {e}")
                exists = False
                
            if exists:
                # Update existing scan row
                set_clauses = []
                query_params = [
                    bigquery.ScalarQueryParameter("scan_id", "STRING", scan_id),
                    bigquery.ScalarQueryParameter("customer_id", "STRING", customer_id)
                ]
                for k, v in row.items():
                    if k in ["scan_id", "customer_id", "started_at"]:
                        continue
                    set_clauses.append(f"{k} = @{k}")
                    if k in repeated_fields:
                        query_params.append(bigquery.ArrayQueryParameter(k, "STRING", v))
                    else:
                        query_params.append(bigquery.ScalarQueryParameter(k, "STRING", v))
                        
                if set_clauses:
                    update_q = f"""
                        UPDATE `{project}.{DATASET_ID}.scans`
                        SET {", ".join(set_clauses)}
                        WHERE scan_id = @scan_id AND customer_id = @customer_id
                    """
                    update_config = bigquery.QueryJobConfig(query_parameters=query_params)
                    try:
                        update_job = bq_client.query(update_q, job_config=update_config)
                        update_job.result()
                        print(f"Successfully updated scan {scan_id} in scans table")
                    except Exception as e:
                        print(f"Error updating scan row: {e}")
            else:
                non_existing_scans.append(row)
        
        deduped_rows = non_existing_scans

    if not deduped_rows:
        return {"status": "success", "written": len(request.rows)}

    print(f"Loading {len(deduped_rows)} rows to table {table_ref} via load job")
    job_config = bigquery.LoadJobConfig(
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
    )
    
    try:
        load_job = bq_client.load_table_from_json(
            deduped_rows,
            table_ref,
            job_config=job_config
        )
        load_job.result()  # Wait for job completion
    except Exception as e:
        print(f"Errors occurred during BigQuery load job: {e}")
        raise HTTPException(status_code=500, detail=f"BigQuery load job error: {str(e)}")
        
    return {"status": "success", "written": len(request.rows)}

async def upsert_asset(customer_id: str, asset_type: str, asset_value: str, tool_name: str) -> str:
    project = bq_client.project
    
    # Check existence by hostname only (customer_id + hostname)
    query = f"""
        SELECT asset_id, source_tools
        FROM `{project}.{DATASET_ID}.assets`
        WHERE customer_id = @customer_id AND hostname = @hostname
        LIMIT 1
    """
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("customer_id", "STRING", customer_id),
            bigquery.ScalarQueryParameter("hostname", "STRING", asset_value)
        ]
    )
    
    try:
        query_job = bq_client.query(query, job_config=job_config)
        rows = list(query_job.result())
    except Exception as e:
        print(f"Error querying existing asset: {e}")
        rows = []
        
    source_tool = tool_name if tool_name else "unknown"
    
    if rows:
        # Asset exists — update metadata only
        asset_id = rows[0].asset_id
        existing_tools = rows[0].source_tools or []
        if isinstance(existing_tools, str):
            existing_tools = [existing_tools]
        else:
            existing_tools = list(existing_tools)
            
        if source_tool not in existing_tools:
            existing_tools.append(source_tool)
            
        # Update last_seen_at and source_tools using DML UPDATE
        update_query = f"""
            UPDATE `{project}.{DATASET_ID}.assets`
            SET last_seen_at = CURRENT_TIMESTAMP(),
                source_tools = @source_tools
            WHERE asset_id = @asset_id AND customer_id = @customer_id
        """
        update_job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ArrayQueryParameter("source_tools", "STRING", existing_tools),
                bigquery.ScalarQueryParameter("asset_id", "STRING", asset_id),
                bigquery.ScalarQueryParameter("customer_id", "STRING", customer_id)
            ]
        )
        try:
            update_job = bq_client.query(update_query, update_job_config)
            update_job.result()
        except Exception as e:
            print(f"Error updating asset metadata: {e}")
            
        return asset_id
    else:
        # New hostname — create new asset record
        import hashlib
        asset_id = hashlib.sha256(f"{customer_id}{asset_type}{asset_value}".encode('utf-8')).hexdigest()
        
        new_asset = {
            "asset_id": asset_id,
            "customer_id": customer_id,
            "type": asset_type,
            "value": asset_value,
            "hostname": asset_value,
            "asset_type": asset_type,
            "discovered_at": datetime.utcnow().isoformat() + "Z",
            "last_seen_at": datetime.utcnow().isoformat() + "Z",
            "status": "active",
            "source_tools": [source_tool]
        }
        
        await write_to_table("assets", WriteRequest(rows=[new_asset]))
        return asset_id

@app.post("/write")
async def handle_write_endpoint(payload: Dict[str, Any]):
    # Check if this is a Pub/Sub push message
    if "message" in payload and isinstance(payload["message"], dict) and "data" in payload["message"]:
        try:
            data_b64 = payload["message"]["data"]
            decoded_data = base64.b64decode(data_b64).decode('utf-8')
            inner_payload = json.loads(decoded_data)
        except Exception as e:
            print(f"Error decoding Pub/Sub wrapper: {e}")
            raise HTTPException(status_code=400, detail="Invalid Pub/Sub message data")
    else:
        # Direct workflow payload or direct write payload
        inner_payload = payload

    # If customer_id, scan_id, tool_name and results are present, it's a direct scanner results post
    if "results" in inner_payload and "tool_name" in inner_payload:
        customer_id = inner_payload.get("customer_id")
        scan_id = inner_payload.get("scan_id")
        tool_name = inner_payload.get("tool_name")
        results = inner_payload.get("results") or []
        
        # 1. Write tool log
        log_id = str(uuid.uuid4())
        
        # Extract new metadata fields or compute defaults
        function_name = inner_payload.get("function_name")
        if not function_name:
            function_name = "exposure-service" if tool_name == "censys" else "httpx-service"
            
        tool_version = inner_payload.get("tool_version")
        if not tool_version:
            tool_version = "api-v3" if tool_name == "censys" else "v1.6.0"
            
        duration_ms = inner_payload.get("duration_ms")
        if duration_ms is not None:
            try:
                duration_ms = int(duration_ms)
            except ValueError:
                duration_ms = 0
        else:
            duration_ms = 0
            
        invoked_at = inner_payload.get("invoked_at")
        if not invoked_at:
            invoked_at = datetime.utcnow().isoformat() + "Z"
            
        error = inner_payload.get("error")
        result_count = len(results)
        
        log_row = {
            "log_id": log_id,
            "scan_id": scan_id,
            "customer_id": customer_id,
            "tool_name": tool_name,
            "status": "FAILED" if error else "SUCCESS",
            "raw_output": f"Successfully processed {len(results)} findings" if not error else f"Error: {error}",
            "timestamp": invoked_at,
            "function_name": function_name,
            "invoked_at": invoked_at,
            "duration_ms": duration_ms,
            "result_count": result_count,
            "error": error,
            "tool_version": tool_version
        }
        await write_to_table("scan_tool_log", WriteRequest(rows=[log_row]))
        
        findings_to_write = []
        properties_to_write = []
        
        for finding in results:
            finding_copy = dict(finding)
            
            # Extract asset metadata if present
            asset_type = finding_copy.pop("_asset_type", None)
            asset_value = finding_copy.pop("_asset_value", None)
            
            if asset_type and asset_value:
                # Upsert the asset and get the resolved asset_id
                asset_id = await upsert_asset(customer_id, asset_type, asset_value, tool_name)
                finding_copy["asset_id"] = asset_id
                
                # Write an asset property to link this asset to this scan_id
                properties_to_write.append({
                    "asset_id": asset_id,
                    "customer_id": customer_id,
                    "key": "last_seen_scan_id",
                    "value": scan_id,
                    "updated_at": datetime.utcnow().isoformat() + "Z"
                })
                # If tool is censys, we can write a property to record censys query
                if tool_name == "censys":
                    properties_to_write.append({
                        "asset_id": asset_id,
                        "customer_id": customer_id,
                        "key": "censys_queried",
                        "value": "true",
                        "updated_at": datetime.utcnow().isoformat() + "Z"
                    })
            
            # Ensure finding contains customer_id
            if "customer_id" not in finding_copy:
                finding_copy["customer_id"] = customer_id
                
            findings_to_write.append(finding_copy)
            
        # Write asset properties
        if properties_to_write:
            try:
                await write_to_table("asset_properties", WriteRequest(rows=properties_to_write))
            except Exception as e:
                print(f"Non-blocking error writing asset properties: {e}")
                
        # Write findings
        if findings_to_write:
            return await write_to_table("findings", WriteRequest(rows=findings_to_write))
        return {"status": "success", "written": 0}
        
    table_name = inner_payload.get("table")
    rows = inner_payload.get("rows")
    
    if not table_name or not rows:
        if isinstance(inner_payload, list):
            table_name = "findings"
            rows = inner_payload
        elif "findings" in inner_payload:
            table_name = "findings"
            rows = inner_payload["findings"]
        else:
            raise HTTPException(status_code=400, detail="Payload must specify 'table' and 'rows', or 'results' with 'tool_name', or be a list of findings")

    # In case rows is a single dict, wrap it
    if isinstance(rows, dict):
        rows = [rows]

    return await write_to_table(table_name, WriteRequest(rows=rows))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}


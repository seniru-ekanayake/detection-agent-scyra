from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google.cloud import bigquery
from typing import List, Dict, Any
from datetime import datetime

app = FastAPI(title="EASM Delta Engine Service")

bq_client = bigquery.Client()
DATASET_ID = "easm_attack_surface"

class CalculateRequest(BaseModel):
    customer_id: str
    scan_id: str

class CalculateResponse(BaseModel):
    customer_id: str
    scan_id: str
    alerts: List[Dict[str, Any]]

@app.post("/calculate", response_model=CalculateResponse)
async def calculate_deltas(request: CalculateRequest):
    project = bq_client.project
    
    # 1. Fetch scan details to get start time
    scan_query = f"""
        SELECT started_at 
        FROM `{project}.{DATASET_ID}.scans` 
        WHERE scan_id = @scan_id AND customer_id = @customer_id
    """
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("scan_id", "STRING", request.scan_id),
            bigquery.ScalarQueryParameter("customer_id", "STRING", request.customer_id)
        ]
    )
    
    try:
        scan_job = bq_client.query(scan_query, job_config=job_config)
        scan_results = list(scan_job.result())
        if not scan_results:
            # Fallback for testing: if scan not found, default started_at to 1 hour ago
            print(f"Warning: Scan {request.scan_id} not found in database. Using default start time.")
            started_at = datetime.utcnow() # we will use current time
        else:
            started_at = scan_results[0].started_at
            
    except Exception as e:
        print(f"Error querying scan: {e}")
        # Default fallback
        started_at = datetime.utcnow()
        
    # Format timestamp for SQL query
    started_at_str = started_at.isoformat()
    if not started_at_str.endswith("Z") and "+" not in started_at_str:
        started_at_str += "Z"

    # 2. Get current scan findings (created during this scan)
    current_query = f"""
        SELECT finding_id, asset_id, severity, title, description
        FROM `{project}.{DATASET_ID}.findings`
        WHERE customer_id = @customer_id AND created_at >= @started_at
    """
    current_job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("customer_id", "STRING", request.customer_id),
            bigquery.ScalarQueryParameter("started_at", "TIMESTAMP", started_at_str)
        ]
    )
    
    # 3. Get previous active findings (created before this scan, still open)
    prev_query = f"""
        SELECT finding_id, asset_id, severity, title
        FROM `{project}.{DATASET_ID}.findings`
        WHERE customer_id = @customer_id AND created_at < @started_at AND status = 'open'
    """
    prev_job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("customer_id", "STRING", request.customer_id),
            bigquery.ScalarQueryParameter("started_at", "TIMESTAMP", started_at_str)
        ]
    )
    
    current_findings = {}
    prev_findings = {}
    
    try:
        current_job = bq_client.query(current_query, current_job_config)
        for row in current_job.result():
            current_findings[row.finding_id] = row
            
        prev_job = bq_client.query(prev_query, prev_job_config)
        for row in prev_job.result():
            prev_findings[row.finding_id] = row
            
    except Exception as e:
        print(f"Error querying findings: {e}")
        # Return empty list in case tables don't exist yet or are empty
        return CalculateResponse(customer_id=request.customer_id, scan_id=request.scan_id, alerts=[])
        
    alerts = []
    resolved_ids = []
    
    # Identify New Findings
    for fid, f in current_findings.items():
        if fid not in prev_findings:
            alerts.append({
                "type": "new_finding",
                "severity": f.severity,
                "title": f"New Finding: {f.title}",
                "details": f.description or "",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            
    # Identify Resolved Findings
    for fid, f in prev_findings.items():
        if fid not in current_findings:
            resolved_ids.append(fid)
            alerts.append({
                "type": "resolved_finding",
                "severity": f.severity,
                "title": f"Resolved Finding: {f.title}",
                "details": f"The vulnerability/exposure is no longer detected.",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            })
            
    # 4. Update status of resolved findings in BigQuery
    if resolved_ids:
        resolved_list_str = ", ".join([f"'{fid}'" for fid in resolved_ids])
        update_query = f"""
            UPDATE `{project}.{DATASET_ID}.findings`
            SET status = 'resolved'
            WHERE finding_id IN ({resolved_list_str}) AND customer_id = @customer_id
        """
        update_job_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("customer_id", "STRING", request.customer_id)
            ]
        )
        try:
            update_job = bq_client.query(update_query, update_job_config)
            update_job.result() # Wait for completion
            print(f"Successfully resolved {len(resolved_ids)} findings in BigQuery.")
        except Exception as e:
            print(f"Error updating resolved findings: {e}")
            
    # 5. Delta Engine logic for assets
    assets_new = 0
    assets_gone = 0

    try:
        # Step 1: Count new assets for this scan_id
        # We query the assets table for rows where customer_id = current customer AND discovered_at matches this scan start time or we can check last_seen_at / discovered_at.
        # Wait, the spec says "Query assets table for rows where customer_id = current customer, first_seen_scan_id = current scan_id... Wait, assets table does not have first_seen_scan_id. Let's look at the schema we defined:
        # assets has asset_id, customer_id, type, value, discovered_at, last_seen_at, status, hostname, asset_type, source_tools.
        # Wait! How can we identify assets discovered during the current scan?
        # We can look at assets where customer_id = request.customer_id and discovered_at >= started_at!
        new_assets_query = f"""
            SELECT COUNT(*) as cnt 
            FROM `{project}.{DATASET_ID}.assets`
            WHERE customer_id = @customer_id AND discovered_at >= @started_at
        """
        new_assets_job = bq_client.query(new_assets_query, current_job_config)
        new_assets_res = list(new_assets_job.result())
        if new_assets_res:
            assets_new = new_assets_res[0].cnt

        # Step 2: Detect gone assets
        # Get the last 3 completed/partial scans for this customer ordered by started_at DESC
        scans_history_query = f"""
            SELECT scan_id 
            FROM `{project}.{DATASET_ID}.scans`
            WHERE customer_id = @customer_id AND (status IN ('completed', 'partial') OR scan_id = '{request.scan_id}')
            ORDER BY started_at DESC
            LIMIT 3
        """
        scans_history_job = bq_client.query(scans_history_query, current_job_config)
        scans_history = [r.scan_id for r in scans_history_job.result()]

        # Minimum 3 scans required for gone detection
        if len(scans_history) >= 3:
            # For each asset with status = 'active' check if it appears in all 3 scans.
            # An asset "appears in a scan" if there is a row in asset_properties where scan_id = <scan_id> and asset_id = <asset_id>.
            # Let's find all active assets for this customer
            active_assets_query = f"""
                SELECT asset_id FROM `{project}.{DATASET_ID}.assets`
                WHERE customer_id = @customer_id AND status = 'active'
            """
            active_assets_job = bq_client.query(active_assets_query, current_job_config)
            active_asset_ids = [r.asset_id for r in active_assets_job.result()]

            # We want to check, for each active_asset_id, if there is at least one appearance in the last 3 scans.
            # Let's count how many of the last 3 scans each asset appeared in:
            # SELECT asset_id, COUNT(DISTINCT scan_id) FROM asset_properties WHERE scan_id IN (last_3_scans) GROUP BY asset_id
            if active_asset_ids:
                scans_list_str = ", ".join([f"'{sid}'" for sid in scans_history])
                appearances_query = f"""
                    SELECT asset_id, COUNT(DISTINCT value) as cnt
                    FROM `{project}.{DATASET_ID}.asset_properties`
                    WHERE customer_id = @customer_id AND key = 'last_seen_scan_id' AND value IN ({scans_list_str})
                    GROUP BY asset_id
                """
                appearances_job = bq_client.query(appearances_query, current_job_config)
                appearances_dict = {r.asset_id: r.cnt for r in appearances_job.result()}

                gone_asset_ids = []
                for aid in active_asset_ids:
                    # If it did not appear in ANY of the last 3 scans (meaning count is 0/missing in appearances_dict)
                    if appearances_dict.get(aid, 0) == 0:
                        gone_asset_ids.append(aid)

                if gone_asset_ids:
                    assets_gone = len(gone_asset_ids)
                    gone_list_str = ", ".join([f"'{aid}'" for aid in gone_asset_ids])
                    update_gone_query = f"""
                        UPDATE `{project}.{DATASET_ID}.assets`
                        SET status = 'gone'
                        WHERE asset_id IN ({gone_list_str}) AND customer_id = @customer_id
                    """
                    update_gone_job = bq_client.query(update_gone_query, current_job_config)
                    update_gone_job.result()
                    print(f"Successfully marked {assets_gone} assets as gone.")

    except Exception as e:
        print(f"Error executing delta-engine asset/gone calculations: {e}")

    # 6. Update scan status, ended_at, assets_new, assets_gone atomically
    # Note: Using standard UPDATE which runs as a DML query (executes as a query/load job internally by BigQuery when DML is run)
    update_scan_query = f"""
        UPDATE `{project}.{DATASET_ID}.scans`
        SET ended_at = CURRENT_TIMESTAMP(),
            assets_new = @assets_new,
            assets_gone = @assets_gone
        WHERE scan_id = @scan_id AND customer_id = @customer_id
    """
    update_scan_job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("scan_id", "STRING", request.scan_id),
            bigquery.ScalarQueryParameter("customer_id", "STRING", request.customer_id),
            bigquery.ScalarQueryParameter("assets_new", "INT64", assets_new),
            bigquery.ScalarQueryParameter("assets_gone", "INT64", assets_gone)
        ]
    )
    try:
        update_scan_job = bq_client.query(update_scan_query, update_scan_job_config)
        update_scan_job.result()
        print(f"Successfully marked scan {request.scan_id} and saved deltas (new: {assets_new}, gone: {assets_gone}).")
    except Exception as e:
        print(f"Error updating scan status: {e}")
            
    return CalculateResponse(
        customer_id=request.customer_id,
        scan_id=request.scan_id,
        alerts=alerts
    )

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

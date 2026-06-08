from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
import os
import base64
import json
import requests
from datetime import datetime
from google.cloud import pubsub_v1
from google.cloud import bigquery

app = FastAPI(title="EASM Analyzer Trigger Service")

project_id = "scyra-agents-495519"
publisher = pubsub_v1.PublisherClient()

def get_critical_findings(scan_id: str) -> list:
    bq_client = bigquery.Client(project=project_id)
    query = """
        SELECT f.finding_id, f.title, a.hostname
        FROM `easm_attack_surface.findings` f
        JOIN `easm_attack_surface.assets` a ON f.asset_id = a.asset_id
        WHERE f.scan_id = @scan_id AND LOWER(f.severity) = 'critical'
    """
    job_config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("scan_id", "STRING", scan_id)]
    )
    try:
        results = list(bq_client.query(query, job_config=job_config).result())
        return [
            {
                "finding_id": row.finding_id,
                "title": row.title,
                "hostname": row.hostname or "unknown",
                "severity": "critical"
            }
            for row in results
        ]
    except Exception as e:
        print(f"Error querying critical findings: {e}")
        return []

@app.post("/trigger")
async def handle_trigger(request: Request):
    payload = await request.json()
    print("Received push request:", json.dumps(payload))
    
    # 1. Parse Pub/Sub wrapper
    if "message" not in payload or "data" not in payload["message"]:
        print("Missing Pub/Sub message data, ACK and return.")
        return {"status": "ignored", "reason": "invalid_pubsub_format"}
        
    try:
        data_b64 = payload["message"]["data"]
        decoded_data = base64.b64decode(data_b64).decode('utf-8')
        message = json.loads(decoded_data)
        print("Decoded message:", json.dumps(message))
    except Exception as e:
        print(f"Error decoding Pub/Sub base64: {e}. ACK and return.")
        return {"status": "ignored", "reason": "decoding_error"}
        
    # 2. Validate mandatory fields
    scan_id = message.get("scan_id")
    customer_id = message.get("customer_id")
    if not scan_id or not customer_id:
        print("Missing scan_id or customer_id. ACK and return.")
        return {"status": "ignored", "reason": "missing_required_fields"}
        
    # 3. Check if any new or changed assets
    assets_new = message.get("assets_new", 0) or 0
    assets_changed = message.get("assets_changed", 0) or 0
    
    # If explicitly 0, we have nothing to analyze
    if assets_new == 0 and assets_changed == 0:
        print(f"No new ({assets_new}) or changed ({assets_changed}) assets. ACK and return.")
        return {"status": "ignored", "reason": "no_assets_to_analyze"}
        
    # 4. Invoke analyzer-agent-service
    agent_url = os.getenv("ANALYZER_AGENT_URL")
    if not agent_url:
        print("Error: ANALYZER_AGENT_URL env var not set.")
        raise HTTPException(status_code=500, detail="ANALYZER_AGENT_URL not configured")
        
    url = f"{agent_url.rstrip('/')}/analyze"
    print(f"Invoking analyzer agent service at: {url}...")
    
    try:
        # Use OIDC token if run in GCP or simple requests (IAM allows trigger calling agent)
        # We can fetch default OIDC token for local/GCP invocation
        # Since we run inside Cloud Run with the same service account, Cloud Run services can call each other
        # using OIDC tokens fetched from Metadata service or library.
        # Standard OIDC token fetch helper:
        headers = {}
        try:
            # Try fetching token from metadata server
            token_url = f"http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience={agent_url}"
            resp_token = requests.get(token_url, headers={"Metadata-Flavor": "Google"}, timeout=2)
            if resp_token.status_code == 200:
                headers["Authorization"] = f"Bearer {resp_token.text.strip()}"
                print("Fetched service OIDC token for invocation.")
        except Exception:
            print("Running in non-GCP environment, calling agent service without OIDC header.")

        resp = requests.post(url, json={"scan_id": scan_id, "customer_id": customer_id}, headers=headers, timeout=600)
        
        if resp.status_code != 200:
            print(f"Agent service returned status {resp.status_code}: {resp.text}")
            raise HTTPException(status_code=502, detail=f"Agent service returned error code: {resp.status_code}")
            
        summary = resp.json()
        print("Agent service summary response:", json.dumps(summary))
        
        # 5. Publish to easm-analysis-complete
        analysis_complete_payload = {
            "scan_id": scan_id,
            "customer_id": customer_id,
            "analysis_completed_at": datetime.utcnow().isoformat() + "Z",
            "findings_written": summary.get("findings_written", 0),
            "critical_count": summary.get("critical_count", 0),
            "high_count": summary.get("high_count", 0),
            "medium_count": summary.get("medium_count", 0),
            "low_count": summary.get("low_count", 0),
            "informational_count": summary.get("informational_count", 0),
            "advisor_consultations": summary.get("advisor_consultations", 0)
        }
        
        complete_topic_path = publisher.topic_path(project_id, "easm-analysis-complete")
        publisher.publish(complete_topic_path, json.dumps(analysis_complete_payload).encode("utf-8"))
        print("Published complete notification to easm-analysis-complete.")
        
        # 6. If critical count > 0, publish critical findings to easm-analysis-alerts
        critical_count = summary.get("critical_count", 0)
        if critical_count > 0:
            critical_findings = get_critical_findings(scan_id)
            alert_payload = {
                "scan_id": scan_id,
                "customer_id": customer_id,
                "critical_findings": critical_findings
            }
            alert_topic_path = publisher.topic_path(project_id, "easm-analysis-alerts")
            publisher.publish(alert_topic_path, json.dumps(alert_payload).encode("utf-8"))
            print("Published alert notification to easm-analysis-alerts.")
            
        return {"status": "success", "summary": summary}
        
    except Exception as e:
        print(f"Error running analyzer trigger: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health():
    return {"status": "healthy"}

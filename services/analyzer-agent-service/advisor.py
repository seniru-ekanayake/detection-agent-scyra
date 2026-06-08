import os
import json
import uuid
from datetime import datetime
from typing import Optional
import vertexai
from vertexai.generative_models import GenerativeModel
from google.cloud import bigquery

ADVISOR_MODEL = "gemini-2.5-pro"
project_id = "scyra-agents-495519"

# Initialize Vertex AI
try:
    vertexai.init(project=project_id, location="us-central1")
except Exception as e:
    print(f"Error initializing Vertex AI in advisor.py: {e}")

def write_advisor_log(scan_id: str, customer_id: str, error: Optional[str] = None):
    row = {
        "log_id": str(uuid.uuid4()),
        "scan_id": scan_id or "unknown-scan",
        "customer_id": customer_id or "unknown-customer",
        "tool_name": "gemini-2.5-pro",
        "status": "failed" if error else "success",
        "raw_output": "Advisor Consultation Executed" if not error else f"Error: {error}",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "function_name": "advisor-consultation",
        "invoked_at": datetime.utcnow().isoformat() + "Z",
        "duration_ms": 0,
        "result_count": 1,
        "error": error,
        "tool_version": "gemini-2.5-pro"
    }
    
    try:
        bq_client = bigquery.Client()
        table_ref = f"{bq_client.project}.easm_attack_surface.scan_tool_log"
        errors = bq_client.insert_rows_json(table_ref, [row])
        if errors:
            raise Exception(f"Streaming insert errors: {errors}")
        print(f"Logged advisor consultation to scan_tool_log.")
    except Exception as e:
        print(f"Non-blocking error logging advisor consultation to scan_tool_log: {e}")

def consult_advisor(
    asset_context: dict,
    evidence: dict,
    ambiguity_reason: str,
    consultation_count: int,
    scan_id: str = "unknown-scan",
    customer_id: str = "unknown-customer"
) -> dict:

    if consultation_count >= 3:
        # Hard cap: executor decides without advisor
        return {
            "recommended_severity": "medium",
            "justification": "Advisor cap reached, defaulting to medium"
        }

    error_msg = None
    try:
        model = GenerativeModel(ADVISOR_MODEL)

        prompt = f"""You are a senior security analyst advisor.
An executor agent is analyzing this asset and needs your guidance.

Asset context:
{json.dumps(asset_context, indent=2)}

Evidence gathered:
{json.dumps(evidence, indent=2)}

Reason for consultation:
{ambiguity_reason}

Respond with ONLY a JSON object, no preamble:
{{
  "recommended_severity": "critical|high|medium|low|informational",
  "justification": "<one sentence explaining the severity>"
}}"""

        response = model.generate_content(prompt)
        raw = response.text.strip()

        # Strip markdown fences if present
        if raw.startswith("```"):
            lines = raw.split("```")
            raw = lines[1]
            if raw.startswith("json"):
                raw = raw[4:]
        raw = raw.strip()

        result = json.loads(raw)

        # Validate response structure
        valid_severities = {"critical", "high", "medium", "low", "informational"}
        if result.get("recommended_severity") not in valid_severities:
            raise ValueError(f"Invalid severity from advisor: {result}")
            
        write_advisor_log(scan_id, customer_id, error=None)
        return result

    except Exception as e:
        print(f"Error during advisor consultation: {e}")
        error_msg = str(e)
        write_advisor_log(scan_id, customer_id, error=error_msg)
        # Fallback
        return {
            "recommended_severity": "medium",
            "justification": f"Advisor consultation failed due to error: {str(e)[:100]}"
        }

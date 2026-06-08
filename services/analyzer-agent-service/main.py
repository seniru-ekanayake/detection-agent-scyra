from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import os
import json
from datetime import datetime
from google.cloud import bigquery
import tools
import guards
from agent import analyzer_agent

app = FastAPI(title="EASM Analyzer Agent Service")

class AnalyzeRequest(BaseModel):
    scan_id: str
    customer_id: str

class AnalyzeResponse(BaseModel):
    status: str
    scan_id: str
    customer_id: str
    findings_written: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int
    skipped_false_positive: int
    skipped_confidence: int
    advisor_consultations: int

def extract_technologies(properties: List[Dict[str, Any]]) -> List[tuple]:
    techs = []
    # Supporting multiple key-value conventions for robustness:
    # 1. key="technology", value="Apache:2.4.29" or "Apache 2.4.29"
    # 2. key="technology:Apache", value="2.4.29"
    # 3. key="technology", value="Apache" paired with key="version", value="2.4.29"
    tech_val = None
    ver_val = None
    for p in properties:
        key = p.get("property_key", "")
        val = p.get("property_value", "")
        if key == "technology":
            if ":" in val:
                parts = val.split(":", 1)
                techs.append((parts[0].strip(), parts[1].strip()))
            elif " " in val:
                parts = val.split(" ", 1)
                techs.append((parts[0].strip(), parts[1].strip()))
            else:
                tech_val = val
        elif key == "version":
            ver_val = val
        elif key.startswith("technology:"):
            tech_name = key.split(":", 1)[1]
            techs.append((tech_name.strip(), val.strip()))
            
    if tech_val and ver_val:
        techs.append((tech_val.strip(), ver_val.strip()))
        
    return list(set(techs))

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_scan(payload: AnalyzeRequest):
    # 1. Reset tool session state
    tools.CURRENT_SCAN_ID = payload.scan_id
    tools.CURRENT_CUSTOMER_ID = payload.customer_id
    tools.VALID_CVE_IDS = set()
    tools.ADVISOR_CONSULTATIONS = {}
    tools.CONSULTATION_COUNTS = {}
    
    # 2. Query new assets in BigQuery
    new_assets = tools.query_new_assets(payload.scan_id, payload.customer_id)
    print(f"Running EASM Analyzer Agent for scan_id: {payload.scan_id}, found {len(new_assets)} assets to check.")
    
    skipped_false_positive = 0
    skipped_confidence = 0
    
    for asset in new_assets:
        # Confidence Guard
        if guards.guard_confidence(asset, payload.scan_id, payload.customer_id):
            skipped_confidence += 1
            continue
            
        asset_id = asset.get("asset_id")
        hostname = asset.get("hostname")
        
        # Query asset properties, org context, and prior findings
        properties = tools.query_asset_properties(asset_id, payload.customer_id)
        org_context = tools.query_org_context(hostname, payload.customer_id)
        prior_findings = tools.query_prior_findings(asset_id, payload.customer_id)
        
        # Pre-lookup CVEs for technology versions
        tech_list = extract_technologies(properties)
        cves_gathered = []
        for tech, ver in tech_list:
            cve_results = tools.lookup_cve(tech, ver)
            if cve_results:
                cves_gathered.extend(cve_results)
                
        current_cve_ids = [cve.get("cve_id") for cve in cves_gathered if cve.get("cve_id")]
        current_source_tools = asset.get("source_tools", [])
        if isinstance(current_source_tools, str):
            current_source_tools = [current_source_tools]
        else:
            current_source_tools = list(current_source_tools)
            
        # False Positive Guard
        if guards.guard_false_positive(asset_id, payload.customer_id, payload.scan_id, 
                                       prior_findings, current_cve_ids, current_source_tools):
            skipped_false_positive += 1
            continue
            
        # Invoke ADK Agent Loop using the Runner
        from google.adk.runners import Runner
        from google.adk.sessions import InMemorySessionService
        from google.genai import types
        
        prompt = f"""Please analyze the following asset:
Asset: {json.dumps(asset)}
Properties: {json.dumps(properties)}
Org Context: {json.dumps(org_context)}
CVEs Gathered: {json.dumps(cves_gathered)}
Prior Findings: {json.dumps(prior_findings)}

Follow the steps in your instruction. Determine the severity, reason over it, and call write_finding. If you receive an Advisor recommendation, follow it and call write_finding again with the finalized severity."""

        session_service = InMemorySessionService()
        await session_service.create_session(
            app_name="easm-analyzer",
            user_id=payload.customer_id,
            session_id=asset_id
        )
        runner = Runner(
            agent=analyzer_agent,
            app_name="easm-analyzer",
            session_service=session_service
        )
        
        # Synchronously consume the async generator to completion
        try:
            async def run_runner():
                content = types.Content(role='user', parts=[types.Part(text=prompt)])
                async for event in runner.run_async(
                    user_id=payload.customer_id,
                    session_id=asset_id,
                    new_message=content
                ):
                    pass
            await run_runner()
        except Exception as e:
            print(f"Error during ADK agent execution on asset {asset_id}: {e}")
            
    # Gather final analysis stats from findings table for this scan_id
    findings_written = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    informational_count = 0
    
    bq_client = bigquery.Client()
    query = """
        SELECT severity, COUNT(*) as cnt
        FROM `easm_attack_surface.findings`
        WHERE scan_id = @scan_id
        AND customer_id = @customer_id
        GROUP BY severity
    """
    job_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("scan_id", "STRING", payload.scan_id),
            bigquery.ScalarQueryParameter("customer_id", "STRING", payload.customer_id)
        ]
    )
    
    try:
        rows = list(bq_client.query(query, job_config=job_config).result())
        findings_written = sum(row.cnt for row in rows)
        for row in rows:
            sev = row.severity.lower()
            if sev == "critical":
                critical_count = row.cnt
            elif sev == "high":
                high_count = row.cnt
            elif sev == "medium":
                medium_count = row.cnt
            elif sev == "low":
                low_count = row.cnt
            elif sev == "informational":
                informational_count = row.cnt
    except Exception as e:
        print(f"Error querying scan findings count: {e}")
        
    advisor_consultations = len(tools.ADVISOR_CONSULTATIONS)
    
    return AnalyzeResponse(
        status="success",
        scan_id=payload.scan_id,
        customer_id=payload.customer_id,
        findings_written=findings_written,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        informational_count=informational_count,
        skipped_false_positive=skipped_false_positive,
        skipped_confidence=skipped_confidence,
        advisor_consultations=advisor_consultations
    )

@app.get("/health")
async def health():
    return {"status": "healthy"}

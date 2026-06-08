import json
import time
import uuid
import os
import requests
import base64
from datetime import datetime
from google.cloud import bigquery
from google.cloud import pubsub_v1

project_id = "scyra-agents-495519"
dataset_id = "easm_attack_surface"
bq_client = bigquery.Client(project=project_id)

# NVD Lookup service local/GCP URL configuration
# We'll resolve the URL from Terraform outputs or Cloud Run
nvd_lookup_url = "https://easm-nvd-lookup-service-114999731000.us-central1.run.app"
agent_url = "https://easm-analyzer-agent-service-114999731000.us-central1.run.app"

results = {}

def get_auth_headers():
    # Attempt to fetch OIDC token from gcloud CLI first for local testing
    headers = {}
    try:
        import subprocess
        res = subprocess.run(["gcloud.cmd", "auth", "print-identity-token"], capture_output=True, text=True)
        if res.returncode == 0:
            token = res.stdout.strip()
            headers["Authorization"] = f"Bearer {token}"
            print("Successfully fetched local gcloud OIDC token.")
            return headers
    except Exception as e:
        print(f"Could not fetch local gcloud token: {e}")
        
    try:
        token_url = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=" + agent_url
        resp = requests.get(token_url, headers={"Metadata-Flavor": "Google"}, timeout=2)
        if resp.status_code == 200:
            headers["Authorization"] = f"Bearer {resp.text.strip()}"
            print("Using metadata-based OIDC auth token.")
    except Exception:
        # Local development fallback
        print("Non-GCP metadata server, requesting without OIDC authorization headers.")
    return headers

def clean_customer_data(customer_id):
    print(f"Cleaning data for customer: {customer_id}...")
    tables = ["assets", "asset_properties", "findings", "scan_tool_log", "scans"]
    for t in tables:
        try:
            q = f"DELETE FROM `{project_id}.{dataset_id}.{t}` WHERE customer_id = @customer_id"
            job_config = bigquery.QueryJobConfig(
                query_parameters=[bigquery.ScalarQueryParameter("customer_id", "STRING", customer_id)]
            )
            bq_client.query(q, job_config=job_config).result()
        except Exception as e:
            print(f"Error cleaning {t}: {e}")

# =====================================================================
# TEST 1 — FINDING COMPLETENESS
# =====================================================================
print("\n--- Starting Test 1 — Finding Completeness ---")
t1_customer_id = "validation-test-1"
results["test_1_finding_completeness"] = {"status": "fail", "findings_written": 0}

try:
    clean_customer_data(t1_customer_id)
    
    # 1. Seed scan
    scan_id = str(uuid.uuid4())
    started_at = datetime.utcnow()
    scan_row = {
        "scan_id": scan_id,
        "customer_id": t1_customer_id,
        "started_at": started_at.isoformat() + "Z",
        "status": "completed"
    }
    bq_client.load_table_from_json([scan_row], f"{project_id}.{dataset_id}.scans").result()

    # 2. Seed active asset with confidence 0.5
    asset_id = str(uuid.uuid4())
    asset_row = {
        "asset_id": asset_id,
        "customer_id": t1_customer_id,
        "type": "subdomain",
        "value": "completeness.testfire.net",
        "discovered_at": started_at.isoformat() + "Z",
        "last_seen_at": started_at.isoformat() + "Z",
        "status": "active",
        "confidence_score": 0.5,
        "source_tools": ["subfinder"]
    }
    bq_client.load_table_from_json([asset_row], f"{project_id}.{dataset_id}.assets").result()

    # Seed asset properties
    prop_rows = [
        {"asset_id": asset_id, "customer_id": t1_customer_id, "key": "ip_address", "value": "1.2.3.4", "updated_at": started_at.isoformat() + "Z"},
        {"asset_id": asset_id, "customer_id": t1_customer_id, "key": "port", "value": "80", "updated_at": started_at.isoformat() + "Z"}
    ]
    bq_client.load_table_from_json(prop_rows, f"{project_id}.{dataset_id}.asset_properties").result()

    # Invoke agent directly
    resp = requests.post(f"{agent_url}/analyze", json={"scan_id": scan_id, "customer_id": t1_customer_id}, headers=get_auth_headers(), timeout=600)
    print("Agent API response:", resp.status_code, resp.text)
    
    # Verify findings written
    q = f"SELECT count(*) as cnt FROM `{project_id}.{dataset_id}.findings` WHERE scan_id = '{scan_id}'"
    count = list(bq_client.query(q).result())[0].cnt
    print(f"Findings written: {count}")
    
    # Also verify finding schema completeness
    q_fields = f"SELECT finding_id, scan_id, customer_id, cvss_score, confidence_score FROM `{project_id}.{dataset_id}.findings` WHERE scan_id = '{scan_id}'"
    fields = list(bq_client.query(q_fields).result())
    if count > 0 and fields[0].scan_id == scan_id and fields[0].customer_id == t1_customer_id:
        results["test_1_finding_completeness"] = {"status": "pass", "findings_written": count}
    else:
        results["test_1_finding_completeness"] = {"status": "fail", "findings_written": count}

except Exception as e:
    print(f"FAIL: Exception in Test 1: {e}")
finally:
    clean_customer_data(t1_customer_id)


# =====================================================================
# TEST 2 — RUBRIC CONSISTENCY
# =====================================================================
time.sleep(20)
print("\n--- Starting Test 2 — Rubric Consistency ---")
t2_customer_id = "validation-test-2"
results["test_2_rubric_consistency"] = {"status": "fail"}

try:
    clean_customer_data(t2_customer_id)
    scan_id = str(uuid.uuid4())
    started_at = datetime.utcnow()
    
    # Load scan
    bq_client.load_table_from_json([{
        "scan_id": scan_id, "customer_id": t2_customer_id, "started_at": started_at.isoformat() + "Z", "status": "completed"
    }], f"{project_id}.{dataset_id}.scans").result()

    # Asset A: Exposed Database Port 3306 -> Critical
    asset_db_id = str(uuid.uuid4())
    asset_db = {
        "asset_id": asset_db_id, "customer_id": t2_customer_id, "type": "subdomain", "value": "db.testfire.net",
        "discovered_at": started_at.isoformat() + "Z", "last_seen_at": started_at.isoformat() + "Z", "status": "active",
        "confidence_score": 0.9, "source_tools": ["subfinder"]
    }
    bq_client.load_table_from_json([asset_db], f"{project_id}.{dataset_id}.assets").result()
    bq_client.load_table_from_json([
        {"asset_id": asset_db_id, "customer_id": t2_customer_id, "key": "port", "value": "3306", "updated_at": started_at.isoformat() + "Z"},
        {"asset_id": asset_db_id, "customer_id": t2_customer_id, "key": "service", "value": "mysql", "updated_at": started_at.isoformat() + "Z"}
    ], f"{project_id}.{dataset_id}.asset_properties").result()

    # Asset B: Outdated Apache (Apache 2.4.29) -> Medium (outdated software, no critical CVE)
    asset_web_id = str(uuid.uuid4())
    asset_web = {
        "asset_id": asset_web_id, "customer_id": t2_customer_id, "type": "subdomain", "value": "web.testfire.net",
        "discovered_at": started_at.isoformat() + "Z", "last_seen_at": started_at.isoformat() + "Z", "status": "active",
        "confidence_score": 0.8, "source_tools": ["subfinder"]
    }
    bq_client.load_table_from_json([asset_web], f"{project_id}.{dataset_id}.assets").result()
    bq_client.load_table_from_json([
        {"asset_id": asset_web_id, "customer_id": t2_customer_id, "key": "port", "value": "80", "updated_at": started_at.isoformat() + "Z"},
        {"asset_id": asset_web_id, "customer_id": t2_customer_id, "key": "technology:Apache", "value": "2.4.29", "updated_at": started_at.isoformat() + "Z"}
    ], f"{project_id}.{dataset_id}.asset_properties").result()

    # Run analyzer
    requests.post(f"{agent_url}/analyze", json={"scan_id": scan_id, "customer_id": t2_customer_id}, headers=get_auth_headers(), timeout=600)

    # Check database finding -> should be critical
    q_db = f"SELECT severity FROM `{project_id}.{dataset_id}.findings` WHERE scan_id = '{scan_id}' AND asset_id = '{asset_db_id}'"
    sev_db = list(bq_client.query(q_db).result())[0].severity.lower()
    
    # Check apache finding -> should be medium or high depending on CVE/lookups
    q_web = f"SELECT severity FROM `{project_id}.{dataset_id}.findings` WHERE scan_id = '{scan_id}' AND asset_id = '{asset_web_id}'"
    sev_web = list(bq_client.query(q_web).result())[0].severity.lower()

    print(f"Exposed DB severity: {sev_db}, Apache web severity: {sev_web}")
    if sev_db == "critical" and sev_web in ["medium", "high", "low"]:
        results["test_2_rubric_consistency"] = {"status": "pass"}
    else:
        results["test_2_rubric_consistency"] = {"status": "fail"}

except Exception as e:
    print(f"FAIL: Exception in Test 2: {e}")
finally:
    clean_customer_data(t2_customer_id)


# =====================================================================
# TEST 3 — ORG CONTEXT ESCALATION
# =====================================================================
time.sleep(20)
print("\n--- Starting Test 3 — Org Context Escalation ---")
t3_customer_id = "validation-test-3"
results["test_3_org_context_escalation"] = {"status": "fail"}

try:
    clean_customer_data(t3_customer_id)
    scan_id = str(uuid.uuid4())
    started_at = datetime.utcnow()

    # org_context is already seeded with:
    # hostname: demo.testfire.net, data_classification: pii, business_criticality: high (escalates by 1)
    # hostname: www.testfire.net, data_classification: public, business_criticality: medium (no change)

    # Load scan
    bq_client.load_table_from_json([{
        "scan_id": scan_id, "customer_id": t3_customer_id, "started_at": started_at.isoformat() + "Z", "status": "completed"
    }], f"{project_id}.{dataset_id}.scans").result()

    # Asset A: Outdated Apache on demo.testfire.net (PII) -> Severity should be escalated to High (from Medium)
    asset_pii_id = str(uuid.uuid4())
    asset_pii = {
        "asset_id": asset_pii_id, "customer_id": t3_customer_id, "type": "subdomain", "value": "demo.testfire.net",
        "discovered_at": started_at.isoformat() + "Z", "last_seen_at": started_at.isoformat() + "Z", "status": "active",
        "confidence_score": 0.8, "source_tools": ["subfinder"]
    }
    bq_client.load_table_from_json([asset_pii], f"{project_id}.{dataset_id}.assets").result()
    bq_client.load_table_from_json([
        {"asset_id": asset_pii_id, "customer_id": t3_customer_id, "key": "port", "value": "80", "updated_at": started_at.isoformat() + "Z"},
        {"asset_id": asset_pii_id, "customer_id": t3_customer_id, "key": "technology:Apache", "value": "2.4.29", "updated_at": started_at.isoformat() + "Z"}
    ], f"{project_id}.{dataset_id}.asset_properties").result()

    # Run analyzer
    requests.post(f"{agent_url}/analyze", json={"scan_id": scan_id, "customer_id": t3_customer_id}, headers=get_auth_headers(), timeout=600)

    # Check finding severity -> Should be High
    q_pii = f"SELECT severity FROM `{project_id}.{dataset_id}.findings` WHERE scan_id = '{scan_id}' AND asset_id = '{asset_pii_id}'"
    sev_pii = list(bq_client.query(q_pii).result())[0].severity.lower()

    print(f"Escalated PII severity: {sev_pii}")
    # The base finding for outdated software with no critical CVE is medium, so PII escalates it to high.
    if sev_pii in ["high", "critical"]:
        results["test_3_org_context_escalation"] = {"status": "pass"}
    else:
        results["test_3_org_context_escalation"] = {"status": "fail"}

except Exception as e:
    print(f"FAIL: Exception in Test 3: {e}")
finally:
    clean_customer_data(t3_customer_id)


# =====================================================================
# TEST 4 — FALSE POSITIVE SUPPRESSION
# =====================================================================
time.sleep(20)
print("\n--- Starting Test 4 — False Positive Suppression ---")
t4_customer_id = "validation-test-4"
results["test_4_false_positive_suppression"] = {"status": "fail"}

try:
    clean_customer_data(t4_customer_id)
    scan_id_1 = str(uuid.uuid4())
    scan_id_2 = str(uuid.uuid4())
    started_at = datetime.utcnow()

    # Seed scan 1 & scan 2
    bq_client.load_table_from_json([
        {"scan_id": scan_id_1, "customer_id": t4_customer_id, "started_at": started_at.isoformat() + "Z", "status": "completed"},
        {"scan_id": scan_id_2, "customer_id": t4_customer_id, "started_at": datetime.utcnow().isoformat() + "Z", "status": "completed"}
    ], f"{project_id}.{dataset_id}.scans").result()

    # Seed asset
    asset_id = str(uuid.uuid4())
    asset_row = {
        "asset_id": asset_id, "customer_id": t4_customer_id, "type": "subdomain", "value": "fp-test.testfire.net",
        "discovered_at": started_at.isoformat() + "Z", "last_seen_at": started_at.isoformat() + "Z", "status": "active",
        "confidence_score": 0.8, "source_tools": ["subfinder"]
    }
    bq_client.load_table_from_json([asset_row], f"{project_id}.{dataset_id}.assets").result()
    bq_client.load_table_from_json([
        {"asset_id": asset_id, "customer_id": t4_customer_id, "key": "port", "value": "80", "updated_at": started_at.isoformat() + "Z"},
        {"asset_id": asset_id, "customer_id": t4_customer_id, "key": "technology:Apache", "value": "2.4.29", "updated_at": started_at.isoformat() + "Z"}
    ], f"{project_id}.{dataset_id}.asset_properties").result()

    # Run scan 1 analyze
    requests.post(f"{agent_url}/analyze", json={"scan_id": scan_id_1, "customer_id": t4_customer_id}, headers=get_auth_headers(), timeout=600)

    # Fetch written finding
    q_f = f"SELECT finding_id FROM `{project_id}.{dataset_id}.findings` WHERE scan_id = '{scan_id_1}'"
    finding_id = list(bq_client.query(q_f).result())[0].finding_id

    # Update finding status to false_positive in BQ
    bq_client.query(f"UPDATE `{project_id}.{dataset_id}.findings` SET status = 'false_positive' WHERE finding_id = '{finding_id}'").result()
    print(f"Marked finding {finding_id} as false_positive.")

    # Re-discover/update discovery date of the same asset for scan 2 to match Scan 2's started_at
    scan2_start_row = list(bq_client.query(f"SELECT started_at FROM `{project_id}.{dataset_id}.scans` WHERE scan_id = '{scan_id_2}'").result())[0]
    scan2_start_str = scan2_start_row.started_at.isoformat()
    bq_client.query(f"UPDATE `{project_id}.{dataset_id}.assets` SET discovered_at = '{scan2_start_str}' WHERE asset_id = '{asset_id}'").result()

    # Run scan 2 analyze
    requests.post(f"{agent_url}/analyze", json={"scan_id": scan_id_2, "customer_id": t4_customer_id}, headers=get_auth_headers(), timeout=600)

    # Check finding written for scan 2 -> Should be 0
    q_f2 = f"SELECT count(*) as cnt FROM `{project_id}.{dataset_id}.findings` WHERE scan_id = '{scan_id_2}'"
    cnt_2 = list(bq_client.query(q_f2).result())[0].cnt
    
    # Check if a skipped guard log exists in scan_tool_log
    q_log = f"SELECT count(*) as cnt FROM `{project_id}.{dataset_id}.scan_tool_log` WHERE scan_id = '{scan_id_2}' AND status = 'skipped'"
    cnt_log = list(bq_client.query(q_log).result())[0].cnt

    print(f"Scan 2 findings: {cnt_2}, guard logs: {cnt_log}")
    if cnt_2 == 0 and cnt_log > 0:
        results["test_4_false_positive_suppression"] = {"status": "pass"}
    else:
        results["test_4_false_positive_suppression"] = {"status": "fail"}

except Exception as e:
    print(f"FAIL: Exception in Test 4: {e}")
finally:
    clean_customer_data(t4_customer_id)


# =====================================================================
# TEST 5 — CVE HALLUCINATION PREVENTION
# =====================================================================
time.sleep(20)
print("\n--- Starting Test 5 — CVE Hallucination Prevention ---")
t5_customer_id = "validation-test-5"
results["test_5_cve_hallucination_prevention"] = {"status": "fail"}

try:
    clean_customer_data(t5_customer_id)
    scan_id = str(uuid.uuid4())
    started_at = datetime.utcnow()

    # Seed scan
    bq_client.load_table_from_json([{
        "scan_id": scan_id, "customer_id": t5_customer_id, "started_at": started_at.isoformat() + "Z", "status": "completed"
    }], f"{project_id}.{dataset_id}.scans").result()

    # Seed asset with specific technology version
    asset_id = str(uuid.uuid4())
    asset_row = {
        "asset_id": asset_id, "customer_id": t5_customer_id, "type": "subdomain", "value": "cve.testfire.net",
        "discovered_at": started_at.isoformat() + "Z", "last_seen_at": started_at.isoformat() + "Z", "status": "active",
        "confidence_score": 0.8, "source_tools": ["subfinder"]
    }
    bq_client.load_table_from_json([asset_row], f"{project_id}.{dataset_id}.assets").result()
    bq_client.load_table_from_json([
        {"asset_id": asset_id, "customer_id": t5_customer_id, "key": "port", "value": "80", "updated_at": started_at.isoformat() + "Z"},
        {"asset_id": asset_id, "customer_id": t5_customer_id, "key": "technology:Apache", "value": "2.4.29", "updated_at": started_at.isoformat() + "Z"}
    ], f"{project_id}.{dataset_id}.asset_properties").result()

    # Get valid CVEs from NVD lookup service directly
    lookup_resp = requests.post(f"{nvd_lookup_url}/lookup", json={"technology": "Apache", "version": "2.4.29"}, headers=get_auth_headers(), timeout=20)
    valid_cves = set()
    if lookup_resp.status_code == 200:
        cve_list = lookup_resp.json().get("cves", [])
        valid_cves = {c.get("cve_id") for c in cve_list if c.get("cve_id")}
    print(f"Valid CVEs in NVD lookup database: {valid_cves}")

    # Run analyze
    requests.post(f"{agent_url}/analyze", json={"scan_id": scan_id, "customer_id": t5_customer_id}, headers=get_auth_headers(), timeout=600)

    # Check cve_ids written to findings table
    q_f = f"SELECT cve_ids FROM `{project_id}.{dataset_id}.findings` WHERE scan_id = '{scan_id}'"
    f_rows = list(bq_client.query(q_f).result())
    
    hallucinated = False
    written_cves = []
    if f_rows:
        written_cves = f_rows[0].cve_ids or []
        for cve in written_cves:
            if cve not in valid_cves:
                hallucinated = True
                print(f"Hallucinated CVE detected: {cve}")
                
    print(f"Written CVEs: {written_cves}, hallucinated: {hallucinated}")
    if not hallucinated and len(written_cves) > 0:
        results["test_5_cve_hallucination_prevention"] = {"status": "pass"}
    else:
        results["test_5_cve_hallucination_prevention"] = {"status": "fail"}

except Exception as e:
    print(f"FAIL: Exception in Test 5: {e}")
finally:
    clean_customer_data(t5_customer_id)


# =====================================================================
# TEST 6 — FULL PIPELINE HANDOFF
# =====================================================================
time.sleep(20)
print("\n--- Starting Test 6 — Full Pipeline Handoff ---")
t6_customer_id = "validation-test-6"
results["test_6_pipeline_handoff"] = {"status": "fail"}

try:
    clean_customer_data(t6_customer_id)
    scan_id = str(uuid.uuid4())
    started_at = datetime.utcnow()
    
    # 1. Seed scan and asset so there is something to analyze
    bq_client.load_table_from_json([{
        "scan_id": scan_id, "customer_id": t6_customer_id, "started_at": started_at.isoformat() + "Z", "status": "completed"
    }], f"{project_id}.{dataset_id}.scans").result()

    asset_id = str(uuid.uuid4())
    asset_row = {
        "asset_id": asset_id, "customer_id": t6_customer_id, "type": "subdomain", "value": "pipeline.testfire.net",
        "discovered_at": started_at.isoformat() + "Z", "last_seen_at": started_at.isoformat() + "Z", "status": "active",
        "confidence_score": 0.8, "source_tools": ["subfinder"]
    }
    bq_client.load_table_from_json([asset_row], f"{project_id}.{dataset_id}.assets").result()
    bq_client.load_table_from_json([
        {"asset_id": asset_id, "customer_id": t6_customer_id, "key": "port", "value": "80", "updated_at": started_at.isoformat() + "Z"},
        {"asset_id": asset_id, "customer_id": t6_customer_id, "key": "technology:Apache", "value": "2.4.29", "updated_at": started_at.isoformat() + "Z"}
    ], f"{project_id}.{dataset_id}.asset_properties").result()

    # 2. Setup Pub/Sub subscriber to listen to easm-analysis-complete
    subscriber = pubsub_v1.SubscriberClient()
    subscription_name = f"projects/{project_id}/subscriptions/temp-easm-analysis-complete-sub"
    topic_name = f"projects/{project_id}/topics/easm-analysis-complete"
    
    # Create temporary subscription
    try:
        subscriber.create_subscription(name=subscription_name, topic=topic_name, ack_deadline_seconds=60)
        print("Created temporary subscription to easm-analysis-complete.")
    except Exception:
        # If subscription already exists, reuse it
        pass

    # 3. Publish completion message to easm-scan-complete topic
    publisher = pubsub_v1.PublisherClient()
    scan_complete_topic = f"projects/{project_id}/topics/easm-scan-complete"
    scan_complete_payload = {
        "scan_id": scan_id,
        "customer_id": t6_customer_id,
        "assets_new": 1,
        "assets_changed": 0,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    print(f"Publishing scan-complete message for scan {scan_id}...")
    publisher.publish(scan_complete_topic, json.dumps(scan_complete_payload).encode("utf-8")).result()

    # 4. Poll and wait for message on the temp subscription (wait up to 90 seconds)
    print("Polling easm-analysis-complete subscription...")
    received_message = False
    start_time = time.time()
    
    while time.time() - start_time < 90:
        try:
            response = subscriber.pull(subscription=subscription_name, max_messages=1, timeout=5)
        except Exception as e:
            if "DeadlineExceeded" in type(e).__name__ or "504" in str(e) or "Deadline" in str(e):
                continue
            raise e
            
        if response.received_messages:
            for msg in response.received_messages:
                payload_str = msg.message.data.decode("utf-8")
                payload = json.loads(payload_str)
                print("Received message on easm-analysis-complete:", payload)
                if payload.get("scan_id") == scan_id:
                    received_message = True
                    subscriber.acknowledge(subscription=subscription_name, ack_ids=[msg.ack_id])
                    break
                else:
                    # Clear backlog of older runs
                    subscriber.acknowledge(subscription=subscription_name, ack_ids=[msg.ack_id])
            if received_message:
                break
        time.sleep(5)

    # Clean up subscription
    try:
        subscriber.delete_subscription(subscription=subscription_name)
        print("Cleaned up temporary subscription.")
    except Exception:
        pass

    if received_message:
        results["test_6_pipeline_handoff"] = {"status": "pass"}
    else:
        results["test_6_pipeline_handoff"] = {"status": "fail"}

except Exception as e:
    print(f"FAIL: Exception in Test 6: {e}")
finally:
    clean_customer_data(t6_customer_id)


# =====================================================================
# FINAL REPORT COMPILATION
# =====================================================================
print("\n")
print("=======================================================")
print("PHASE 2 VALIDATION REPORT")
print(f"Project:   {project_id}")
print(f"Dataset:   {dataset_id}")
print(f"Run at:    {datetime.utcnow().isoformat()}Z")
print("=======================================================")

passed_count = sum(1 for t in results.values() if t.get("status") == "pass")
failed_list = [name for name, t in results.items() if t.get("status") != "pass"]

for t_num, (t_name, t_data) in enumerate(results.items(), 1):
    status_str = "PASS" if t_data.get("status") == "pass" else "FAIL"
    print(f"TEST {t_num} — {t_name.replace('test_', '').replace('_', ' ').upper():<35} [ {status_str} ]")

print("=======================================================")
print(f"RESULT: {passed_count}/6 TESTS PASSED")
print("=======================================================")

report = {
    "project_id": project_id,
    "dataset": dataset_id,
    "run_at": datetime.utcnow().isoformat() + "Z",
    "results": results,
    "overall": {
        "passed": passed_count,
        "failed": len(failed_list),
        "ready_for_phase_3": passed_count == 6
    }
}

report_path = r"C:\Scybers\Detection Agent\tests\e2e\phase2_validation_report.json"
with open(report_path, "w") as f:
    json.dump(report, f, indent=2)

print(f"\nJSON report saved to: {report_path}")

import json
import os
import sys
from google.cloud import bigquery

project_id = "scyra-agents-495519"
dataset_id = "easm_attack_surface"
table_id = "org_context"

def run_seed():
    print("Starting org_context seeding...")
    
    # Path to seed file
    seed_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "tests", "e2e", "fixtures", "org_context_seed.json"))
    if not os.path.exists(seed_path):
        print(f"Error: Seed file not found at: {seed_path}")
        sys.exit(1)
        
    with open(seed_path, "r") as f:
        records = json.load(f)
        
    print(f"Loaded {len(records)} records from seed JSON.")
    
    bq_client = bigquery.Client(project=project_id)
    table_ref = f"{project_id}.{dataset_id}.{table_id}"
    
    job_config = bigquery.LoadJobConfig(
        write_disposition=bigquery.WriteDisposition.WRITE_APPEND,
        source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON
    )
    
    # Run the batch load job
    print(f"Running BigQuery batch load job for table: {table_ref}...")
    load_job = bq_client.load_table_from_json(records, table_ref, job_config=job_config)
    load_job.result()
    
    print("Batch load job completed successfully!")
    
    # Verification query
    q = f"SELECT COUNT(*) as cnt FROM `{table_ref}` WHERE customer_id = 'manual-customer'"
    res = list(bq_client.query(q).result())
    count = res[0].cnt if res else 0
    print(f"Verification query result: found {count} records in {table_id} for 'manual-customer'.")

if __name__ == "__main__":
    run_seed()

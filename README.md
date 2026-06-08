# Scyra External Attack Surface Management (EASM) - Phase 1 Scanner Pipeline

This is Phase 1 of a multi-phase enterprise External Attack Surface Management (EASM) platform deployed on Google Cloud Platform (GCP). The pipeline is fully deterministic, timer-triggered, and orchestrated using Google Cloud Workflows.

## Architecture Overview

Phase 1 consists of:
- **Scope Profiler Service**: Classifies scan seeds into Tiers (A, B, or C).
- **Subfinder Service**: Passive subdomain discovery using Subfinder and VirusTotal.
- **DNSX Service**: DNS resolution using dnsx.
- **Crt.sh Service**: Certificate transparency log search.
- **Exposure Service**: IP/Port/Service scanner using Censys.
- **Httpx Service**: Web technology detection and vulnerability scanning (Nuclei).
- **BigQuery Writer Service**: Streaming data ingestion and deduplication.
- **Delta Engine**: Net new and gone asset state tracking.
- **Cloud Workflows**: Orchestrator coordinating service fan-out and sequence.
- **Cloud Scheduler**: Automated daily scanner triggers.

## Repository Structure

```
easm-platform/
├── .github/
│   └── workflows/
│       ├── pr.yaml
│       └── deploy.yaml
├── infrastructure/
│   ├── terraform/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   ├── bigquery.tf
│   │   ├── pubsub.tf
│   │   ├── cloudrun.tf
│   │   ├── workflows.tf
│   │   ├── scheduler.tf
│   │   └── iam.tf
│   └── workflows/
│       └── scan-pipeline.yaml
├── services/
│   ├── scope-profiler/
│   ├── subfinder-service/
│   ├── dnsx-service/
│   ├── crtsh-service/
│   ├── exposure-service/
│   ├── httpx-service/
│   ├── bigquery-writer/
│   └── delta-engine/
└── tests/
    ├── unit/
    ├── integration/
    └── e2e/
        ├── phase1_validation.py
        └── fixtures/
            ├── generate_ground_truth.py
            └── ground_truth.json
```

## How-To Guides

### 1. How to Trigger a Manual Scan for Any Domain

To trigger a manual scan, publish a message to the `easm-scan-trigger` Pub/Sub topic:

```bash
gcloud pubsub topics publish easm-scan-trigger \
  --message='{"customer_id": "manual-customer", "seed": {"domains": ["example.com"]}, "triggered_by": "manual"}'
```

### 2. How to Add a New Customer and Their Domains

To add a new customer and set up automated daily scanning:
1. Open the Terraform configuration file `infrastructure/terraform/scheduler.tf`.
2. Define a new `google_cloud_scheduler_job` resource:
   ```hcl
   resource "google_cloud_scheduler_job" "customer_name_job" {
     name        = "scan-trigger-customer-name"
     description = "Daily scan trigger for Customer Name"
     schedule    = "0 2 * * *"  # 02:00 UTC daily
     time_zone   = "UTC"

     pubsub_target {
       topic_name = google_pubsub_topic.scan_trigger.id
       data       = base64encode(jsonencode({
         customer_id  = "customer-name"
         seed = {
           domains    = ["customername.com"]
           org_name   = "Customer Name Org"
           asn_ranges = []
           known_ips  = []
         }
         triggered_by = "scheduler"
       }))
     }
   }
   ```
3. Run `terraform apply` (or merge to `main` for automated deploy).

### 3. How to Update an Existing Customer's Domain List

To update an existing customer's scanned domains:
1. Locate the customer's `google_cloud_scheduler_job` in `infrastructure/terraform/scheduler.tf`.
2. Update the `domains` list inside the JSON encoded payload.
3. Run `terraform apply` (or merge to `main` for automated deploy).

### 4. How to Run the Validation Suite

To run the end-to-end Phase 1 validation tests:
1. Ensure you are authenticated to GCP with `gcloud auth application-default login`.
2. Generate the ground truth dataset:
   ```bash
   python tests/e2e/fixtures/generate_ground_truth.py
   ```
3. Run the validation suite:
   ```bash
   python tests/e2e/phase1_validation.py
   ```

### 5. How to Deploy to Prod

The pipeline uses GitHub Actions for CI/CD:
1. **Develop/Dev deployment**: On a Pull Request to `develop` branch, the PR pipeline runs unit tests, performs `terraform plan`, builds and pushes images to Artifact Registry, and runs integration tests in the dev project. Merging to `main` deploys to the dev environment.
2. **Production deployment**: Production deployment is gated. Merging changes to `main` triggers a deploy to dev, runs E2E tests, and then requests manual approval to run `terraform apply` on the prod environment workspace.

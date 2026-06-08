# Phase 2: Analyzer Agent Infrastructure

# 1. Enable Required APIs
resource "google_project_service" "redis" {
  project            = var.project_id
  service            = "redis.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "vpcaccess" {
  project            = var.project_id
  service            = "vpcaccess.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "servicenetworking" {
  project            = var.project_id
  service            = "servicenetworking.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "aiplatform" {
  project            = var.project_id
  service            = "aiplatform.googleapis.com"
  disable_on_destroy = false
}

# 2. Service Networking & Private Service Access for Redis
resource "google_compute_global_address" "redis_private_ip_alloc" {
  name          = "easm-redis-private-ip-alloc"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = "default"
  project       = var.project_id
}

resource "google_service_networking_connection" "redis_private_vpc_connection" {
  network                 = "default"
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.redis_private_ip_alloc.name]
  depends_on              = [google_project_service.servicenetworking]
}

# 3. Memorystore Redis Instance
resource "google_redis_instance" "nvd_cache" {
  name                    = "easm-nvd-cache"
  tier                    = "BASIC"
  memory_size_gb          = 1
  redis_version           = "REDIS_7_0"
  region                  = var.region
  project                 = var.project_id
  authorized_network      = "default"
  connect_mode            = "PRIVATE_SERVICE_ACCESS"

  depends_on = [
    google_project_service.redis,
    google_service_networking_connection.redis_private_vpc_connection
  ]
}

# 4. VPC Access Connector (Cloud Run -> Redis)
resource "google_vpc_access_connector" "connector" {
  name          = "easm-vpc-connector"
  region        = var.region
  project       = var.project_id
  ip_cidr_range = "10.9.0.0/28"
  network       = "default"
  depends_on    = [google_project_service.vpcaccess]
}

# 5. Service Account for Analyzer Agent
resource "google_service_account" "analyzer" {
  account_id   = "easm-analyzer-sa"
  display_name = "EASM Analyzer Service Account"
  project       = var.project_id
  depends_on   = [google_project_service.aiplatform]
}

# 6. IAM Bindings for easm-analyzer-sa
resource "google_project_iam_member" "analyzer_aiplatform" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.analyzer.email}"
}

resource "google_project_iam_member" "analyzer_bigquery_viewer" {
  project = var.project_id
  role    = "roles/bigquery.dataViewer"
  member  = "serviceAccount:${google_service_account.analyzer.email}"
}

resource "google_project_iam_member" "analyzer_bigquery_user" {
  project = var.project_id
  role    = "roles/bigquery.user"
  member  = "serviceAccount:${google_service_account.analyzer.email}"
}

resource "google_project_iam_member" "analyzer_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.analyzer.email}"
}

# Table-specific write permission on findings table (using bigquery_table from Phase 1)
resource "google_bigquery_table_iam_member" "analyzer_findings_editor" {
  project    = var.project_id
  dataset_id = "easm_attack_surface"
  table_id   = "findings"
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.analyzer.email}"
}

resource "google_bigquery_table_iam_member" "analyzer_scan_tool_log_editor" {
  project    = var.project_id
  dataset_id = "easm_attack_surface"
  table_id   = "scan_tool_log"
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.analyzer.email}"
}

resource "google_secret_manager_secret_iam_member" "analyzer_nvd_key_accessor" {
  project   = var.project_id
  secret_id = "nvd-api-key"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.analyzer.email}"
}

resource "google_project_iam_member" "analyzer_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.analyzer.email}"
}

resource "google_project_iam_member" "analyzer_pubsub_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.analyzer.email}"
}

# 7. Pub/Sub Topics
resource "google_pubsub_topic" "analysis_complete" {
  name    = "easm-analysis-complete"
  project = var.project_id
}

resource "google_pubsub_topic" "analysis_alerts" {
  name    = "easm-analysis-alerts"
  project = var.project_id
}

# 8. BigQuery Table: org_context
resource "google_bigquery_table" "org_context" {
  dataset_id = "easm_attack_surface"
  table_id   = "org_context"
  project    = var.project_id

  schema = <<EOF
[
  {"name": "customer_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "hostname", "type": "STRING", "mode": "REQUIRED"},
  {"name": "owner_team", "type": "STRING", "mode": "NULLABLE"},
  {"name": "data_classification", "type": "STRING", "mode": "NULLABLE"},
  {"name": "business_criticality", "type": "STRING", "mode": "NULLABLE"},
  {"name": "known_third_party", "type": "BOOLEAN", "mode": "NULLABLE"},
  {"name": "known_false_positive", "type": "BOOLEAN", "mode": "NULLABLE"},
  {"name": "notes", "type": "STRING", "mode": "NULLABLE"},
  {"name": "last_updated", "type": "TIMESTAMP", "mode": "NULLABLE"}
]
EOF

  clustering          = ["customer_id"]
  deletion_protection = false
}

# 9. BQ Additive ALTER for findings table (additive schema updates)
resource "terraform_data" "update_findings_schema" {
  input = {
    project_id = var.project_id
  }

  provisioner "local-exec" {
    command     = "bq query --use_legacy_sql=false --project_id=${self.input.project_id} \"ALTER TABLE easm_attack_surface.findings ADD COLUMN IF NOT EXISTS scan_id STRING, ADD COLUMN IF NOT EXISTS attack_narrative STRING, ADD COLUMN IF NOT EXISTS evidence JSON, ADD COLUMN IF NOT EXISTS cve_ids ARRAY<STRING>, ADD COLUMN IF NOT EXISTS cvss_score FLOAT64, ADD COLUMN IF NOT EXISTS exploit_available BOOLEAN, ADD COLUMN IF NOT EXISTS confidence_score FLOAT64, ADD COLUMN IF NOT EXISTS prior_finding_id STRING, ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP; ALTER TABLE easm_attack_surface.assets ADD COLUMN IF NOT EXISTS confidence_score FLOAT64;\""
    interpreter = ["PowerShell", "-Command"]
  }
}

# 10. Update Row-Level Security (RLS) policies on assets, scans, findings, asset_properties, scan_tool_log, and org_context
resource "terraform_data" "apply_rls_phase2" {
  for_each = toset(["assets", "asset_properties", "scans", "findings", "scan_tool_log", "org_context"])

  input = {
    project_id  = var.project_id
    dataset_id  = "easm_attack_surface"
    table_id    = each.value
    scanner_sa  = "easm-scanner-sa@scyra-agents-495519.iam.gserviceaccount.com"
    analyzer_sa = google_service_account.analyzer.email
  }

  provisioner "local-exec" {
    command     = "bq query --use_legacy_sql=false --project_id=${self.input.project_id} \"CREATE OR REPLACE ROW ACCESS POLICY customer_rls_policy ON ${self.input.dataset_id}.${self.input.table_id} GRANT TO ('user:seniruekanayaketestacc@gmail.com', 'serviceAccount:${self.input.scanner_sa}', 'serviceAccount:${self.input.analyzer_sa}') FILTER USING (customer_id = 'manual-customer' OR customer_id = 'phase2-test' OR customer_id = 'validation-test-1' OR customer_id = 'validation-test-2' OR customer_id = 'validation-test-3' OR customer_id = 'validation-test-6' OR customer_id = 'tenant-isolation-A' OR customer_id = 'tenant-isolation-B' OR SESSION_USER() = 'seniruekanayaketestacc@gmail.com' OR SESSION_USER() = '${self.input.scanner_sa}' OR SESSION_USER() = '${self.input.analyzer_sa}')\""
    interpreter = ["PowerShell", "-Command"]
  }

  depends_on = [
    google_bigquery_table.org_context,
    google_service_account.analyzer,
    terraform_data.update_findings_schema
  ]
}

# 11. Cloud Run: NVD Lookup Service
resource "google_cloud_run_service" "nvd_lookup" {
  name     = "easm-nvd-lookup-service"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${var.region}-docker.pkg.dev/${var.project_id}/easm-services/easm-nvd-lookup-service:latest"
        resources {
          limits = {
            memory = "1Gi"
            cpu    = "1"
          }
        }
        env {
          name  = "REDIS_HOST"
          value = google_redis_instance.nvd_cache.host
        }
      }
      service_account_name = google_service_account.analyzer.email
    }
    metadata {
      annotations = {
        "run.googleapis.com/vpc-access-connector" = google_vpc_access_connector.connector.name
        "run.googleapis.com/vpc-access-egress"    = "private-ranges-only"
      }
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [
    google_service_account.analyzer,
    google_redis_instance.nvd_cache,
    google_vpc_access_connector.connector
  ]
}

# 12. Cloud Run: Analyzer Agent Service
resource "google_cloud_run_service" "analyzer_agent" {
  name     = "easm-analyzer-agent-service"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${var.region}-docker.pkg.dev/${var.project_id}/easm-services/easm-analyzer-agent-service:latest"
        resources {
          limits = {
            memory = "2Gi"
            cpu    = "2"
          }
        }
        env {
          name  = "NVD_LOOKUP_URL"
          value = google_cloud_run_service.nvd_lookup.status[0].url
        }
      }
      service_account_name = google_service_account.analyzer.email
      timeout_seconds      = 600
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [
    google_service_account.analyzer,
    google_cloud_run_service.nvd_lookup
  ]
}

# 13. Cloud Run: Analyzer Trigger Service
resource "google_cloud_run_service" "analyzer_trigger" {
  name     = "easm-analyzer-trigger-service"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${var.region}-docker.pkg.dev/${var.project_id}/easm-services/easm-analyzer-trigger-service:latest"
        resources {
          limits = {
            memory = "512Mi"
            cpu    = "1000m"
          }
        }
        env {
          name  = "ANALYZER_AGENT_URL"
          value = google_cloud_run_service.analyzer_agent.status[0].url
        }
      }
      service_account_name = google_service_account.analyzer.email
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [
    google_service_account.analyzer,
    google_cloud_run_service.analyzer_agent
  ]
}

# 14. Pub/Sub Push Subscription: easm-scan-complete -> analyzer-trigger-service
resource "google_pubsub_subscription" "analyzer_trigger_push" {
  name                 = "easm-analysis-trigger-sub"
  project              = var.project_id
  topic                = "easm-scan-complete"
  ack_deadline_seconds = 600

  push_config {
    push_endpoint = "${google_cloud_run_service.analyzer_trigger.status[0].url}/trigger"

    oidc_token {
      service_account_email = google_service_account.analyzer.email
    }
  }

  depends_on = [
    google_cloud_run_service.analyzer_trigger
  ]
}

# 15. IAM Invoker Bindings
resource "google_cloud_run_service_iam_member" "trigger_invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloud_run_service.analyzer_trigger.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.analyzer.email}"
}

resource "google_cloud_run_service_iam_member" "agent_invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloud_run_service.analyzer_agent.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.analyzer.email}"
}

resource "google_cloud_run_service_iam_member" "nvd_invoker" {
  project  = var.project_id
  location = var.region
  service  = google_cloud_run_service.nvd_lookup.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.analyzer.email}"
}

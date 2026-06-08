resource "google_bigquery_dataset" "easm" {
  dataset_id  = "easm_attack_surface"
  description = "EASM attack surface database containing assets, scans, and findings"
  location    = var.region
  depends_on  = [google_project_service.enabled_apis]
}

# 1. Assets Table
resource "google_bigquery_table" "assets" {
  dataset_id = google_bigquery_dataset.easm.dataset_id
  table_id   = "assets"

  schema = <<EOF
[
  {"name": "asset_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "customer_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "type", "type": "STRING", "mode": "REQUIRED"},
  {"name": "value", "type": "STRING", "mode": "REQUIRED"},
  {"name": "discovered_at", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "last_seen_at", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "status", "type": "STRING", "mode": "REQUIRED"},
  {"name": "hostname", "type": "STRING", "mode": "NULLABLE"},
  {"name": "asset_type", "type": "STRING", "mode": "NULLABLE"},
  {"name": "source_tools", "type": "STRING", "mode": "REPEATED"}
]
EOF

  deletion_protection = false
}

# 2. Asset Properties Table
resource "google_bigquery_table" "asset_properties" {
  dataset_id = google_bigquery_dataset.easm.dataset_id
  table_id   = "asset_properties"

  schema = <<EOF
[
  {"name": "asset_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "customer_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "key", "type": "STRING", "mode": "REQUIRED"},
  {"name": "value", "type": "STRING", "mode": "REQUIRED"},
  {"name": "updated_at", "type": "TIMESTAMP", "mode": "REQUIRED"}
]
EOF

  deletion_protection = false
}

# 3. Scans Table
resource "google_bigquery_table" "scans" {
  dataset_id = google_bigquery_dataset.easm.dataset_id
  table_id   = "scans"

  schema = <<EOF
[
  {"name": "scan_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "customer_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "status", "type": "STRING", "mode": "REQUIRED"},
  {"name": "started_at", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "ended_at", "type": "TIMESTAMP", "mode": "NULLABLE"},
  {"name": "seed", "type": "STRING", "mode": "NULLABLE"},
  {"name": "functions_run", "type": "STRING", "mode": "REPEATED"},
  {"name": "functions_failed", "type": "STRING", "mode": "REPEATED"},
  {"name": "assets_new", "type": "INT64", "mode": "NULLABLE"},
  {"name": "assets_gone", "type": "INT64", "mode": "NULLABLE"}
]
EOF

  deletion_protection = false
}

# 4. Findings Table
resource "google_bigquery_table" "findings" {
  dataset_id = google_bigquery_dataset.easm.dataset_id
  table_id   = "findings"

  schema = <<EOF
[
  {"name": "finding_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "customer_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "asset_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "severity", "type": "STRING", "mode": "REQUIRED"},
  {"name": "title", "type": "STRING", "mode": "REQUIRED"},
  {"name": "description", "type": "STRING", "mode": "NULLABLE"},
  {"name": "remediation", "type": "STRING", "mode": "NULLABLE"},
  {"name": "created_at", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "status", "type": "STRING", "mode": "REQUIRED"}
]
EOF

  deletion_protection = false
}

# 5. Scan Tool Log Table
resource "google_bigquery_table" "scan_tool_log" {
  dataset_id = google_bigquery_dataset.easm.dataset_id
  table_id   = "scan_tool_log"

  schema = <<EOF
[
  {"name": "log_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "scan_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "customer_id", "type": "STRING", "mode": "REQUIRED"},
  {"name": "tool_name", "type": "STRING", "mode": "REQUIRED"},
  {"name": "status", "type": "STRING", "mode": "REQUIRED"},
  {"name": "raw_output", "type": "STRING", "mode": "NULLABLE"},
  {"name": "timestamp", "type": "TIMESTAMP", "mode": "REQUIRED"},
  {"name": "function_name", "type": "STRING", "mode": "NULLABLE"},
  {"name": "invoked_at", "type": "TIMESTAMP", "mode": "NULLABLE"},
  {"name": "duration_ms", "type": "INT64", "mode": "NULLABLE"},
  {"name": "result_count", "type": "INT64", "mode": "NULLABLE"},
  {"name": "error", "type": "STRING", "mode": "NULLABLE"},
  {"name": "tool_version", "type": "STRING", "mode": "NULLABLE"}
]
EOF

  deletion_protection = false
}

# Row-Level Security (RLS) Policies applied via bq CLI query
resource "terraform_data" "apply_rls" {
  for_each = toset(["assets", "asset_properties", "scans", "findings", "scan_tool_log"])

  input = {
    project_id = var.project_id
    dataset_id = google_bigquery_dataset.easm.dataset_id
    table_id   = each.value
    scanner_sa = google_service_account.scanner.email
  }

  provisioner "local-exec" {
    command     = "bq query --use_legacy_sql=false --project_id=${self.input.project_id} \"CREATE OR REPLACE ROW ACCESS POLICY customer_rls_policy ON ${self.input.dataset_id}.${self.input.table_id} GRANT TO ('user:seniruekanayaketestacc@gmail.com', 'serviceAccount:${self.input.scanner_sa}') FILTER USING (customer_id = 'manual-customer' OR SESSION_USER() = 'seniruekanayaketestacc@gmail.com' OR SESSION_USER() = '${self.input.scanner_sa}')\""
    interpreter = ["PowerShell", "-Command"]
  }

  provisioner "local-exec" {
    command     = "bq query --use_legacy_sql=false --project_id=${self.input.project_id} \"CREATE OR REPLACE ROW ACCESS POLICY full_access_policy ON ${self.input.dataset_id}.${self.input.table_id} GRANT TO ('user:seniruekanayaketestacc@gmail.com', 'serviceAccount:${self.input.scanner_sa}') FILTER USING (TRUE)\""
    interpreter = ["PowerShell", "-Command"]
  }

  depends_on = [
    google_bigquery_table.assets,
    google_bigquery_table.asset_properties,
    google_bigquery_table.scans,
    google_bigquery_table.findings,
    google_bigquery_table.scan_tool_log,
    google_service_account.scanner
  ]
}

resource "google_secret_manager_secret_iam_member" "censys_id_accessor" {
  project   = var.project_id
  secret_id = "censys-api-id"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_secret_manager_secret_iam_member" "censys_secret_accessor" {
  project   = var.project_id
  secret_id = "censys-api-secret"
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.scanner.email}"
}

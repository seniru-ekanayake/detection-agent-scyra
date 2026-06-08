# Service Accounts
resource "google_service_account" "scanner" {
  account_id   = "easm-scanner-sa"
  display_name = "EASM Scanner Service Account"
  depends_on   = [google_project_service.enabled_apis]
}

resource "google_service_account" "workflows" {
  account_id   = "easm-workflows-sa"
  display_name = "EASM Workflows Service Account"
  depends_on   = [google_project_service.enabled_apis]
}

resource "google_service_account" "scheduler" {
  account_id   = "easm-scheduler-sa"
  display_name = "EASM Scheduler Service Account"
  depends_on   = [google_project_service.enabled_apis]
}



resource "google_project_iam_member" "scanner_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_project_iam_member" "scanner_pubsub_subscriber" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_project_iam_member" "scanner_bigquery_editor" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_project_iam_member" "scanner_bigquery_user" {
  project = var.project_id
  role    = "roles/bigquery.user"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

resource "google_project_iam_member" "scanner_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.scanner.email}"
}

# IAM Role Bindings for Workflows Service Account
resource "google_project_iam_member" "workflows_run_invoker" {
  project = var.project_id
  role    = "roles/run.invoker"
  member  = "serviceAccount:${google_service_account.workflows.email}"
}

resource "google_project_iam_member" "workflows_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.workflows.email}"
}

resource "google_project_iam_member" "workflows_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.workflows.email}"
}

# IAM Role Bindings for Scheduler Service Account
resource "google_project_iam_member" "scheduler_pubsub_publisher" {
  project = var.project_id
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${google_service_account.scheduler.email}"
}

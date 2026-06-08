# Pub/Sub Topics
resource "google_pubsub_topic" "scan_trigger" {
  name       = "easm-scan-trigger"
  project    = var.project_id
  depends_on = [google_project_service.enabled_apis]
}

resource "google_pubsub_topic" "scan_results" {
  name       = "easm-scan-results"
  project    = var.project_id
  depends_on = [google_project_service.enabled_apis]
}

resource "google_pubsub_topic" "scan_complete" {
  name       = "easm-scan-complete"
  project    = var.project_id
  depends_on = [google_project_service.enabled_apis]
}

resource "google_pubsub_topic" "scan_alerts" {
  name       = "easm-scan-alerts"
  project    = var.project_id
  depends_on = [google_project_service.enabled_apis]
}

# Pub/Sub Push Subscription for BigQuery Writer (Cloud Run)
# The push endpoint will point to the Cloud Run service URL.
resource "google_pubsub_subscription" "bigquery_writer_push" {
  name                 = "easm-bigquery-writer-push"
  project              = var.project_id
  topic                = google_pubsub_topic.scan_results.name
  ack_deadline_seconds = 60

  push_config {
    push_endpoint = "${google_cloud_run_service.bigquery_writer.status[0].url}/write"

    oidc_token {
      service_account_email = google_service_account.scanner.email
    }
  }

  depends_on = [
    google_pubsub_topic.scan_results,
    google_cloud_run_service.bigquery_writer
  ]
}

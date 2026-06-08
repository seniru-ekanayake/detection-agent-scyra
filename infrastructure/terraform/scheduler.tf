# Cloud Scheduler Trigger for Daily Scan
resource "google_cloud_scheduler_job" "daily_scan_manual_customer" {
  name        = "easm-daily-scan-manual-customer"
  description = "Triggers daily scanning pipeline for manual-customer"
  schedule    = "0 0 * * *" # Daily at midnight UTC
  time_zone   = "UTC"
  project     = var.project_id
  region      = var.region

  pubsub_target {
    topic_name = google_pubsub_topic.scan_trigger.id
    data = base64encode(jsonencode({
      customer_id = "manual-customer"
      seed = {
        domains = ["example.com"]
      }
      triggered_by = "scheduler"
    }))
  }

  depends_on = [
    google_pubsub_topic.scan_trigger,
    google_project_service.enabled_apis
  ]
}

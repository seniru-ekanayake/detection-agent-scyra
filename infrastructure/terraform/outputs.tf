output "bigquery_dataset_id" {
  description = "The BigQuery dataset ID"
  value       = google_bigquery_dataset.easm.dataset_id
}

output "pubsub_topic_scan_trigger" {
  description = "The Pub/Sub topic for scan triggers"
  value       = google_pubsub_topic.scan_trigger.id
}

output "pubsub_topic_scan_results" {
  description = "The Pub/Sub topic for scan results"
  value       = google_pubsub_topic.scan_results.id
}

output "pubsub_topic_scan_complete" {
  description = "The Pub/Sub topic for scan completion"
  value       = google_pubsub_topic.scan_complete.id
}

output "pubsub_topic_scan_alerts" {
  description = "The Pub/Sub topic for alerts"
  value       = google_pubsub_topic.scan_alerts.id
}

output "workflow_id" {
  description = "The Cloud Workflows ID"
  value       = google_workflows_workflow.scan_pipeline.id
}

output "scanner_service_account" {
  description = "The scanner service account email"
  value       = google_service_account.scanner.email
}

output "workflows_service_account" {
  description = "The workflows service account email"
  value       = google_service_account.workflows.email
}

output "scheduler_service_account" {
  description = "The scheduler service account email"
  value       = google_service_account.scheduler.email
}

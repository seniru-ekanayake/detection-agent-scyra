resource "google_workflows_workflow" "scan_pipeline" {
  name            = "easm-scan-pipeline"
  region          = var.region
  project         = var.project_id
  description     = "Orchestrator for the EASM scanning pipeline"
  service_account = google_service_account.workflows.email
  source_contents = file("${path.module}/../workflows/scan-pipeline.yaml")

  depends_on = [
    google_project_service.enabled_apis,
    google_service_account.workflows
  ]
}

# 1. Scope Profiler Service
resource "google_cloud_run_service" "scope_profiler" {
  name     = "easm-scope-profiler"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${google_artifact_registry_repository.easm.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.easm.repository_id}/easm-scope-profiler:latest"
        resources {
          limits = {
            memory = "512Mi"
            cpu    = "1000m"
          }
        }
      }
      service_account_name = google_service_account.scanner.email
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [google_project_service.enabled_apis, google_service_account.scanner]
}

# 2. Subfinder Service
resource "google_cloud_run_service" "subfinder" {
  name     = "easm-subfinder-service"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${google_artifact_registry_repository.easm.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.easm.repository_id}/easm-subfinder-service:latest"
        resources {
          limits = {
            memory = "2Gi"
            cpu    = "1"
          }
        }

        env {
          name = "VT_API_KEY"
          value_from {
            secret_key_ref {
              name = "virustotal-api-key"
              key  = "latest"
            }
          }
        }
      }
      service_account_name = google_service_account.scanner.email
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_service_account.scanner
  ]
}

# 3. DNSX Service
resource "google_cloud_run_service" "dnsx" {
  name     = "easm-dnsx-service"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${google_artifact_registry_repository.easm.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.easm.repository_id}/easm-dnsx-service:latest"
        resources {
          limits = {
            memory = "1Gi"
            cpu    = "1"
          }
        }
      }
      service_account_name = google_service_account.scanner.email
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [google_project_service.enabled_apis, google_service_account.scanner]
}

# 4. Crt.sh Service
resource "google_cloud_run_service" "crtsh" {
  name     = "easm-crtsh-service"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${google_artifact_registry_repository.easm.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.easm.repository_id}/easm-crtsh-service:latest"
        resources {
          limits = {
            memory = "512Mi"
            cpu    = "1000m"
          }
        }
      }
      service_account_name = google_service_account.scanner.email
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [google_project_service.enabled_apis, google_service_account.scanner]
}

# 5. Exposure Service (Censys)
resource "google_cloud_run_service" "exposure" {
  name     = "easm-exposure-service"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${google_artifact_registry_repository.easm.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.easm.repository_id}/easm-exposure-service:latest"
        resources {
          limits = {
            memory = "512Mi"
            cpu    = "1000m"
          }
        }

        env {
          name = "CENSYS_API_ID"
          value_from {
            secret_key_ref {
              name = "censys-api-id"
              key  = "latest"
            }
          }
        }
        env {
          name = "CENSYS_API_SECRET"
          value_from {
            secret_key_ref {
              name = "censys-api-secret"
              key  = "latest"
            }
          }
        }
      }
      service_account_name = google_service_account.scanner.email
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_service_account.scanner
  ]
}

# 6. Httpx Service (Nuclei / Vuln Scanning)
resource "google_cloud_run_service" "httpx" {
  name     = "easm-httpx-service"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${google_artifact_registry_repository.easm.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.easm.repository_id}/easm-httpx-service:latest"
        resources {
          limits = {
            memory = "2Gi"
            cpu    = "1"
          }
        }

        env {
          name = "NVD_API_KEY"
          value_from {
            secret_key_ref {
              name = "nvd-api-key"
              key  = "latest"
            }
          }
        }
      }
      service_account_name = google_service_account.scanner.email
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [
    google_project_service.enabled_apis,
    google_service_account.scanner
  ]
}

# 7. BigQuery Writer Service
resource "google_cloud_run_service" "bigquery_writer" {
  name     = "easm-bigquery-writer"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${google_artifact_registry_repository.easm.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.easm.repository_id}/easm-bigquery-writer:latest"
        resources {
          limits = {
            memory = "1Gi"
            cpu    = "1"
          }
        }
      }
      service_account_name = google_service_account.scanner.email
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [google_project_service.enabled_apis, google_service_account.scanner]
}

# 8. Delta Engine
resource "google_cloud_run_service" "delta_engine" {
  name     = "easm-delta-engine"
  location = var.region
  project  = var.project_id

  template {
    spec {
      containers {
        image = "${google_artifact_registry_repository.easm.location}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.easm.repository_id}/easm-delta-engine:latest"
        resources {
          limits = {
            memory = "1Gi"
            cpu    = "1"
          }
        }
      }
      service_account_name = google_service_account.scanner.email
    }
  }

  traffic {
    percent         = 100
    latest_revision = true
  }

  depends_on = [google_project_service.enabled_apis, google_service_account.scanner]
}

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# List of APIs to enable
locals {
  services = [
    "iam.googleapis.com",
    "pubsub.googleapis.com",
    "bigquery.googleapis.com",
    "run.googleapis.com",
    "workflows.googleapis.com",
    "cloudscheduler.googleapis.com",
    "secretmanager.googleapis.com",
    "artifactregistry.googleapis.com"
  ]
}

resource "google_project_service" "enabled_apis" {
  for_each           = toset(local.services)
  project            = var.project_id
  service            = each.key
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "easm" {
  location      = var.region
  repository_id = "easm-services"
  description   = "Docker repository for EASM microservices"
  format        = "DOCKER"
  depends_on    = [google_project_service.enabled_apis]
}


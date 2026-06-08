variable "project_id" {
  description = "The GCP Project ID"
  type        = string
  default     = "scyra-agents-495519"
}

variable "region" {
  description = "The GCP Region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The GCP Zone"
  type        = string
  default     = "us-central1-a"
}

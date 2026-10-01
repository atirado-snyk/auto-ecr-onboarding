# Test infrastructure for the e2e harness: the ECR repository the product connects Snyk to.
# Created by `e2e.sh infra-up` and destroyed by `e2e.sh infra-down`. Not part of the product.

terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "region" {
  type    = string
  default = "ap-southeast-2"
}

variable "repository_name" {
  type    = string
  default = "snyk-e2e/app"
}

provider "aws" {
  region = var.region
}

resource "aws_ecr_repository" "test" {
  name = var.repository_name
  # Test fixture choices (Snyk IaC flags these as low): tags stay mutable because the harness re-pushes
  # `latest`, and the default AES256 encryption is enough for a throwaway repo. Use IMMUTABLE tags
  # and a customer-managed KMS key for real registries.
  image_tag_mutability = "MUTABLE"
  force_delete         = true # infra-down removes the repo even with images in it

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    managed-by = "terraform"
    purpose    = "snyk-ecr-onboarding-e2e-fixture"
  }
}

output "repository_url" {
  value = aws_ecr_repository.test.repository_url
}

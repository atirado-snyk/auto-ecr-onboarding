# Test infrastructure for the e2e harness: the ECR repositories the product connects Snyk to, one in each
# of two regions of the same account (the "another region in the same account" scenarios).
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

variable "region_a" {
  type    = string
  default = "ap-southeast-2"
}

variable "region_b" {
  type    = string
  default = "us-east-1"
}

variable "repository_name" {
  type    = string
  default = "snyk-e2e/app"
}

provider "aws" {
  region = var.region_a
}

provider "aws" {
  alias  = "b"
  region = var.region_b
}

# Test fixture choices (Snyk IaC flags these as low): tags stay mutable because the harness re-pushes
# `latest`, and the default AES256 encryption is enough for a throwaway repo. Use IMMUTABLE tags
# and a customer-managed KMS key for real registries.
resource "aws_ecr_repository" "a" {
  name                 = var.repository_name
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

resource "aws_ecr_repository" "b" {
  provider             = aws.b
  name                 = var.repository_name
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    managed-by = "terraform"
    purpose    = "snyk-ecr-onboarding-e2e-fixture"
  }
}

output "repository_url_a" {
  value = aws_ecr_repository.a.repository_url
}

output "repository_url_b" {
  value = aws_ecr_repository.b.repository_url
}

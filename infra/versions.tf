# Terraform >= 1.5 for the simplified required_provider blocks and
# precondition support. AWS provider v5 is the current stable major.
# Archive bundles the Python sources into deployable lambda zips.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  # Production runs should pin state remotely:
  #   backend "s3" {
  #     bucket         = "your-tfstate-bucket"
  #     key            = "cloud-incident-response/terraform.tfstate"
  #     region         = "eu-west-1"
  #     dynamodb_table = "tfstate-lock"
  #     encrypt        = true
  #   }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.tags
  }
}

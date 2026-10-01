output "role_arn" {
  description = "ARN to pass to the Snyk ECR integration (scripts/onboard_ecr.py --role-arn)."
  value       = aws_iam_role.snyk_ecr_read.arn
}

output "role_name" {
  description = "Name of the IAM role."
  value       = aws_iam_role.snyk_ecr_read.name
}

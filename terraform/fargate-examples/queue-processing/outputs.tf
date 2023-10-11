output "service_task_security_group_arn" {
  description = "The ARN of the security group"
  value       = module.service_task_security_group.security_group_arn
}

output "service_task_security_group_id" {
  description = "The ID of the security group"
  value       = module.service_task_security_group.security_group_id
}

output "container_image_ecr_url" {
  value       = module.container_image_ecr.repository_url
  description = "container_image_ecr_url"
}

output "container_image_ecr_arn" {
  value       = module.container_image_ecr.repository_arn
  description = "container_image_ecr_arn"
}

output "aws_ecs_task_definition_arn" {
  value       = aws_ecs_task_definition.this.arn
  description = "aws_ecs_task_definition_arn"
}

output "aws_ecs_task_definition_family" {
  value       = aws_ecs_task_definition.this.family
  description = "aws_ecs_task_definition_family"
}

output "aws_cloudwatch_log_group" {
  value       = aws_cloudwatch_log_group.this.arn
  description = "aws_cloudwatch_log_group"
}

output "lambda_function_arn" {
  value       = module.lambda_function.lambda_function_arn
  description = "lambda_function_arn"
}

output "aws_cloudwatch_event_rule" {
  value       = aws_cloudwatch_event_rule.fargate_scaling.arn
  description = "aws_cloudwatch_event_rule"
}

 
output "source_s3_bucket_id" {
  value       = module.source_s3_bucket.s3_bucket_id
  description = "Source S3 Bucket Id for data pipeline processing"
}

output "source_s3_bucket_arn" {
  value       = module.source_s3_bucket.s3_bucket_arn
  description = "Source S3 Bucket ARN for data pipeline processing"
}


output "destination_s3_bucket_id" {
  value       = module.destination_s3_bucket.s3_bucket_id
  description = "Destination S3 Bucket Id for processed files"
}

output "destination_s3_bucket_arn" {
  value       = module.destination_s3_bucket.s3_bucket_arn
  description = "Destination S3 Bucket ARN for processed files"
}


output "processing_queue_id" {
  value       = module.processing_queue.this_sqs_queue_id 
  description = "SQS processing_queue_id"
}


output "processing_queue_arn" {
  value       = module.processing_queue.this_sqs_queue_arn 
  description = "SQS processing_queue_arn"
}


output "aws_ssm_parameter_ecs_pipeline_enabled" {
  value       = aws_ssm_parameter.ecs_pipeline_enabled.arn
  description = "aws_ssm_parameter_ecs_pipeline_enabled"
}

output "aws_ssm_parameter_ecs_pipeline_max_tasks" {
  value       = aws_ssm_parameter.ecs_pipeline_max_tasks.arn
  description = "aws_ssm_parameter_ecs_pipeline_max_tasks"
}

output "codepipeline_s3_bucket_id" {
  value       = module.codepipeline_s3_bucket.s3_bucket_id
  description = "codepipeline S3 Bucket Id "
}

output "codepipeline_s3_bucket_arn" {
  value       = module.codepipeline_s3_bucket.s3_bucket_arn
  description = "codepipeline S3 Bucket ARN"
}

output "aws_sns_topic" {
  value       = aws_sns_topic.codestar_notification.arn
  description = "aws_sns_topic"
}

output "codebuild_ci_project_id" {
  value       = module.codebuild_ci.project_id
  description = "codebuild_ci_project_id"
}

output "codebuild_ci_project_arn" {
  value       = module.codebuild_ci.project_arn
  description = "codebuild_ci_project_arn"
}

output "task_aws_iam_role" {
  value       = aws_iam_role.task.arn
  description = "aws_iam_role for task"
}

output "secret_id" {
  value       = data.aws_secretsmanager_secret.github_token.id
  description = "secret_id"
}

output "cluster_name" {
  value       = data.aws_ecs_cluster.core_infra.cluster_name
  description = "cluster_name"
}

output "ecs_service_definition_id" {
  value       = module.ecs_service_definition.id
  description = "ecs_service_definition_id"
}

output "ecs_service_definition_name" {
  value       = module.ecs_service_definition.name
  description = "ecs_service_definition_name"
}

output "autoscaling_policies" {
  value       = module.ecs_service_definition.autoscaling_policies
  description = "autoscaling_policies"
}





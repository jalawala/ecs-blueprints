variable "repository_owner" {
  description = "The name of the owner of the Github repository"
  type        = string
  default     = "jalawala"
}

variable "repository_name" {
  description = "The name of the Github repository"
  type        = string
  default     = "ecs-blueprints"
}

variable "repository_branch" {
  description = "The name of branch the Github repository, which is going to trigger a new CodePipeline excecution"
  type        = string
  default     = "main"
}

variable "github_token_secret_name" {
  description = "The name of branch the Github repository, which is going to trigger a new CodePipeline excecution"
  type        = string
  default     = "ecs-github-token"
}

variable "aws_region" {
  description = "AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "appMetricName" {
  description = "appMetricName"
  type        = string
  default     = "MsgProcessingDuration"
}

variable "bpiMetricName" {
  description = "bpiMetricName"
  type        = string
  default     = "ecsTargetBPI"
}


variable "metricType" {
  description = "metricType"
  type        = string
  default     = "Single-Queue"
}

variable "metricNamespace" {
  description = "metricNamespace"
  type        = string
  default     = "ECS-SQS-BPI"
}

variable "ecsServiceName" {
  description = "ecsServiceName"
  type        = string
  default     = "ecsdemo-queue-proc"
}

variable "containerName" {
  description = "containerName"
  type        = string
  default     = "ecsdemo-queue-proc"
}

variable "scaling_policy_name" {
  description = "scaling_policy_name"
  type        = string
  default     = "ecs_sqs_scaling"
}



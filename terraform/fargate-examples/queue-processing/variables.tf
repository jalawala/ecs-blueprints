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
locals {

  name   = "ecsdemo-queue-proc"
  region = var.aws_region

  container_name = "ecsdemo-queue-proc"

  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/aws-ia/ecs-blueprints"
  }
}

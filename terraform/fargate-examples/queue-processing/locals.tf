locals {

  name   = var.ecsServiceName
  region = var.aws_region
  appMetricName = var.appMetricName
  bpiMetricName = var.bpiMetricName
  metricType = var.metricType
  metricNamespace = var.metricNamespace
  container_name = var.containerName

  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/aws-ia/ecs-blueprints"
  }
}

locals {

  name   = var.ecsServiceName
  region = var.aws_region
  scaling_policy_name = var.scaling_policy_name
  appMetricName = var.appMetricName
  bpiMetricName = var.bpiMetricName
  metricType = var.metricType
  metricNamespace = var.metricNamespace
  container_name = var.containerName
  ecsServiceName = var.ecsServiceName
  ecsServiceName1 = "${var.ecsServiceName}-1"
  ecsServiceName2 = "${var.ecsServiceName}-2"

  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/aws-ia/ecs-blueprints"
  }
}

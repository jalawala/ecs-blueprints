provider "aws" {
  region = local.region
}

data "aws_caller_identity" "current" {}

################################################################################
# ECS Blueprint
################################################################################

module "service_task_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "~> 4.0"

  name        = "${local.name}-task-sg"
  description = "Security group for task"
  vpc_id      = data.aws_vpc.vpc.id

  ingress_cidr_blocks = [data.aws_vpc.vpc.cidr_block]
  egress_rules        = ["all-all"]

  tags = local.tags
}

module "container_image_ecr" {
  source  = "terraform-aws-modules/ecr/aws"
  version = "~> 1.4"

  repository_name = local.ecsServiceName1

  repository_force_delete           = true
  create_lifecycle_policy           = false
  repository_read_access_arns       = [one(data.aws_iam_roles.ecs_core_infra_exec_role.arns)]
  repository_read_write_access_arns = [module.codepipeline_ci_cd.codepipeline_role_arn]

  tags = local.tags
}

resource "aws_ecs_task_definition" "this" {
  family                   = local.ecsServiceName1
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 256
  memory                   = 512
  task_role_arn            = aws_iam_role.task.arn
  execution_role_arn       = one(data.aws_iam_roles.ecs_core_infra_exec_role.arns)
  container_definitions = jsonencode([
    {
      name  = local.ecsServiceName1
      image = module.container_image_ecr.repository_url
      environment = [
        {
          name  = "ProcessingQueueName",
          value = module.processing_queue.this_sqs_queue_name
        },
        {
          name  = "appMetricName",
          value = local.appMetricName
        },
                {
          name  = "metricType",
          value = local.metricType
        },
        {
          name  = "metricNamespace",
          value = local.metricNamespace
        },
                
      ]      
      logConfiguration = {
        "logDriver" : "awslogs",
        "options" : {
          "awslogs-region" : local.region,
          "awslogs-group" : aws_cloudwatch_log_group.this.name,
          "awslogs-stream-prefix" : "ecs"
        }
      }
    }
  ])

  lifecycle {
    ignore_changes = [container_definitions]
  }

  tags = local.tags
}

module "ecs_service_definition" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.2.2"

  deployment_controller = "ECS"

  name               = local.name
  desired_count      = 1
  cluster_arn        = data.aws_ecs_cluster.core_infra.arn
  enable_autoscaling = false

  subnet_ids = data.aws_subnets.private.ids
    security_group_rules = {
    egress_all = {
      type        = "egress"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
 
  # Task Definition
  create_iam_role        = false
  create_task_definition = false
  task_definition_arn = aws_ecs_task_definition.this.arn
  #task_definition_arn = "arn:aws:ecs:us-east-1:000474600478:task-definition/ecsdemo-queue-proc:11"
  
  enable_execute_command = true
  
  #ignore_task_definition_changes = false

  tags = local.tags
}

module "ecs_service_definition_2" {
  source  = "terraform-aws-modules/ecs/aws//modules/service"
  version = "~> 5.2.2"

  deployment_controller = "ECS"

  name               = local.ecsServiceName2
  desired_count      = 1
  cluster_arn        = data.aws_ecs_cluster.core_infra.arn
  enable_autoscaling = false

  subnet_ids = data.aws_subnets.private.ids
    security_group_rules = {
    egress_all = {
      type        = "egress"
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  # service_connect_configuration = {
  #   enabled = false
  #   service = {
  #     client_alias = [{
  #       port     = local.container_port
  #       dns_name = local.container_name
  #     }],
  #     port_name      = "${local.container_name}-${local.container_port}"
  #     discovery_name = local.container_name
  #   }
  # }

  # Task Definition
  
  create_iam_role        = false
  tasks_iam_role_arn     =  aws_iam_role.task.arn
  task_exec_iam_role_arn = one(data.aws_iam_roles.ecs_core_infra_exec_role.arns)
  enable_execute_command = true

  container_definitions = {
    main_container = {
      name  = local.ecsServiceName2     
      image = "${module.container_image_ecr.repository_url}:4332f79"
      
      environment = [
        {
          name  = "ProcessingQueueName",
          value = module.processing_queue.this_sqs_queue_name
        },
        {
          name  = "appMetricName",
          value = local.appMetricName
        },
                {
          name  = "metricType",
          value = local.metricType
        },
        {
          name  = "metricNamespace",
          value = local.metricNamespace
        },        
      ]
      
      enable_cloudwatch_logging = true
      log_configuration = {
        logDriver = "awslogs"
        options = {
          awslogs-group = aws_cloudwatch_log_group.this.name
          awslogs-stream-prefix = "ecs"
          awslogs-region = local.region
        }
      }      

    }
  }

  ignore_task_definition_changes = false

  tags = local.tags
}

resource "aws_appautoscaling_target" "ecs_target" {
  max_capacity       = 10
  min_capacity       = 1
  resource_id        = "service/${data.aws_ecs_cluster.core_infra.cluster_name}/${module.ecs_service_definition.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "ecs_sqs_app_scaling_policy" {
  name               = local.scaling_policy_name
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_target.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_target.service_namespace

  target_tracking_scaling_policy_configuration {
    target_value = 12
    scale_out_cooldown = 150
    scale_in_cooldown  = 0
    
    customized_metric_specification {
      #metric_name = "BPI"
      #namespace   = "ECS-SQS-BPI"
      #statistic = "Average"
      
      metrics {
        label = "Get the queue size (the number of messages waiting to be processed)"
        id    = "m1"

        metric_stat {
          metric {
            metric_name = "ApproximateNumberOfMessagesVisible"
            namespace   = "AWS/SQS"

            dimensions {
              name  = "QueueName"
              value = module.processing_queue.this_sqs_queue_name
            }
          }

          stat = "Sum"
        }

        return_data = false
      }

      metrics {
        label = "Get the ECS running task count (the number of currently running tasks)"
        id    = "m2"

        metric_stat {
          metric {
            metric_name = "RunningTaskCount"
            namespace   = "ECS/ContainerInsights"

            dimensions {
              name  = "ClusterName"
              value = data.aws_ecs_cluster.core_infra.cluster_name
            }

            dimensions {
              name  = "ServiceName"
              value = module.ecs_service_definition.name
            }
          }

          stat = "Average"
        }

        return_data = false
      }

      metrics {
        label       = "Calculate the backlog per instance"
        id          = "e1"
        expression  = "m1 / m2"
        return_data = true
      }
    }
  }
}


resource "aws_cloudwatch_log_group" "this" {
  name              = "/ecs/${local.name}"
  retention_in_days = 30

  tags = local.tags
}

################################################################################
# Lambda Function ECS scaling trigger
################################################################################

module "lambda_function_message_producer" {
  source = "terraform-aws-modules/lambda/aws"

  function_name      = "${local.name}-message-producer"
  description        = "This function can be used to send test messages to the processing queue and trigger ASG scaling events."
  handler            = "lambda_function.lambda_handler"
  runtime            = "python3.9"
  publish            = true
  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.lambda_role.json
  source_path        = "../../../application-code/message-producer/"

  environment_variables = {
    queueName      = module.processing_queue.this_sqs_queue_name
    defaultMsgProcDuration =  25
    nMessages = 300
  }
  
  cloudwatch_logs_retention_in_days = 30

  tags = local.tags
}

module "lambda_function_target_bpi_update" {
  source = "terraform-aws-modules/lambda/aws"

  function_name      = "${local.name}-target_bpi_update"
  description        = "This function regularly updates the target BPI of the ECS"
  handler            = "lambda_function.lambda_handler"
  runtime            = "python3.9"
  publish            = true
  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.lambda_role.json
  source_path        = "../../../application-code/ecs-target-setter/"

  environment_variables = {
    scaling_policy_name = local.scaling_policy_name
    queueName      = module.processing_queue.this_sqs_queue_name
    appMetricName = local.appMetricName
    metricType = local.metricType
    metricNamespace = local.metricNamespace
    bpiMetricName = local.bpiMetricName
    defaultMsgProcDuration =  25
    nMessages = 300
  }
  
  allowed_triggers = {
    PollSSMScale = {
      principal  = "events.amazonaws.com"
      source_arn = aws_cloudwatch_event_rule.fargate_scaling.arn
    }
  }
  
  cloudwatch_logs_retention_in_days = 30

  tags = local.tags
}

################################################################################
# Cloudwatch Events (EventBridge)
################################################################################

resource "aws_cloudwatch_event_rule" "fargate_scaling" {
  name                = "ECSTaskTriggerScheduler"
  description         = "This rule is used for update ECS Autoscaling Target BPI"
  schedule_expression = "rate(10 minutes)"

  tags = local.tags
}

resource "aws_cloudwatch_event_target" "ecs_fargate_lambda_function" {
  rule = aws_cloudwatch_event_rule.fargate_scaling.name
  arn  = module.lambda_function_target_bpi_update.lambda_function_arn
}

################################################################################
# SQS Queue
################################################################################


module "processing_queue" {
  source  = "terraform-aws-modules/sqs/aws"
  version = "~> 2.0"

  name = "${local.name}-processing-queue.fifo"
  fifo_queue = true
  content_based_deduplication = true
  
  tags = local.tags
}

################################################################################
# CodePipeline
################################################################################

module "codepipeline_s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~> 3.0"

  bucket = "codepipeline-${local.region}-${random_id.this.hex}"

  # For example only - please re-evaluate for your environment
  force_destroy = true

  attach_deny_insecure_transport_policy = true
  attach_require_latest_tls_policy      = true

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = local.tags
}

resource "aws_sns_topic" "codestar_notification" {
  name = local.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "WriteAccess"
        Effect   = "Allow"
        Action   = "sns:Publish"
        Resource = "arn:aws:sns:${local.region}:${data.aws_caller_identity.current.account_id}:${local.name}"
        Principal = {
          Service = "codestar-notifications.amazonaws.com"
        }
      },
    ]
  })

  tags = local.tags
}

module "codebuild_ci" {
  source = "../../modules/codebuild"

  name           = "codebuild-${local.name}"
  service_role   = module.codebuild_ci.codebuild_role_arn
  buildspec_path = "./application-code/container-queue-proc/templates/buildspec.yml"
  s3_bucket      = module.codepipeline_s3_bucket

  environment = {
    privileged_mode = true
    environment_variables = [
      {
        name  = "REPO_URL"
        value = module.container_image_ecr.repository_url
        }, {
        name  = "TASK_DEFINITION_FAMILY"
        value = aws_ecs_task_definition.this.family
        }, {
        name  = "CONTAINER_NAME"
        value = local.ecsServiceName1
        }, {
        name  = "FOLDER_PATH"
        value = "./application-code/container-queue-proc/."
        },
    ]
  }

  create_iam_role = true
  iam_role_name   = "${local.name}-codebuild-${random_id.this.hex}"
  ecr_repository  = module.container_image_ecr.repository_arn

  tags = local.tags
}

module "codepipeline_ci_cd" {
  source = "../../modules/codepipeline"

  name         = "pipeline-${local.name}"
  service_role = module.codepipeline_ci_cd.codepipeline_role_arn
  s3_bucket    = module.codepipeline_s3_bucket
  sns_topic    = aws_sns_topic.codestar_notification.arn

  stage = [{
    name = "Source"
    action = [{
      name             = "Source"
      category         = "Source"
      owner            = "ThirdParty"
      provider         = "GitHub"
      version          = "1"
      input_artifacts  = []
      output_artifacts = ["SourceArtifact"]
      configuration = {
        OAuthToken           = data.aws_secretsmanager_secret_version.github_token.secret_string
        Owner                = var.repository_owner
        Repo                 = var.repository_name
        Branch               = var.repository_branch
        PollForSourceChanges = true
      }
    }],
    }, {
    name = "Build"
    action = [{
      name             = "Build_app"
      category         = "Build"
      owner            = "AWS"
      provider         = "CodeBuild"
      version          = "1"
      input_artifacts  = ["SourceArtifact"]
      output_artifacts = ["BuildArtifact_app"]
      configuration = {
        ProjectName = module.codebuild_ci.project_id
      }
    }],
  }
, {
    name = "Deploy"
    action = [{
      name             = "Deploy_app"
      category         = "Deploy"
      owner            = "AWS"
      provider         = "ECS"
      version          = "1"
      input_artifacts  = ["BuildArtifact_app"]
      configuration = {
        ClusterName = data.aws_ecs_cluster.core_infra.cluster_name
        ServiceName = module.ecs_service_definition.name
        FileName    = "imagedefinitions.json"
      }

    }],
  }
  
  ]

  create_iam_role = true
  iam_role_name   = "${local.name}-pipeline-${random_id.this.hex}"

  tags = local.tags
}

################################################################################
# Task and Lambda Roles
################################################################################

resource "aws_iam_role" "task" {
  name               = "${local.name}-task"
  assume_role_policy = data.aws_iam_policy_document.task.json
  managed_policy_arns = ["arn:aws:iam::aws:policy/CloudWatchFullAccess"]
  
  tags = local.tags
}



data "aws_iam_policy_document" "task" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy" "task" {
  name   = "${local.name}-task"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_role.json
}

data "aws_iam_policy_document" "task_role" {

  statement {
    sid       = "IAMPassRole"
    actions   = ["iam:PassRole"]
    resources = ["*"]
  }
  statement {
    sid = "SQSReadWrite"
    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:ChangeMessageVisibilityBatch",
      "sqs:SendMessage",
      "sqs:DeleteMessage",
      "sqs:DeleteMessageBatch",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage"
    ]
    resources = [module.processing_queue.this_sqs_queue_arn]
  }
  statement {
    sid = "SSMRead"
    actions = [
      "ssm:GetParameters",
      "ssm:DescribeParameters"
    ]
    resources = [
      "arn:aws:ssm:${local.region}:${data.aws_caller_identity.current.account_id}:parameter",
      "arn:aws:ssm:${local.region}:${data.aws_caller_identity.current.account_id}:parameter/*",
    ]
  }
}

data "aws_iam_policy_document" "lambda_role" {

  statement {
    sid       = "IAMPassRole"
    actions   = ["iam:PassRole"]
    resources = ["*"]
  }
  statement {
    sid = "SQSReadWrite"
    actions = [
      "sqs:ChangeMessageVisibility",
      "sqs:ChangeMessageVisibilityBatch",
      "sqs:SendMessage",
      "sqs:DeleteMessage",
      "sqs:DeleteMessageBatch",
      "sqs:GetQueueAttributes",
      "sqs:GetQueueUrl",
      "sqs:ReceiveMessage"
    ]
    resources = [module.processing_queue.this_sqs_queue_arn]

  }
  statement {
    sid = "ECSTaskReadWrite"
    actions = [
      "ecs:Describe*",
      "ecs:List*",
      "ecs:DescribeTasks",
      "ecs:ListTasks",
      "ecs:StartTask",
      "ecs:RunTask"
    ]
    resources = ["*"]
  }
  statement {
    sid = "SSMRead"
    actions = [
      "ssm:GetParameters",
      "ssm:DescribeParameters"
    ]
    resources = [
      "arn:aws:ssm:${local.region}:${data.aws_caller_identity.current.account_id}:parameter",
      "arn:aws:ssm:${local.region}:${data.aws_caller_identity.current.account_id}:parameter/*",
    ]
  }
}

################################################################################
# Supporting Resources
################################################################################

resource "random_id" "this" {
  byte_length = "2"
}

data "aws_secretsmanager_secret" "github_token" {
  name = var.github_token_secret_name
}

data "aws_secretsmanager_secret_version" "github_token" {
  secret_id = data.aws_secretsmanager_secret.github_token.id
}

data "aws_vpc" "vpc" {
  filter {
    name   = "tag:Name"
    values = ["core-infra"]
  }
}

data "aws_subnets" "private" {
  filter {
    name   = "tag:Name"
    values = ["core-infra-private-*"]
  }
}

data "aws_ecs_cluster" "core_infra" {
  cluster_name = "core-infra"
}

data "aws_iam_roles" "ecs_core_infra_exec_role" {
  name_regex = "core-infra-*"
}

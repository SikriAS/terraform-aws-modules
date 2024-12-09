/*
 * = Logging
 */
resource "aws_cloudwatch_log_group" "main" {
  name              = var.application_name
  retention_in_days = var.log_retention_in_days
  tags              = var.tags
}

/*
 * = IAM
 *
 * Various permissions needed for the module to function
 */

data "aws_iam_policy_document" "task_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

/*
 * == Task execution role
 *
 * This allows the task to pull from ECR, etc
 */
resource "aws_iam_role" "execution" {
  name               = "${var.application_name}-task-execution-role"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

resource "aws_iam_role_policy" "task_execution" {
  name   = "${var.application_name}-task-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.task_execution_permissions.json
}

data "aws_iam_policy_document" "task_execution_permissions" {
  statement {
    effect = "Allow"

    resources = [
      "*",
    ]

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
  }
}

/*
 * == Task Role
 *
 * Gives the actual containers the permissions they need
 */
resource "aws_iam_role" "task" {
  name               = "${var.application_name}-task-role"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

resource "aws_iam_role_policy" "ecs_task_logs" {
  name   = "${var.application_name}-log-permissions"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.ecs_task_logs.json
}

data "aws_iam_policy_document" "ecs_task_logs" {
  statement {
    effect = "Allow"

    resources = [
      aws_cloudwatch_log_group.main.arn,
    ]

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
  }
}



resource "aws_iam_role_policy" "ssm_messages_for_local_access" {
  count = var.enable_execute_command ? 1 : 0

  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.ssm_messages_for_local_access.json
}

data "aws_iam_policy_document" "ssm_messages_for_local_access" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "ssmmessages:OpenDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:CreateControlChannel"
    ]
  }
}

/*
 * = Networking
 *
 * Various networking components for the services
 */

/*
 * == Security Groups
 */
resource "aws_security_group" "ecs_service" {
  count = var.launch_type == "EXTERNAL" ? 0 : 1

  vpc_id      = var.vpc_id
  name        = "${var.application_name}-ecs-service-sg"
  description = "Fargate service security group"
  tags = merge(
    var.tags,
    { Name = "${var.application_name}-sg" }
  )
}

resource "aws_security_group_rule" "loadbalancer" {
  for_each = (var.launch_type == "EXTERNAL"
    ? {}
    : { for lb in var.lb_listeners : lb.listener_arn => lb.security_group_id }
  )

  security_group_id = aws_security_group.ecs_service[0].id

  type      = "ingress"
  protocol  = "tcp"
  from_port = var.application_container.port
  to_port   = var.application_container.port

  source_security_group_id = each.value
}

resource "aws_security_group_rule" "loadbalancer_to_service" {
  for_each = (var.launch_type == "EXTERNAL"
    ? {}
    : { for lb in var.lb_listeners : lb.listener_arn => lb.security_group_id }
  )

  security_group_id = each.value

  type      = "egress"
  protocol  = "tcp"
  from_port = var.application_container.port
  to_port   = var.application_container.port

  source_security_group_id = aws_security_group.ecs_service[0].id
}

resource "aws_security_group_rule" "egress_service" {
  count = var.launch_type == "EXTERNAL" ? 0 : 1

  security_group_id = aws_security_group.ecs_service[0].id
  type              = "egress"
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

/*
 * == Load Balancer
 *
 * Setup load balancing with an existing loadbalancer.
 */
resource "aws_lb_target_group" "service" {
  for_each = { for idx, value in var.lb_listeners : idx => value }

  vpc_id = var.vpc_id

  target_type = "ip"
  port        = var.application_container.port
  protocol    = var.application_container.protocol

  deregistration_delay = var.lb_deregistration_delay

  dynamic "health_check" {
    for_each = [var.lb_health_check]

    content {
      enabled             = lookup(health_check.value, "enabled", null)
      healthy_threshold   = lookup(health_check.value, "healthy_threshold", null)
      interval            = lookup(health_check.value, "interval", null)
      matcher             = lookup(health_check.value, "matcher", null)
      path                = lookup(health_check.value, "path", null)
      port                = lookup(health_check.value, "port", null)
      protocol            = lookup(health_check.value, "protocol", null)
      timeout             = lookup(health_check.value, "timeout", null)
      unhealthy_threshold = lookup(health_check.value, "unhealthy_threshold", null)
    }
  }

  dynamic "stickiness" {
    for_each = var.lb_stickiness[*]
    content {
      type            = var.lb_stickiness.type
      enabled         = var.lb_stickiness.enabled
      cookie_duration = var.lb_stickiness.cookie_duration
      cookie_name     = var.lb_stickiness.cookie_name
    }
  }

  # NOTE: TF is unable to destroy a target group while a listener is attached,
  # therefor we have to create a new one before destroying the old. This also means
  # we have to let it have a random name, and then tag it with the desired name.
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    var.tags,
    { Name = "${var.application_name}-target-${var.application_container.port}-${each.key}" }
  )
}

resource "aws_lb_listener_rule" "service" {
  for_each = { for idx, value in var.lb_listeners : idx => value }

  listener_arn = each.value.listener_arn


  # forward blocks require at least two target group blocks
  dynamic "action" {
    for_each = length(aws_lb_target_group.service) > 1 ? [1] : []
    content {
      type = "forward"
      forward {
        target_group {
          arn = aws_lb_target_group.service[each.key].arn
        }
        dynamic "stickiness" {
          for_each = var.lb_stickiness.enabled ? [1] : []
          content {
            enabled  = true
            duration = var.lb_stickiness.cookie_duration
          }
        }
      }
    }
  }

  # Use default forward type if only one target group is defined
  dynamic "action" {
    for_each = length(aws_lb_target_group.service) == 1 ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.service[each.key].arn
    }
  }

  dynamic "condition" {
    for_each = each.value.conditions

    content {
      dynamic "path_pattern" {
        for_each = condition.value.path_pattern != null ? [condition.value.path_pattern] : []
        content {
          values = [path_pattern.value]
        }
      }

      dynamic "host_header" {
        for_each = condition.value.host_header != null ? [condition.value.host_header] : []
        content {
          values = flatten([host_header.value]) # Accept both a string or a list
        }
      }

      dynamic "http_header" {
        for_each = condition.value.http_header != null ? [condition.value.http_header] : []
        content {
          http_header_name = http_header.value.name
          values           = http_header.value.values
        }
      }
    }
  }
}

/*
 * = ECS Service
 *
 * This is what users are here for
 */

locals {

  datadog_containers = var.datadog_agent == true ? [
    {
      name      = "datadog-agent",
      image     = "datadog/agent:latest",
      essential = true,

      environment = {
        ECS_FARGATE                                 = "true"
        DD_SITE                                     = "datadoghq.eu"
        DD_RUNTIME_SECURITY_CONFIG_ENABLED          = "true"
        DD_RUNTIME_SECURITY_CONFIG_EBPFLESS_ENABLED = "true"
        DD_API_KEY                                  = var.datadog_api_key

        DD_SERVICE                = var.application_name
        DD_TAGS                   = "team:samsvar"
        DD_APM_ENABLED            = "true"
        DD_APM_FILTER_TAGS_REJECT = "http.useragent:ELB-HealthChecker/2.0 user_agent:ELB-HealthChecker/2.0"
        # Reject anything ending in /health
        DD_APM_FILTER_TAGS_REGEX_REJECT = "http.url:.*\\/health$"

        DD_TRACE_REMOVE_INTEGRATION_SERVICE_NAMES_ENABLED = "true"
      }
      health_check = {
        command     = ["CMD-SHELL", "/probe.sh"]
        interval    = 30
        timeout     = 5
        retries     = 2
        startPeriod = 60
      }
    },
    {
      name      = "cws-instrumentation-init"
      image     = "datadog/cws-instrumentation:latest"
      essential = false
      user      = 0
      command = [
        "/cws-instrumentation",
        "setup",
        "--cws-volume-mount",
        "/cws-instrumentation-volume",
      ]
      extra_options = {
        mountPoints = [
          {
            sourceVolume  = "cws-instrumentation-volume"
            containerPath = "/cws-instrumentation-volume"
            readOnly      = false
          }
        ]
      }
    }
  ] : null
}


locals {
  # If datadog_agent is enabled, we need to add extra options to the application container
  application_container = var.datadog_agent == true ? merge(var.application_container,
    {
      extra_options = {
        dependsOn = [
          {
            containerName = "datadog-agent",
            condition     = "HEALTY"
          },
          {
            containerName = "cws-instrumentation-init",
            condition     = "SUCCESS"
          }
        ]
        mountPoints = [
          {
            sourceVolume  = "cws-instrumentation-volume",
            containerPath = "/cws-instrumentation-volume",
            readOnly      = true
          }
        ]
        linuxParameters = {
          capabilities = {
            add = ["SYS_PTRACE"]
          }
        }
      }
    }
  ) : var.application_container

  containers = [
    for container in concat([local.application_container], var.sidecar_containers, local.datadog_containers) : {
      name    = container.name
      image   = container.image
      command = try(container.command, null)
      # Only the application container is essential
      # Container names have to be unique, so this is guaranteed to be correct.
      essential         = try(container.essential, container.name == var.application_container.name)
      environment       = try(container.environment, {})
      secrets           = try(container.secrets, {})
      port              = try(container.port, null)
      network_protocol  = try(container.network_protocol, "tcp")
      health_check      = try(container.health_check, null)
      cpu               = try(container.cpu, null)
      memory_hard_limit = try(container.memory_hard_limit, null)
      memory_soft_limit = try(container.memory_soft_limit, null)
      extra_options     = try(container.extra_options, {})
    }
  ]

  capacity_provider_strategy = {
    capacity_provider = "FARGATE_SPOT"
    weight            = 1
  }
}

data "aws_region" "current" {}

# == Hack for terraform invisible strong typing
#
# This is a workaround for the fact that a variable can't have a ternary
# that returns two objects where the keys are different.
#
# To work around this we conditionally create a task with an AWS logger
# or a Datadog logger.

resource "aws_ecs_task_definition" "task" {
  count = var.datadog_agent == true ? 0 : 1

  family = var.application_name
  container_definitions = jsonencode([
    for container in local.containers : merge({
      name    = container.name
      image   = container.image
      command = container.command
      # Only the application container is essential
      # Container names have to be unique, so this is guaranteed to be correct.
      essential = container.essential
      environment = [
        for key, value in container.environment : {
          name  = key
          value = value
        }
      ]
      secrets = [
        for key, value in container.secrets : {
          name      = key
          valueFrom = value
        }
      ]
      portMappings = container.port == null ? [] : [
        {
          containerPort = tonumber(container.port)
          hostPort      = tonumber(container.port)
          protocol      = container.network_protocol
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group" : aws_cloudwatch_log_group.main.name,
          "awslogs-region" : data.aws_region.current.name,
          "awslogs-stream-prefix" : container.name
        }
      }
      healthCheck       = container.health_check
      cpu               = container.cpu
      memory            = container.memory_hard_limit
      memoryReservation = container.memory_soft_limit
    }, container.extra_options)
  ])

  execution_role_arn = aws_iam_role.execution.arn
  task_role_arn      = aws_iam_role.task.arn

  requires_compatibilities = [var.launch_type]
  cpu                      = var.cpu
  memory                   = var.memory
  # ECS Anywhere can't have "awsvpc" as the network mode
  network_mode = var.launch_type == "EXTERNAL" ? "bridge" : "awsvpc"
}

resource "aws_ecs_task_definition" "task_datadog" {
  count = var.datadog_agent == true ? 1 : 0

  family = var.application_name

  container_definitions = jsonencode([
    for container in local.containers : merge({
      name    = container.name
      image   = container.image
      command = container.command
      # Only the application container is essential
      # Container names have to be unique, so this is guaranteed to be correct.
      essential = container.essential
      environment = [
        for key, value in container.environment : {
          name  = key
          value = value
        }
      ]
      secrets = [
        for key, value in container.secrets : {
          name      = key
          valueFrom = value
        }
      ]
      portMappings = container.port == null ? [] : [
        {
          containerPort = tonumber(container.port)
          hostPort      = tonumber(container.port)
          protocol      = container.network_protocol
        }
      ]

      logConfiguration = {
        logDriver = "awsfirelens",
        options = {
          Name       = "datadog",
          Host       = "http-intake.logs.datadoghq.eu",
          compress   = "gzip",
          TLS        = "on"
          provider   = "ecs"
          dd_service = var.application_name,
          dd_tags    = "env:${var.environment},version:${split(":", var.application_container.image)[1]},team:samsvar",
        }
      }

      healthCheck       = container.health_check
      cpu               = container.cpu
      memory            = container.memory_hard_limit
      memoryReservation = container.memory_soft_limit
      dockerLabels = {
        "com.datadoghq.tags.service" = var.application_name
        "com.datadoghq.tags.env"     = var.environment
        "com.datadoghq.tags.version" = split(":", var.application_container.image)[1]
        "com.datadoghq.tags.team"    = "samsvar"
      }
    }, container.extra_options)
  ])

  execution_role_arn = aws_iam_role.execution.arn
  task_role_arn      = aws_iam_role.task.arn

  requires_compatibilities = [var.launch_type]
  cpu                      = var.cpu
  memory                   = var.memory
  network_mode             = "awsvpc"

  volume {
    name = "cws-instrumentation-volume"
  }
}

locals {
  task_definition = var.datadog_agent == true ? aws_ecs_task_definition.task_datadog[0].arn : aws_ecs_task_definition.task[0].arn
}

# == End of hack ==

# Service preconditions to ensure that the user doesn't try combinations we want to avoid.
resource "terraform_data" "no_launch_type_and_spot" {
  lifecycle {
    precondition {
      condition     = !var.use_spot || var.launch_type == "FARGATE"
      error_message = "use_spot and launch_type are mutually exclusive"
    }
  }
}

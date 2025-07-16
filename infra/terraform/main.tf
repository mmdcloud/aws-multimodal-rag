resource "random_id" "random" {
  byte_length = 8
}

# Source Bucket
module "source_bucket" {
  source             = "./modules/s3"
  bucket_name        = "source-bucket-${random_id.random.hex}"
  objects            = []
  versioning_enabled = "Enabled"
  bucket_notification = {
    queue = [
      {
        queue_arn = module.sqs.arn
        events    = ["s3:ObjectCreated:*"]
      }
    ]
    lambda_function = []
  }
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["PUT", "POST", "GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  force_destroy = true
}

# SQS
module "sqs" {
  source                        = "./modules/sqs"
  queue_name                    = "document-upload-queue"
  delay_seconds                 = 0
  maxReceiveCount               = 3
  dlq_message_retention_seconds = 86400
  dlq_name                      = "document-upload-dlq"
  max_message_size              = 262144
  message_retention_seconds     = 345600
  visibility_timeout_seconds    = 180
  receive_wait_time_seconds     = 20
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = "arn:aws:sqs:${var.region}:*:document-upload-queue"
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = module.source_bucket.arn
          }
        }
      }
    ]
  })
}

#  Lambda SQS event source mapping
resource "aws_lambda_event_source_mapping" "sqs_event_trigger" {
  event_source_arn                   = module.sqs.arn
  function_name                      = module.lambda_function.arn
  enabled                            = true
  batch_size                         = 10
  maximum_batching_window_in_seconds = 60
}

# Lambda function IAM Role
module "lambda_function_iam_role" {
  source             = "./modules/iam"
  role_name          = "lambda-function-iam-role"
  role_description   = "lambda-function-iam-role"
  policy_name        = "lambda-function-iam-policy"
  policy_description = "lambda-function-iam-policy"
  assume_role_policy = <<EOF
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "sts:AssumeRole",
                "Principal": {
                  "Service": "lambda.amazonaws.com"
                },
                "Effect": "Allow",
                "Sid": ""
            }
        ]
    }
    EOF
  policy             = <<EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*",
            "Effect": "Allow"
        },
        {
            "Action": [
                "s3:*",            
            ],
            "Effect"   : "Allow",
            "Resource" : [
                "${module.source_bucket.arn}"
                "${module.source_bucket.arn}/*"
            ]
        }      
      ]
    }
    EOF
}

module "lambda_function_code_bucket" {
  source      = "./modules/s3"
  bucket_name = "process-embeddin-function-src"
  objects = [
    {
      key    = "process_embedding.zip"
      source = "./files/process_embedding.zip"
    }
  ]
  bucket_policy = ""
  cors = [
    {
      allowed_headers = ["*"]
      allowed_methods = ["GET"]
      allowed_origins = ["*"]
      max_age_seconds = 3000
    }
  ]
  versioning_enabled = "Enabled"
  force_destroy      = false
}

# Lambda function to upload document embeddings into vector database
module "lambda_function" {
  source        = "./modules/lambda"
  function_name = "process-embeddings-function"
  role_arn      = module.lambda_function_iam_role.arn
  env_variables = {
    REGION              = var.region
    PINECONE_API_KEY    = ""
    PINECONE_ENV        = ""
    PINECONE_INDEX_NAME = ""
  }
  handler    = "main.lambda_handler"
  runtime    = "python3.12"
  s3_bucket  = module.lambda_function_code_bucket.bucket
  s3_key     = "process_embedding.zip"
  depends_on = [module.lambda_function_code_bucket]
}

# Cognito
module "cognito" {
  source                     = "./modules/cognito"
  name                       = "docrag-users"
  username_attributes        = ["email"]
  auto_verified_attributes   = ["email"]
  password_minimum_length    = 8
  password_require_lowercase = true
  password_require_numbers   = true
  password_require_symbols   = true
  password_require_uppercase = true
  schema = [
    {
      attribute_data_type = "String"
      name                = "email"
      required            = true
    }
  ]
  verification_message_template_default_email_option = "CONFIRM_WITH_CODE"
  verification_email_subject                         = "Verify your email for DocRag"
  verification_email_message                         = "Your verification code is {####}"
  user_pool_clients = [
    {
      name                                 = "docrag_client"
      generate_secret                      = false
      explicit_auth_flows                  = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
      allowed_oauth_flows_user_pool_client = true
      allowed_oauth_flows                  = ["code", "implicit"]
      allowed_oauth_scopes                 = ["email", "openid"]
      callback_urls                        = ["https://example.com/callback"]
      logout_urls                          = ["https://example.com/logout"]
      supported_identity_providers         = ["COGNITO"]
    }
  ]
}

# VPC Configuration
module "docrag_vpc" {
  source                = "./modules/vpc/vpc"
  vpc_name              = "docrag-vpc"
  vpc_cidr_block        = "10.0.0.0/16"
  enable_dns_hostnames  = true
  enable_dns_support    = true
  internet_gateway_name = "vpc_igw"
}

# Security Group
module "docrag_frontend_lb_sg" {
  source = "./modules/vpc/security_groups"
  vpc_id = module.docrag_vpc.vpc_id
  name   = "docrag_frontend_lb_sg"
  ingress = [
    {
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      self            = "false"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      description     = "HTTP traffic"
    },
    {
      from_port       = 443
      to_port         = 443
      protocol        = "tcp"
      self            = "false"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      description     = "HTTPS traffic"
    }
  ]
  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

module "docrag_backend_lb_sg" {
  source = "./modules/vpc/security_groups"
  vpc_id = module.docrag_vpc.vpc_id
  name   = "docrag_backend_lb_sg"
  ingress = [
    {
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      self            = "false"
      cidr_blocks     = ["0.0.0.0/0"]
      security_groups = []
      description     = "any"
    }
  ]
  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

module "docrag_ecs_frontend_sg" {
  source = "./modules/vpc/security_groups"
  vpc_id = module.docrag_vpc.vpc_id
  name   = "docrag_ecs_frontend_sg"
  ingress = [
    {
      from_port       = 3000
      to_port         = 3000
      protocol        = "tcp"
      self            = "false"
      cidr_blocks     = []
      security_groups = [module.docrag_frontend_lb_sg.id]
      description     = "any"
    }
  ]
  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

module "docrag_ecs_backend_sg" {
  source = "./modules/vpc/security_groups"
  vpc_id = module.docrag_vpc.vpc_id
  name   = "docrag_ecs_backend_sg"
  ingress = [
    {
      from_port       = 80
      to_port         = 80
      protocol        = "tcp"
      self            = "false"
      cidr_blocks     = []
      security_groups = [module.docrag_backend_lb_sg.id]
      description     = "any"
    }
  ]
  egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  ]
}

# Public Subnets
module "docrag_public_subnets" {
  source = "./modules/vpc/subnets"
  name   = "docrag-public-subnet"
  subnets = [
    {
      subnet = "10.0.1.0/24"
      az     = "us-east-1a"
    },
    {
      subnet = "10.0.2.0/24"
      az     = "us-east-1b"
    },
    {
      subnet = "10.0.3.0/24"
      az     = "us-east-1c"
    }
  ]
  vpc_id                  = module.docrag_vpc.vpc_id
  map_public_ip_on_launch = true
}

# Private Subnets
module "docrag_private_subnets" {
  source = "./modules/vpc/subnets"
  name   = "docrag-private-subnet"
  subnets = [
    {
      subnet = "10.0.6.0/24"
      az     = "us-east-1a"
    },
    {
      subnet = "10.0.5.0/24"
      az     = "us-east-1b"
    },
    {
      subnet = "10.0.4.0/24"
      az     = "us-east-1c"
    }
  ]
  vpc_id                  = module.docrag_vpc.vpc_id
  map_public_ip_on_launch = false
}

# Public Route Table
module "public_rt" {
  source  = "./modules/vpc/route_tables"
  name    = "docrag-public-route-table"
  subnets = module.docrag_public_subnets.subnets[*]
  routes = [
    {
      cidr_block = "0.0.0.0/0"
      gateway_id = module.docrag_vpc.igw_id
    }
  ]
  vpc_id = module.docrag_vpc.vpc_id
}

# Private Route Table
module "private_rt" {
  source  = "./modules/vpc/route_tables"
  name    = "docrag-private-route-table"
  subnets = module.docrag_private_subnets.subnets[*]
  routes  = []
  vpc_id  = module.docrag_vpc.vpc_id
}

# -----------------------------------------------------------------------------------------
# ECR Module
# -----------------------------------------------------------------------------------------

# 1. Frontend Repo
module "docrag_frontend_container_registry" {
  source               = "./modules/ecr"
  force_delete         = true
  scan_on_push         = false
  image_tag_mutability = "IMMUTABLE"
  bash_command         = "bash ${path.cwd}/../src/frontend/artifact_push.sh docrag_frontend ${var.region} http://${module.docrag_backend_lb.lb_dns_name}"
  name                 = "docrag_frontend"
}

# 2. Backend Repo
module "docrag_backend_container_registry" {
  source               = "./modules/ecr"
  force_delete         = true
  scan_on_push         = false
  image_tag_mutability = "IMMUTABLE"
  bash_command         = "bash ${path.cwd}/../src/backend/artifact_push.sh docrag_backend ${var.region}"
  name                 = "docrag_backend"
}

# -----------------------------------------------------------------------------------------
# Load Balancer Configuration
# -----------------------------------------------------------------------------------------

# Frontend Load Balancer
module "docrag_frontend_lb" {
  source                     = "./modules/load-balancer"
  lb_name                    = "docrag-frontend-lb"
  lb_is_internal             = false
  lb_ip_address_type         = "ipv4"
  load_balancer_type         = "application"
  drop_invalid_header_fields = true
  enable_deletion_protection = true
  security_groups            = [module.docrag_frontend_lb_sg.id]
  subnets                    = module.docrag_public_subnets.subnets[*].id
  target_groups = [
    {
      target_group_name      = "docrag-frontend-tg"
      target_port            = 3000
      target_ip_address_type = "ipv4"
      target_protocol        = "HTTP"
      target_type            = "ip"
      target_vpc_id          = module.docrag_vpc.vpc_id

      health_check_interval            = 30
      health_check_path                = "/auth/signin"
      health_check_enabled             = true
      health_check_protocol            = "HTTP"
      health_check_timeout             = 5
      health_check_healthy_threshold   = 3
      health_check_unhealthy_threshold = 3
      health_check_port                = 3000

    }
  ]
  listeners = [
    {
      listener_port     = 80
      listener_protocol = "HTTP"
      certificate_arn   = null
      default_actions = [
        {
          type             = "forward"
          target_group_arn = module.docrag_frontend_lb.target_groups[0].arn
        }
      ]
    }
  ]
}

# Backend Load Balancer
module "docrag_backend_lb" {
  source                     = "./modules/load-balancer"
  lb_name                    = "docrag-backend-lb"
  lb_is_internal             = false
  lb_ip_address_type         = "ipv4"
  load_balancer_type         = "application"
  enable_deletion_protection = true
  drop_invalid_header_fields = true
  security_groups            = [module.docrag_backend_lb_sg.id]
  subnets                    = module.docrag_public_subnets.subnets[*].id
  target_groups = [
    {
      target_group_name      = "docrag-backend-tg"
      target_port            = 80
      target_ip_address_type = "ipv4"
      target_protocol        = "HTTP"
      target_type            = "ip"
      target_vpc_id          = module.docrag_vpc.vpc_id

      health_check_interval            = 30
      health_check_path                = "/"
      health_check_enabled             = true
      health_check_protocol            = "HTTP"
      health_check_timeout             = 5
      health_check_healthy_threshold   = 3
      health_check_unhealthy_threshold = 3
      health_check_port                = 80
    }
  ]
  listeners = [
    {
      listener_port     = 80
      listener_protocol = "HTTP"
      certificate_arn   = null
      default_actions = [
        {
          type             = "forward"
          target_group_arn = module.docrag_backend_lb.target_groups[0].arn
        }
      ]
    }
  ]
}

# -----------------------------------------------------------------------------------------
# ECS Configuration
# -----------------------------------------------------------------------------------------
resource "aws_ecs_cluster" "docrag_cluster" {
  name = "docrag-cluster"
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# Cloudwatch log groups for ecs service logs
module "docrag_frontend_ecs_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/ecs/docrag_frontend"
  retention_in_days = 30
}

module "docrag_backend_ecs_log_group" {
  source            = "./modules/cloudwatch/cloudwatch-log-group"
  log_group_name    = "/ecs/docrag_backend"
  retention_in_days = 30
}

data "aws_iam_policy_document" "s3_put_object_policy_document" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "s3_put_policy" {
  name        = "s3_put_policy"
  description = "Policy for allowing PutObject action"
  policy      = data.aws_iam_policy_document.s3_put_object_policy_document.json
}

# ECR-ECS IAM Role
resource "aws_iam_role" "docrag_ecs_task_execution_role" {
  name               = "docrag-ecs-task-execution-role"
  assume_role_policy = <<EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
        "Effect": "Allow",
        "Principal": {
            "Service": "ecs-tasks.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
        }
    ]
    }
    EOF
}

# ECR-ECS policy attachment 
resource "aws_iam_role_policy_attachment" "docrag_ecs_task_execution_role_policy_attachment" {
  role       = aws_iam_role.docrag_ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# X-Ray tracing
resource "aws_iam_role_policy_attachment" "docrag_ecs_task_xray" {
  role       = aws_iam_role.docrag_ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

resource "aws_iam_role_policy_attachment" "s3_put_object_role_policy_attachment" {
  role       = aws_iam_role.docrag_ecs_task_execution_role.name
  policy_arn = aws_iam_policy.s3_put_policy.arn
}

# Frontend ECS Configuration
module "docrag_frontend_ecs" {
  source                                   = "./modules/ecs"
  task_definition_family                   = "docrag_frontend_task_definition"
  task_definition_requires_compatibilities = ["FARGATE"]
  task_definition_cpu                      = 2048
  task_definition_memory                   = 4096
  task_definition_execution_role_arn       = aws_iam_role.docrag_ecs_task_execution_role.arn
  task_definition_task_role_arn            = aws_iam_role.docrag_ecs_task_execution_role.arn
  task_definition_network_mode             = "awsvpc"
  task_definition_cpu_architecture         = "X86_64"
  task_definition_operating_system_family  = "LINUX"
  task_definition_container_definitions = jsonencode(
    [
      {
        "name" : "docrag_frontend",
        "image" : "${module.docrag_frontend_container_registry.repository_url}:latest",
        "cpu" : 1024,
        "memory" : 2048,
        "essential" : true,
        "healthCheck" : {
          "command" : ["CMD-SHELL", "curl -f http://localhost:3000/ || exit 1"],
          "interval" : 30,
          "timeout" : 5,
          "retries" : 3,
          "startPeriod" : 60
        },
        "ulimits" : [
          {
            "name" : "nofile",
            "softLimit" : 65536,
            "hardLimit" : 65536
          }
        ]
        "portMappings" : [
          {
            "containerPort" : 3000,
            "hostPort" : 3000,
            "name" : "docrag_frontend"
          }
        ],
        "logConfiguration" : {
          "logDriver" : "awslogs",
          "options" : {
            "awslogs-group" : "${module.docrag_frontend_ecs_log_group.name}",
            "awslogs-region" : "${var.region}",
            "awslogs-stream-prefix" : "ecs"
          }
        },
        environment = [
          {
            name  = "BASE_URL"
            value = "${module.docrag_backend_lb.lb_dns_name}"
          }
        ]
      },
      {
        "name" : "xray-daemon",
        "image" : "amazon/aws-xray-daemon",
        "cpu" : 32,
        "memoryReservation" : 256,
        "portMappings" : [
          {
            "containerPort" : 2000,
            "protocol" : "udp"
          }
        ]
      },
  ])

  service_name                = "docrag_frontend_ecs_service"
  service_cluster             = aws_ecs_cluster.docrag_cluster.id
  service_launch_type         = "FARGATE"
  service_scheduling_strategy = "REPLICA"
  service_desired_count       = 1

  deployment_controller_type = "ECS"
  load_balancer_config = [{
    container_name   = "docrag_frontend"
    container_port   = 3000
    target_group_arn = module.docrag_frontend_lb.target_groups[0].arn
  }]

  security_groups = [module.docrag_ecs_frontend_sg.id]
  subnets = [
    module.docrag_private_subnets.subnets[0].id,
    module.docrag_private_subnets.subnets[1].id,
    module.docrag_private_subnets.subnets[2].id
  ]
  assign_public_ip = false
}

# Backend ECS Configuration
module "docrag_backend_ecs" {
  source                                   = "./modules/ecs"
  task_definition_family                   = "docrag_backend_task_definition"
  task_definition_requires_compatibilities = ["FARGATE"]
  task_definition_cpu                      = 2048
  task_definition_memory                   = 4096
  task_definition_execution_role_arn       = aws_iam_role.docrag_ecs_task_execution_role.arn
  task_definition_task_role_arn            = aws_iam_role.docrag_ecs_task_execution_role.arn
  task_definition_network_mode             = "awsvpc"
  task_definition_cpu_architecture         = "X86_64"
  task_definition_operating_system_family  = "LINUX"
  task_definition_container_definitions = jsonencode(
    [
      {
        "name" : "docrag_backend",
        "image" : "${module.docrag_backend_container_registry.repository_url}:latest",
        "cpu" : 1024,
        "memory" : 2048,
        "essential" : true,
        "healthCheck" : {
          "command" : ["CMD-SHELL", "curl -f http://localhost:80 || exit 1"],
          "interval" : 30,
          "timeout" : 5,
          "retries" : 3,
          "startPeriod" : 60
        },
        "ulimits" : [
          {
            "name" : "nofile",
            "softLimit" : 65536,
            "hardLimit" : 65536
          }
        ]
        "portMappings" : [
          {
            "containerPort" : 80,
            "hostPort" : 80,
            "name" : "docrag_backend"
          }
        ],
        "logConfiguration" : {
          "logDriver" : "awslogs",
          "options" : {
            "awslogs-group" : "${module.docrag_backend_ecs_log_group.name}",
            "awslogs-region" : "${var.region}",
            "awslogs-stream-prefix" : "ecs"
          }
        },
        environment = []
      },
      {
        "name" : "xray-daemon",
        "image" : "amazon/aws-xray-daemon",
        "cpu" : 32,
        "memoryReservation" : 256,
        "portMappings" : [
          {
            "containerPort" : 2000,
            "protocol" : "udp"
          }
        ]
      }
  ])

  service_name                = "docrag_backend_ecs_service"
  service_cluster             = aws_ecs_cluster.docrag_cluster.id
  service_launch_type         = "FARGATE"
  service_scheduling_strategy = "REPLICA"
  service_desired_count       = 1

  deployment_controller_type = "ECS"
  load_balancer_config = [{
    container_name   = "docrag_backend"
    container_port   = 80
    target_group_arn = module.docrag_backend_lb.target_groups[0].arn
  }]

  security_groups = [module.docrag_ecs_backend_sg.id]
  subnets = [
    module.docrag_private_subnets.subnets[0].id,
    module.docrag_private_subnets.subnets[1].id,
    module.docrag_private_subnets.subnets[2].id
  ]
  assign_public_ip = false
}

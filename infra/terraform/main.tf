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
            "aws:SourceArn" = module.mediaconvert_source_bucket.arn
          }
        }
      }
    ]
  })
}

#  Lambda SQS event source mapping
resource "aws_lambda_event_source_mapping" "sqs_event_trigger" {
  event_source_arn                   = module.sqs.arn
  function_name                      = module.mediaconvert_lambda_function.arn
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
                "logs:PutLogEvents",
                "mediaconvert:*"
            ],
            "Resource": "arn:aws:logs:*:*:*",
            "Effect": "Allow"
        }      
      ]
    }
    EOF
}

# Lambda function to process media files
module "lambda_function" {
  source        = "./modules/lambda"
  function_name = "lambda-function"
  role_arn      = module.lambda_function_iam_role.arn
  env_variables = {
    REGION            = var.region
  }
  handler    = "lambda_function.lambda_handler"
  runtime    = "python3.12"
  s3_bucket  = module.lambda_function_code_bucket.bucket
  s3_key     = "lambda_function.zip"
  depends_on = [module.mediaconvert_function_code_bucket]
}

module "cognito" {
  source                     = "./modules/cognito"
  name                       = "mediaconvert-users"
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
  verification_email_subject                         = "Verify your email for MediaConvert"
  verification_email_message                         = "Your verification code is {####}"
  user_pool_clients = [
    {
      name                                 = "mediaconvert_client"
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
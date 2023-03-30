# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      hashicorp-learn = "lambda-api-gateway"
    }
  }

}

# read service user secret
data "aws_secretsmanager_secret" "capstone_creds" {
  arn = "arn:aws:secretsmanager:us-west-1:900510214286:secret:capstone-creds-yvkEMx"
}

data "aws_secretsmanager_secret_version" "capstone_creds" {
  secret_id = data.aws_secretsmanager_secret.capstone_creds.id
}

locals {
    capstone_creds=jsondecode(data.aws_secretsmanager_secret_version.capstone_creds.secret_string)
}

terraform {
    backend "s3" {
        bucket         = "sre-bootcamp-demenskan-tfstate"
        key            = "global/s3/terraform.tfstate"
        region         = "us-west-1"

        dynamodb_table = "sre-bootcamp-demenskan-locks"
        encrypt        = true
    }
}
resource "random_pet" "lambda_bucket_name" {
  prefix = "learn-terraform-functions"
  length = 4
}

resource "aws_s3_bucket" "lambda_bucket" {
  bucket = random_pet.lambda_bucket_name.id
}

resource "aws_s3_bucket_acl" "bucket_acl" {
  bucket = aws_s3_bucket.lambda_bucket.id
  acl    = "private"
}

data "archive_file" "lambda_hello_world" {
  type = "zip"
  source_dir  = "${path.module}/hello-world"
  output_path = "${path.module}/hello-world.zip"
}

data "archive_file" "lambda_cidr_to_mask" {
  type = "zip"
  source_dir  = "${path.module}/cidr-to-mask"
  output_path = "${path.module}/cidr-to-mask.zip"
}

data "archive_file" "lambda_mask_to_cidr" {
  type = "zip"
  source_dir  = "${path.module}/mask-to-cidr"
  output_path = "${path.module}/mask-to-cidr.zip"
}

data "archive_file" "lambda_login" {
  type = "zip"
  source_dir  = "${path.module}/login"
  output_path = "${path.module}/login.zip"
}

resource "aws_s3_object" "lambda_hello_world" {
  bucket = aws_s3_bucket.lambda_bucket.id
  key    = "hello-world.zip"
  source = data.archive_file.lambda_hello_world.output_path
  etag = filemd5(data.archive_file.lambda_hello_world.output_path)
}

resource "aws_s3_object" "lambda_cidr_to_mask" {
  bucket = aws_s3_bucket.lambda_bucket.id
  key    = "cidr-to-mask.zip"
  source = data.archive_file.lambda_cidr_to_mask.output_path
  etag = filemd5(data.archive_file.lambda_cidr_to_mask.output_path)
}

resource "aws_s3_object" "lambda_mask_to_cidr" {
  bucket = aws_s3_bucket.lambda_bucket.id
  key    = "mask-to-cidr.zip"
  source = data.archive_file.lambda_mask_to_cidr.output_path
  etag = filemd5(data.archive_file.lambda_mask_to_cidr.output_path)
}

resource "aws_s3_object" "lambda_login" {
  bucket = aws_s3_bucket.lambda_bucket.id
  key    = "login.zip"
  source = data.archive_file.lambda_login.output_path
  etag = filemd5(data.archive_file.lambda_login.output_path)
}

resource "aws_lambda_function" "hello_world" {
  function_name = "HelloWorld"
  s3_bucket = aws_s3_bucket.lambda_bucket.id
  s3_key    = aws_s3_object.lambda_hello_world.key
  runtime = "nodejs12.x"
  handler = "hello.handler"
  source_code_hash = data.archive_file.lambda_hello_world.output_base64sha256
  role = aws_iam_role.lambda_exec.arn
}

resource "aws_lambda_function" "cidr_to_mask" {
  function_name = "CidrToMask"
  s3_bucket = aws_s3_bucket.lambda_bucket.id
  s3_key    = aws_s3_object.lambda_cidr_to_mask.key
  runtime = "python3.9"
  handler = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_cidr_to_mask.output_base64sha256
  role = aws_iam_role.lambda_exec.arn
}

resource "aws_lambda_function" "mask_to_cidr" {
  function_name = "MaskToCidr"
  s3_bucket = aws_s3_bucket.lambda_bucket.id
  s3_key    = aws_s3_object.lambda_mask_to_cidr.key
  runtime = "python3.9"
  handler = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_mask_to_cidr.output_base64sha256
  role = aws_iam_role.lambda_exec.arn
}

resource "aws_lambda_function" "login" {
  function_name = "Login"
  s3_bucket = aws_s3_bucket.lambda_bucket.id
  s3_key    = aws_s3_object.lambda_login.key
  runtime = "python3.9"
  handler = "lambda_function.lambda_handler"
  source_code_hash = data.archive_file.lambda_login.output_base64sha256
  role = aws_iam_role.lambda_exec.arn
  vpc_config {
    subnet_ids = ["subnet-0951be4b7566d0bc1","subnet-048ac37137f653270"]
    security_group_ids = ["sg-01cf4c35e9bd3c2c6"]
  }
  environment {
    variables = {
        db_host = local.capstone_creds.db_host
        db_user = local.capstone_creds.db_user
        db_pass = local.capstone_creds.db_pass
        db_name = local.capstone_creds.db_name
        jwt_key = local.capstone_creds.jwt_key
        developer = local.capstone_creds.developer
    }
  }
}


resource "aws_cloudwatch_log_group" "hello_world" {
  name = "/aws/lambda/${aws_lambda_function.hello_world.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "cidr_to_mask" {
  name = "/aws/lambda/${aws_lambda_function.cidr_to_mask.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "mask_to_cidr" {
  name = "/aws/lambda/${aws_lambda_function.mask_to_cidr.function_name}"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "login" {
  name = "/aws/lambda/${aws_lambda_function.login.function_name}"
  retention_in_days = 30
}

resource "aws_iam_policy" "secrets_access" {
  name        = "secrets_access"
  path        = "/"
  description = "Access to secrets"
  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:secretsmanager:us-west-1:900510214286:secret:capstone-creds-yvkEMx"
      },
    ]
  })
}

resource "aws_iam_policy" "ec2_permissions" {
  name        = "ec2_permissions"
  path        = "/"
  description = "permissions to EC2 for the DB"
  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DeleteNetworkInterface"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role" "lambda_exec" {
  name = "serverless_lambda"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [ "sts:AssumeRole" ],
      Effect = "Allow"
      Sid    = ""
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      }
    ]
  })
}


resource "aws_iam_role_policy_attachment" "lambda_policy" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "secret_policy" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.secrets_access.arn
}

resource "aws_iam_role_policy_attachment" "ec2_policy" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = aws_iam_policy.ec2_permissions.arn
}

######

resource "aws_apigatewayv2_api" "lambda" {
  name          = "serverless_lambda_gw"
  protocol_type = "HTTP"
}

resource "aws_apigatewayv2_stage" "lambda" {
  api_id = aws_apigatewayv2_api.lambda.id

  name        = "serverless_lambda_stage"
  auto_deploy = true

  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_gw.arn

    format = jsonencode({
      requestId               = "$context.requestId"
      sourceIp                = "$context.identity.sourceIp"
      requestTime             = "$context.requestTime"
      protocol                = "$context.protocol"
      httpMethod              = "$context.httpMethod"
      resourcePath            = "$context.resourcePath"
      routeKey                = "$context.routeKey"
      status                  = "$context.status"
      responseLength          = "$context.responseLength"
      integrationErrorMessage = "$context.integrationErrorMessage"
      }
    )
  }
}

resource "aws_apigatewayv2_integration" "hello_world" {
  api_id = aws_apigatewayv2_api.lambda.id
  integration_uri    = aws_lambda_function.hello_world.invoke_arn
  integration_type   = "AWS_PROXY"
  integration_method = "POST"
}

resource "aws_apigatewayv2_integration" "cidr_to_mask" {
  api_id = aws_apigatewayv2_api.lambda.id
  integration_uri    = aws_lambda_function.cidr_to_mask.invoke_arn
  integration_type   = "AWS_PROXY"
  integration_method = "POST"
}

resource "aws_apigatewayv2_integration" "mask_to_cidr" {
  api_id = aws_apigatewayv2_api.lambda.id
  integration_uri    = aws_lambda_function.mask_to_cidr.invoke_arn
  integration_type   = "AWS_PROXY"
  integration_method = "POST"
}

resource "aws_apigatewayv2_integration" "login" {
  api_id = aws_apigatewayv2_api.lambda.id
  integration_uri    = aws_lambda_function.login.invoke_arn
  integration_type   = "AWS_PROXY"
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "hello_world" {
  api_id = aws_apigatewayv2_api.lambda.id
  route_key = "GET /hello"
  target    = "integrations/${aws_apigatewayv2_integration.hello_world.id}"
}

resource "aws_apigatewayv2_route" "cidr_to_mask" {
  api_id = aws_apigatewayv2_api.lambda.id
  route_key = "GET /cidr-to-mask"
  target    = "integrations/${aws_apigatewayv2_integration.cidr_to_mask.id}"
}

resource "aws_apigatewayv2_route" "mask_to_cidr" {
  api_id = aws_apigatewayv2_api.lambda.id
  route_key = "GET /mask-to-cidr"
  target    = "integrations/${aws_apigatewayv2_integration.mask_to_cidr.id}"
}

resource "aws_apigatewayv2_route" "login" {
  api_id = aws_apigatewayv2_api.lambda.id
  route_key = "POST /login"
  target    = "integrations/${aws_apigatewayv2_integration.login.id}"
}

resource "aws_cloudwatch_log_group" "api_gw" {
  name = "/aws/api_gw/${aws_apigatewayv2_api.lambda.name}"
  retention_in_days = 30
}

resource "aws_lambda_permission" "api_gw" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.hello_world.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_apigatewayv2_api.lambda.execution_arn}/*/*"
}

resource "aws_lambda_permission" "api_gw_cidr_to_mask" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cidr_to_mask.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_apigatewayv2_api.lambda.execution_arn}/*/*"
}

resource "aws_lambda_permission" "api_gw_mask_to_cidr" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.mask_to_cidr.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_apigatewayv2_api.lambda.execution_arn}/*/*"
}

resource "aws_lambda_permission" "api_gw_login" {
  statement_id  = "AllowExecutionFromAPIGateway"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.login.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn = "${aws_apigatewayv2_api.lambda.execution_arn}/*/*"
}



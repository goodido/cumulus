resource "aws_sqs_queue" "db_indexer_dead_letter_queue" {
  name                       = "${var.prefix}-dbIndexerDeadLetterQueue"
  receive_wait_time_seconds  = 20
  visibility_timeout_seconds = 60
}

resource "aws_lambda_function" "db_indexer" {
  function_name    = "${var.prefix}-dbIndexer"
  filename         = "${path.module}/../../packages/api/dist/dbIndexer/lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/../../packages/api/dist/dbIndexer/lambda.zip")
  handler          = "index.handler"
  role             = aws_iam_role.lambda_processing.arn
  runtime          = "nodejs8.10"
  timeout          = 300
  memory_size      = 320
  dead_letter_config {
    target_arn = aws_sqs_queue.db_indexer_dead_letter_queue.arn
  }
  environment {
    variables = {
      CMR_ENVIRONMENT = var.cmr_environment
      FilesTable      = var.dynamo_tables.Files
      ES_HOST         = var.elasticsearch_hostname
      stackName       = var.prefix
      system_bucket   = var.system_bucket
    }
  }
  tags = {
    Project = var.prefix
  }
  vpc_config {
    subnet_ids         = var.lambda_subnet_ids
    security_group_ids = [aws_security_group.no_ingress_all_egress.id]
  }
}

resource "aws_lambda_event_source_mapping" "collections_table_db_indexer" {
  event_source_arn  = data.aws_dynamodb_table.collections.stream_arn
  function_name     = aws_lambda_function.db_indexer.arn
  starting_position = "TRIM_HORIZON"
  batch_size        = 10
}

resource "aws_lambda_event_source_mapping" "executions_table_db_indexer" {
  event_source_arn  = data.aws_dynamodb_table.executions.stream_arn
  function_name     = aws_lambda_function.db_indexer.arn
  starting_position = "TRIM_HORIZON"
  batch_size        = 10
}

resource "aws_lambda_event_source_mapping" "granules_table_db_indexer" {
  event_source_arn  = data.aws_dynamodb_table.granules.stream_arn
  function_name     = aws_lambda_function.db_indexer.arn
  starting_position = "TRIM_HORIZON"
  batch_size        = 10
}

resource "aws_lambda_event_source_mapping" "pdrs_table_db_indexer" {
  event_source_arn  = data.aws_dynamodb_table.pdrs.stream_arn
  function_name     = aws_lambda_function.db_indexer.arn
  starting_position = "TRIM_HORIZON"
  batch_size        = 10
}

resource "aws_lambda_event_source_mapping" "providers_table_db_indexer" {
  event_source_arn  = data.aws_dynamodb_table.providers.stream_arn
  function_name     = aws_lambda_function.db_indexer.arn
  starting_position = "TRIM_HORIZON"
  batch_size        = 10
}

resource "aws_lambda_event_source_mapping" "rules_table_db_indexer" {
  event_source_arn  = data.aws_dynamodb_table.rules.stream_arn
  function_name     = aws_lambda_function.db_indexer.arn
  starting_position = "TRIM_HORIZON"
  batch_size        = 10
}
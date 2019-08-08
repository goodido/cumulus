# Report Executions

This package includes a Lambda function to process granule ingest notifications received via SNS and store granule data to a database.

## Deployment

1. Copy the .tfvars sample file: `cp terraform.tfvars.sample terraform.tfvars`
2. Populate the sample file with values that apply to your AWS environment (see configuration variables section below).
3. Deploy this module: `terraform apply`

NOTE: Terraform will ignore the `aws_profile` config variable if you have static credentials or environment variables set, see the [AWS Provider page](https://www.terraform.io/docs/providers/aws/index.html#authentication).

## Configuration

Configuration variables are shown in `terraform.tfvars.sample`, and are explained below:

```text
# Required
granules_table        = "GranulesTableName"  # name of DynamoDB table to store granules data
prefix                = "myprefix"             # prefix to use for naming created resources

# Optional
permissions_boundary  = "arn:aws:iam::1234567890:policy/YourRoleBoundary" # IAM permissions boundary
security_groups       = ["sg-123456"]          # Security Group IDs (for Lambda)
subnet_ids            = ["subnet-123456"]      # Subnet IDs (for Lambda)
```
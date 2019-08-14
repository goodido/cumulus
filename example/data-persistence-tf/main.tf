variable "prefix" {
  type = string
}

variable "subnet_ids" {
  type = list(string)
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

provider "aws" {
  region = var.aws_region
}

module "data_persistence" {
  source = "../../tf-modules/data-persistence"

  prefix                     = var.prefix
  subnet_ids                 = var.subnet_ids
  create_service_linked_role = false
}

output "dynamo_tables" {
  value = module.data_persistence.dynamo_tables
}

output "elasticsearch_domain_arn" {
  value = module.data_persistence.elasticsearch_domain_arn
}

output "elasticsearch_hostname" {
  value = module.data_persistence.elasticsearch_hostname
}

output "elasticsearch_security_group_id" {
  value = module.data_persistence.elasticsearch_security_group_id
}

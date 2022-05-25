provider "aws" {
  region = "ap-southeast-1"
}

module "aws_certification_expiry_alert" {
  source = "./modules/services/aws-certification-expiry"
  account_id = "102165413997"
  topic_name = "aws_expiration_alert_sns_topic"
  email_subscription  = "thangnh1997soict@gmail.com"
  expiry_day      = 120
  scheduler_name = "aws_scheduler_cert_expiry"
  schedule_expression      = "cron(0 9 * * ? *)"
}
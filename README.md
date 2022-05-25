# aws-expiry-certification-alert-trf
## Usage

Modify environment below:

```sh
module "aws_certification_expiry_alert" {
  source = "./modules/services/aws-certification-expiry"
  account_id = "your_account_id_here"
  topic_name = "aws_expiration_alert_sns_topic"
  email_subscription  = "youremail@gmail.com"
  expiry_day      = 120
  scheduler_name = "aws_scheduler_cert_expiry"
  schedule_expression      = "cron(0 9 * * ? *)"
}
```
Ref https://aws.amazon.com/blogs/security/how-to-monitor-expirations-of-imported-certificates-in-aws-certificate-manager-acm/
https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html

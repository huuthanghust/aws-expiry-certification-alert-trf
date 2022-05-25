resource "aws_iam_role" "lambda_role" {
name   = "AWS_Cert_expiration_Lambda_Function_Role"
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
}

resource "aws_iam_policy" "iam_policy_for_lambda" {
 
 name         = "aws_iam_policy_for_terraform_aws_lambda_role"
 path         = "/"
 description  = "AWS IAM Policy for managing aws lambda role"
 policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid":"LambdaCertificateExpiryPolicy1",
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:ap-southeast-1:${var.account_id}:*"
        },
        {
            "Sid":"LambdaCertificateExpiryPolicy2",
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:ap-southeast-1:${var.account_id}:log-group:/aws/lambda/handle-expiring-certificates:*"
            ]
        },
        {
            "Sid":"LambdaCertificateExpiryPolicy3",
            "Effect": "Allow",
            "Action": [
                "acm:DescribeCertificate",
                "acm:GetCertificate",
                "acm:ListCertificates",
                "acm:ListTagsForCertificate"
            ],
            "Resource": "*"
        },
        {
            "Sid":"LambdaCertificateExpiryPolicy4",
            "Effect": "Allow",
            "Action": "SNS:Publish",
            "Resource": "*"
        },
        {
            "Sid":"LambdaCertificateExpiryPolicy5",
            "Effect": "Allow",
            "Action": [
                "SecurityHub:BatchImportFindings",
                "SecurityHub:BatchUpdateFindings",
                "SecurityHub:DescribeHub"
            ],
            "Resource": "*"
        },
        {
            "Sid": "LambdaCertificateExpiryPolicy6",
            "Effect": "Allow",
            "Action": "cloudwatch:ListMetrics",
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "attach_iam_policy_to_iam_role" {
 role        = aws_iam_role.lambda_role.name
 policy_arn  = aws_iam_policy.iam_policy_for_lambda.arn
}
 
data "archive_file" "zip_the_python_code" {
type        = "zip"
source_dir  = "${path.module}/python/"
output_path = "${path.module}/python/aws-cert-expiry.zip"
}
 
resource "aws_lambda_function" "terraform_lambda_func" {
filename                       = "${path.module}/python/aws-cert-expiry.zip"
function_name                  = "Spacelift_Test_Lambda_Function"
role                           = aws_iam_role.lambda_role.arn
handler                        = "aws-cert-expiry.lambda_handler"
runtime                        = "python3.8"
depends_on                     = [aws_iam_role_policy_attachment.attach_iam_policy_to_iam_role]
environment {
    variables = {
      EXPIRY_DAYS = var.expiry_day
      SNS_TOPIC_ARN = aws_sns_topic.topic.arn
    }
  }
}

resource "aws_sns_topic" "topic" {
  name = var.topic_name
}

resource "aws_sns_topic_subscription" "email-target" {
  topic_arn = aws_sns_topic.topic.arn
  protocol  = "email"
  endpoint  =  var.email_subscription
}


resource "aws_cloudwatch_event_rule" "every_five_minutes" {
    name = var.scheduler_name
    description = "Fires with cron expression"
    schedule_expression = var.schedule_expression
    # schedule_expression = "cron(0 20 * * ? *)"
}

resource "aws_cloudwatch_event_target" "check_foo_every_five_minutes" {
    rule = aws_cloudwatch_event_rule.every_five_minutes.name
    target_id = "terraform_lambda_func"
    arn = aws_lambda_function.terraform_lambda_func.arn
}

resource "aws_lambda_permission" "allow_cloudwatch_to_call_check_foo" {
    statement_id = "AllowExecutionFromCloudWatch"
    action = "lambda:InvokeFunction"
    function_name = aws_lambda_function.terraform_lambda_func.function_name
    principal = "events.amazonaws.com"
    source_arn = aws_cloudwatch_event_rule.every_five_minutes.arn
}
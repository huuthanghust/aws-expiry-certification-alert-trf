variable "account_id" {
  description = "AWS account id"
  type        = string
}

variable "topic_name" {
  description = "Topic name sns"
  type        = string
}

variable "email_subscription" {
  description = "Email subscription"
  type        = string
}

variable "expiry_day" {
  description = "Number of day before expire to monitor"
  type        = number
}

variable "scheduler_name" {
  description = "scheduler name"
  type        = string
}

variable "schedule_expression" {
  description = "scheduler expression"
  type        = string
}



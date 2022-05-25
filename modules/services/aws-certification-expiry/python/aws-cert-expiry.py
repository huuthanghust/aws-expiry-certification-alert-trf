# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json
import boto3
import os
from datetime import datetime, timedelta, timezone

# -------------------------------------------
# setup global data
# -------------------------------------------
utc = timezone.utc

# make today timezone aware
today = datetime.now().replace(tzinfo=utc)

# set up time window for alert - default to 45 if its missing
if os.environ.get('EXPIRY_DAYS') is None:
    expiry_days = 45
else:
    expiry_days = int(os.environ['EXPIRY_DAYS'])

expiry_window = today + timedelta(days = expiry_days)

def lambda_handler(event, context):

    # if this is coming from the ACM event, its for a single certificate
    if (event['detail-type'] == "ACM Certificate Approaching Expiration"):
        response = handle_single_cert (event, context.invoked_function_arn)

    # otherwise, we need to get all the expiring certs that are expiring from CloudWatch Metrics
    else:
        response = handle_multiple_certs(event, context.invoked_function_arn)
    
    return {
        'statusCode': 200,
        'body': response 
    }


def handle_single_cert(event, context_arn):
    cert_client = boto3.client('acm')

    cert_details = cert_client.describe_certificate(CertificateArn=event['resources'][0])

    result = 'The following certificate is expiring within ' + str(expiry_days) + ' days: ' + cert_details['Certificate']['DomainName']
    
    # check the expiry window before logging to Security Hub and sending an SNS
    if cert_details['Certificate']['NotAfter'] < expiry_window:
        # This call is the text going into the SNS notification
        result = result + ' (' + cert_details['Certificate']['CertificateArn'] + ') '

        # this call is publishing to SH
        result = result + ' - ' + log_finding_to_sh(event, cert_details, context_arn)
        
        # if there's an SNS topic, publish a notification to it
        if os.environ.get('SNS_TOPIC_ARN') is None:
            response = result
        else:
            sns_client = boto3.client('sns')
            response = sns_client.publish(TopicArn=os.environ['SNS_TOPIC_ARN'], Message=result, Subject='Certificate Expiration Notification')
        
    return result

def handle_multiple_certs(event, context_arn):
    cert_client = boto3.client('acm')

    cert_list = json.loads(get_expiring_cert_arns())
    
    if cert_list is None:
        response = 'No certificates are expiring within ' + str(expiry_days) + ' days.'

    else:
        response = 'The following certificates are expiring within ' + str(expiry_days) + ' days: \n'

        # loop through the cert list and pull out certs that are expiring within the expiry window
        for csl in cert_list:
            cert_arn = json.dumps(csl['Dimensions'][0]['Value']).replace('\"', '')
            cert_details = cert_client.describe_certificate(CertificateArn=cert_arn)

            if cert_details['Certificate']['NotAfter'] < expiry_window:
                current_cert = 'Domain:' + cert_details['Certificate']['DomainName'] + ' (' + cert_details['Certificate']['CertificateArn'] + '), \n'
                print(current_cert)

                # this is publishing to SH
                result = log_finding_to_sh(event, cert_details, context_arn)

                # This is the text going into the SNS notification
                response = response + current_cert
                
    # if there's an SNS topic, publish a notification to it
    if os.environ.get('SNS_TOPIC_ARN') is not None:
        sns_client = boto3.client('sns')
        response = sns_client.publish(TopicArn=os.environ['SNS_TOPIC_ARN'], Message=response.rstrip(', \n'), Subject='Certificate Expiration Notification')

    return response

def log_finding_to_sh(event, cert_details, context_arn):
    # setup for security hub
    sh_region = get_sh_region(event['region'])
    sh_hub_arn = "arn:aws:securityhub:{0}:{1}:hub/default".format(sh_region, event['account'])
    sh_product_arn = "arn:aws:securityhub:{0}:{1}:product/{1}/default".format(sh_region, event['account'])

    # check if security hub is enabled, and if the hub arn exists
    sh_client = boto3.client('securityhub', region_name = sh_region)
    try:
        sh_enabled = sh_client.describe_hub(HubArn = sh_hub_arn)

    # the previous command throws an error indicating the hub doesn't exist or lambda doesn't have rights to it so we'll stop attempting to use it
    except Exception as error:
        sh_enabled = None
        print ('Default Security Hub product doesn\'t exist')
        response = 'Security Hub disabled'
    
    # This is used to generate the URL to the cert in the Security Hub Findings to link directly to it
    cert_id = right(cert_details['Certificate']['CertificateArn'], 36)

    if sh_enabled:
        # set up a new findings list
        new_findings = []
    
            # add expiring certificate to the new findings list
        new_findings.append({
            "SchemaVersion": "2018-10-08",
            "Id": cert_id,
            "ProductArn": sh_product_arn,
            "GeneratorId": context_arn,
            "AwsAccountId": event['account'],
            "Types": [
                "Software and Configuration Checks/AWS Config Analysis"
            ],
            "CreatedAt": event['time'],
            "UpdatedAt": event['time'],
            "Severity": {
                "Original": '89.0',
                "Label": 'HIGH'
            },
            "Title": 'Certificate expiration',
            "Description": 'cert expiry',
            'Remediation': {
                'Recommendation': {
                    'Text': 'A new certificate for ' + cert_details['Certificate']['DomainName'] + ' should be imported to replace the existing imported certificate before expiration',
                    'Url': "https://console.aws.amazon.com/acm/home?region=" + event['region'] + "#/?id=" + cert_id
                }
            },
            'Resources': [
                {
                    'Id': event['id'],
                    'Type': 'ACM Certificate',
                    'Partition': 'aws',
                    'Region': event['region']
                }
            ],
            'Compliance': {'Status': 'WARNING'}
        })
    
        # push any new findings to security hub
        if new_findings:
            try:
                response = sh_client.batch_import_findings(Findings=new_findings)
    
                if response['FailedCount'] > 0:
                    print("Failed to import {} findings".format(response['FailedCount']))
    
            except Exception as error:
                print("Error: ", error)
                raise
            
    return json.dumps(response)

def get_expiring_cert_arns():
    cert_list = []
    
    # Create CloudWatch client
    cloudwatch = boto3.client('cloudwatch')
    
    paginator = cloudwatch.get_paginator('list_metrics')
    
    for response in paginator.paginate(
        MetricName='DaysToExpiry',
        Namespace='AWS/CertificateManager',
        Dimensions=[{'Name': 'CertificateArn'}],):
            cert_list = cert_list + (response['Metrics'])
            
    # return all certs that are expiring according to CW
    return json.dumps(cert_list)

# function to setup the sh region    
def get_sh_region(event_region):
    # security hub findings may need to go to a different region so set that here
    if os.environ.get('SECURITY_HUB_REGION') is None:
        sh_region_local = event_region
    else:
        sh_region_local = os.environ['SECURITY_HUB_REGION']
    
    return sh_region_local
    
# quick function to trim off right side of a string
def right(value, count):
    # To get right part of string, use negative first index in slice.
    return value[-count:] 

import os
import json
import boto3
from tenable.io import TenableIO
from botocore.exceptions import ClientError


# --- Configuration ---
tio_access_key = 'key'
tio_secret_key = 'secret'
aws_region = 'us-east-1'
sender_email = 'security@contrastsecurity.com'

# Get access/secret key for SES
def get_secret(secret_name, region_name):

    secret_name = "ses_tenable_key"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']

# Initialize Tenable.io and AWS SES clients
tio = TenableIO(tio_access_key, tio_secret_key)
ses_client = boto3.client('ses', region_name='us-east-1')

# Retrieves a list of assets with their vulnerabilities from Tenable.io.
def get_asset_vulnerabilities():

    # returns dictionary where keys are asset names and values are lists of vulns
    assets_with_vulns = {}
    assets = tio.assets.list()
    for asset in assets:
        vulns = tio.workbenches.vuln_info(asset_id=asset['id'])
        if vulns:
            assets_with_vulns[asset['name']] = vulns
    return assets_with_vulns

# Sends an email to a user with a list of vulnerabilities on their machine using AWS SES.
def send_vulnerability_email(recipient_email, asset_name, vulnerabilities):
    """
    Args:
        recipient_email (str): The email address of the recipient.
        asset_name (str): The name of the asset.
        vulnerabilities (list): A list of vulnerabilities.
    """
    # Create email body w/ vulnerability details and remediation information
    body = f"Hello,\n\nThis is a vulnerability report for your computer: {asset_name}\n\n"
    for vuln in vulnerabilities:
        body += f"Vulnerability: {vuln['plugin_name']}\n"
        body += f"Severity: {vuln['severity']}\n"
        body += f"Remediation: {vuln['solution']}\n\n"

    try:
        response = ses_client.send_email(
            Source=sender_email,
            Destination={
                'ToAddresses': [recipient_email]
            },
            Message={
                'Subject': {
                    'Data': f'Vulnerability Report for {asset_name}'
                },
                'Body': {
                    'Text': {
                        'Data': body
                    }
                }
            }
        )
        print(f"Email sent to {recipient_email} with message ID: {response['MessageId']}")
    except Exception as e:
        print(f"Error sending email: {e}")

# def main():
#     """
#     Main function to retrieve vulnerabilities and send emails.
#     """
#     try:
#         asset_vulnerabilities = get_asset_vulnerabilities()

#         # Assuming you have a way to map asset names to user emails (e.g., through tags)
#         asset_to_email_mapping = {
#             # 'asset_name1': 'user1@example.com',
#             # 'asset_name2': 'user2@example.com',
#             # ...
#         }

#         for asset_name, vulnerabilities in asset_vulnerabilities.items():
#             recipient_email = asset_to_email_mapping.get(asset_name)
#             if recipient_email:
#                 send_vulnerability_email(recipient_email, asset_name, vulnerabilities)
#             else:
#                 print(f"No email address found for asset: {asset_name}")

#     except Exception as e:
#         print(f"An error occurred: {e}")

# if __name__ == "__main__":
#     main()
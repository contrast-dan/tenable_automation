import requests
import base64
import boto3
import json
import os
from botocore.exceptions import ClientError

## AWS Authentication and Secrets Retreival 
# Get Tenable keys from AWS Secrets manager
def get_secret():

    secret_name = "SecOps/Tenable/ApiKey"
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
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e 
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        else:
            raise e

    # Decrypts secret using the associated KMS CMK.
    # Depending on whether the secret is a string or binary, one of these fields will be populated.
    if 'SecretString' in get_secret_value_response: 
        secret = get_secret_value_response['SecretString']
    else:
        decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
    print(secret)

    secretJson = json.loads(secret)

    return secretJson[secret_name]

def auth():
    apiKeys = get_secret()
    authHeaders = {
        'Accept': 'application/json',
        'content-type': 'application/json',
        'x-apikeys': apiKeys
    }
    return(authHeaders)

url = 'https://cloud.tenable.com/scans/scan_uuid/hosts/host_id'
headers = {
    'accept': 'application/json',
    'X-ApiKeys': apiKeys
}

response = requests.get(url, headers=authHeaders)

print(response.text)

# Retrieves a list of assets with their vulnerabilities from Tenable.io.
# def get_asset_vulnerabilities():
#     url = "https://cloud.tenable.com/scans/(scan_uuid)/hosts/(host_id)"
#     headers = {
#     "accept": "application/json",
#     "X-ApiKeys": apiKeys
#     }

# response = requests.request(url, headers=authHeaders)

# print(response.text)

# --------------------------------------------------------------------------------------------------------------------



#     # returns dictionary where keys are asset names and values are lists of vulns
#     assets_with_vulns = {}
#     assets = tio.assets.list()
#     for asset in assets:
#         vulns = tio.workbenches.vuln_info(asset_id=asset['id'])
#         if vulns:
#             assets_with_vulns[asset['name']] = vulns
#     return assets_with_vulns

# # Sends an email to a user with a list of vulnerabilities on their machine using AWS SES.
# def send_vulnerability_email(recipient_email, asset_name, vulnerabilities):
#     """
#     Args:
#         recipient_email (str): The email address of the recipient.
#         asset_name (str): The name of the asset.
#         vulnerabilities (list): A list of vulnerabilities.
#     """
#     # Create email body w/ vulnerability details and remediation information
#     body = f"Hello,\n\nThis is a vulnerability report for your computer: {asset_name}\n\n"
#     for vuln in vulnerabilities:
#         body += f"Vulnerability: {vuln['plugin_name']}\n"
#         body += f"Severity: {vuln['severity']}\n"
#         body += f"Remediation: {vuln['solution']}\n\n"

#     try:
#         response = ses_client.send_email(
#             Source=sender_email,
#             Destination={
#                 'ToAddresses': [recipient_email]
#             },
#             Message={
#                 'Subject': {
#                     'Data': f'Vulnerability Report for {asset_name}'
#                 },
#                 'Body': {
#                     'Text': {
#                         'Data': body
#                     }
#                 }
#             }
#         )
#         print(f"Email sent to {recipient_email} with message ID: {response['MessageId']}")
#     except Exception as e:
#         print(f"Error sending email: {e}")

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
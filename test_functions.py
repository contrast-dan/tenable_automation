# # This is what I used for testing 
# import requests
# import base64
# import boto3
# import json
# import os
# import socket
# from botocore.exceptions import ClientError

# scan_uuid='d94d2bc0-7699-47b8-8246-5a3700a6c516'
# host_id = socket.gethostname()
# print("This is only a test")
# url = 'https://cloud.tenable.com/scans/'+scan_uuid+'/hosts/'+host_id+''
# print(url)
# #apiKeys = 'kjlbhnvfoin7wq465bvywiabowv46'
# #print(apiKeys)
# #headers = {"accept": "application/json","X-ApiKeys": apiKeys}
# #print(headers)
# #authHeaders = {"Accept": "application/json","content-type": "application/json","x-apikeys": apiKeys}
# #print(authHeaders)
# #response = requests.get(url, headers=authHeaders)

# def auth():
#     apiKeys = 'kjlbhnvfoin7wq465bvywiabowv46'
#     authHeaders = {"Accept": "application/json","content-type": "application/json","x-apikeys": apiKeys}
#     return authHeaders

# authHeaders = auth()
# print(authHeaders)

# # Retrieves a list of assets with their vulnerabilities from Tenable.io.
# def get_asset_vulnerabilities(authHeaders):
#     url = '"https://cloud.tenable.com/scans/"'+scan_uuid+'"/hosts/"'+host_id+'"'
#     print(url)
#     headers = {"accept": "application/json","X-ApiKeys": apiKeys}
#     response = requests.get(url, headers=authHeaders)
#     return response



# test_fun = get_asset_vulnerabilities(authHeaders)
# print(test_fun)

import requests
import base64
import boto3
import json
import os
from botocore.exceptions import ClientError
#from tenable.io import TenableIO
## Global Variables
# Setting the Global Variables
scan_uuid = "d94d2bc0-7699-47b8-8246-5a3700a6c516"

## AWS Authentication and Secrets Retreival 
# Get Tenable keys from AWS Secrets manager
def get_secret():

    secret_name = "SecOps/Tenable/ApiKey"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager',region_name=region_name)

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
    authHeaders = '{"Accept": "application/json","content-type": "application/json","x-apikeys":'+apiKeys+'}'
    return(authHeaders)

authHeaders = auth()

# Retrieves a list of assets with their vulnerabilities from Tenable.io.
def get_asset_vulnerabilities(authHeaders):
    apiKeys = get_secret()
    url = '"https://cloud.tenable.com/scans/"'+scan_uuid+'"/hosts/"'+host_id+'"'
    headers = '{"accept": "application/json","X-ApiKeys":'+apiKeys+'}'
    response = requests.get(url, headers=authHeaders)
    return(response)

response = get_asset_vulnerabilities(authHeaders)

print(response.text)
import requests
import base64
import boto3
import json
from tenable.io import TenableIO

# Get access/secret key for SES
def get_secret(secret_name, region_name):

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
            raise e:
        get_secret_value_response = client.get_secret_value(SecretId='secret_name')
        print(get_secret_value_response)

    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']

    print(secret)

# # Initiate tenable authorization
# secret_name = "ses_tenable_key"
# region_name = "us-east-1"

# # import keys
# secret_dict = json.loads(secret)
# access_key = secret_dict['accesskey']
# secret_key = secret_dict['secretkey']

# tio = TenableIO(access_key, secret_key)

# # Get secret from Secrets Manager
# secret = get_secret(secret_name, region_name)

# # Get all assets
# assets = tio.assets.list()

# # Extract all machine names
# machine_names = [asset['hostname'] for asset in assets]

# # Print machine names
# for name in machine_names:
# 	print(name)

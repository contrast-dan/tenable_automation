import boto3
from tenable.io import TenableIO

# Get access/secret key for SES
def get_secret():

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

# Initiate tenable authorization
tio = TenableIO(SecretId)

#Get all assets
assets = tio.assets.list()

# Extract all machine names
machine_names = [asset['hostname'] for asset in assets]

# Print machine names
for name in machine_names:
	print(name)

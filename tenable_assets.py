import boto3
from tenable.io import TenableIO

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
            SecretId='secret_name'
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']

    return secret

	# Initiate tenable authorization
	secret_name = "ses_tenable_key"
	region_name = "us-east-1"

	# import keys
	import json
	secret_dict = json.loads(secret)
	access_key = secret_dict['accesskey']
	secret_key = secret_dict['secretkey']

	tio = TenableIO(access_key, secret_key)

	# Get secret from Secrets Manager
	secret = get_secret(secret_name, region_name)

	# Get all assets
	assets = tio.assets.list()

	# Extract all machine names
	machine_names = [asset['hostname'] for asset in assets]

	# Print machine names
	for name in machine_names:
		print(name)

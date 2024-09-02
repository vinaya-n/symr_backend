from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.http import JsonResponse, HttpResponseForbidden
from django.middleware.csrf import get_token
from datetime import datetime, timedelta
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt, requires_csrf_token, csrf_protect
#from corsheaders.decorators import allow_all_origins
import math
import json
import boto3
from django.middleware.csrf import get_token
from django.conf import settings
from django.shortcuts import render, redirect
from boto3.s3.transfer import S3Transfer
from boto3.session import Session
from botocore.exceptions import ClientError
import jwt, requests
from urllib.parse import urlencode
from jwt.algorithms import RSAAlgorithm
from jwt import PyJWKClient
from jwt.exceptions import DecodeError, InvalidTokenError
import os, io
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from base64 import b64encode, b64decode
import magic
from docx import Document
from PyPDF2 import PdfReader
from io import BytesIO
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from django.core.files.storage import default_storage
from google_auth_oauthlib.flow import Flow
import logging
from django.urls import reverse
import logging
import sys
import csv
from django.utils import timezone
from datetime import *
import datetime

# Set up logging
# logging.basicConfig(
    # level=logging.INFO,
    # format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    # handlers=[
        # logging.StreamHandler(sys.stdout)
    # ]
# )

# logger = logging.getLogger(__name__)

#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development

@csrf_exempt
def fetch_data(request):
    print("Inside fetch_data ")
    if request.method == 'POST':
        data = json.loads(request.body)
        user_name = data['username']
        request_from = data['page']
        
        print("Inside fetch_data "+request_from)
        print("user_name " +user_name)

        if not user_name:
            return JsonResponse({'error': 'User name is required'}, status=400)
            
        #Get the environment variable
        aws_access_key_id_json = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_access_key_json = os.getenv('AWS_SECRET_ACCESS_KEY')

        # Parse the JSON string
        aws_access_key_id_dict = json.loads(aws_access_key_id_json)
        aws_secret_access_key_dict = json.loads(aws_secret_access_key_json)

        # Extract the value
        aws_access_key_id_e = aws_access_key_id_dict['AWS_ACCESS_KEY_ID']
        aws_secret_access_key_e = aws_secret_access_key_dict['AWS_SECRET_ACCESS_KEY']    

        # aws_access_key_id_e = os.getenv('AWS_ACCESS_KEY_ID')
        # aws_secret_access_key_e = os.getenv('AWS_SECRET_ACCESS_KEY')
        print("inside request_from FHC") 

        dynamodb = boto3.resource('dynamodb',
                                  region_name=os.getenv('AWS_REGION'),
                                  aws_access_key_id=aws_access_key_id_e,
                                  aws_secret_access_key=aws_secret_access_key_e)
        # table = dynamodb.Table('know_your_metrics')
        if request_from == "FHC":     
            print("inside request_from FHC")    
            table = dynamodb.Table('know_your_metrics')
        elif request_from == "AS":
            table = dynamodb.Table('symr_allocate_savings')
        elif request_from == "BH":
            table = dynamodb.Table('symr_buy_home') 
        elif request_from == "DM":
            table = dynamodb.Table('symr_debt_mgmt')
        elif request_from == "SFG":
            table = dynamodb.Table('symr_save_for_goal')  
        elif request_from == "VP":
            table = dynamodb.Table('symr_create_budget')
        elif request_from == "INV":
            table = dynamodb.Table('symr_investing') 

        response = table.get_item(Key={'user_name': user_name})
        
        print("After response")
        print(response)

        if 'Item' in response:
            return JsonResponse(response['Item'])
        else:
            return JsonResponse({'error': 'User not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def save_to_dynamo(request):
    if request.method == 'POST':
        print("Inside save_to_dynamo")
        # if not request.user.is_authenticated:
        #     return JsonResponse({'error': 'User not authenticated'}, status=401)

        data = json.loads(request.body)
        
        #Get the environment variable
        aws_access_key_id_json = os.getenv('AWS_ACCESS_KEY_ID')
        aws_secret_access_key_json = os.getenv('AWS_SECRET_ACCESS_KEY')

        # Parse the JSON string
        aws_access_key_id_dict = json.loads(aws_access_key_id_json)
        aws_secret_access_key_dict = json.loads(aws_secret_access_key_json)

        # Extract the value
        aws_access_key_id_e = aws_access_key_id_dict['AWS_ACCESS_KEY_ID']
        aws_secret_access_key_e = aws_secret_access_key_dict['AWS_SECRET_ACCESS_KEY']
        
        # Add username and created date to the data
        data['user_name'] = data['username']
        data['created_date'] = datetime.datetime.now().isoformat()
        request_from = data['page']
        
        # AWS credentials from environment variables
        # aws_access_key_id_e = os.getenv('AWS_ACCESS_KEY_ID')
        # aws_secret_access_key_e = os.getenv('AWS_SECRET_ACCESS_KEY')
        region_name = os.getenv('AWS_REGION')
        
        print("before initializing")
        # Initialize DynamoDB resource
        dynamodb = boto3.resource('dynamodb',
                                  region_name=region_name,
                                  aws_access_key_id=aws_access_key_id_e,
                                  aws_secret_access_key=aws_secret_access_key_e)
        if request_from == "FHC":                          
            table = dynamodb.Table('know_your_metrics')
        elif request_from == "AS":
            table = dynamodb.Table('symr_allocate_savings')
        elif request_from == "BH":
            table = dynamodb.Table('symr_buy_home') 
        elif request_from == "DM":
            table = dynamodb.Table('symr_debt_mgmt')
        elif request_from == "SFG":
            table = dynamodb.Table('symr_save_for_goal')  
        elif request_from == "VP":
            table = dynamodb.Table('symr_create_budget')
        elif request_from == "INV":
            table = dynamodb.Table('symr_investing')        
        
        # Check if the record exists
        response = table.get_item(
            Key={
                'user_name': data['user_name']
            }
        )
        existing_item = table.get_item(Key={'user_name': data['user_name']}).get('Item')

        if existing_item:
            # Update the existing item with new values from data
            for key, value in data.items():
                if key not in ['user_name', 'created_date']:
                    existing_item[key] = value
            
            # Construct the update expression
            update_expression = []
            expression_attribute_names = {}
            expression_attribute_values = {}

            for key, value in existing_item.items():
                if key not in ['user_name', 'created_date']:
                    placeholder_name = f'#{key}'
                    update_expression.append(f'{placeholder_name} = :{key}')
                    expression_attribute_names[placeholder_name] = key
                    expression_attribute_values[f':{key}'] = value

            if update_expression:
                update_expression_str = 'set ' + ', '.join(update_expression)
                
                print("update_expression_str is "+update_expression_str)

                table.update_item(
                    Key={'user_name': data['user_name']},
                    UpdateExpression=update_expression_str,
                    ExpressionAttributeNames=expression_attribute_names,
                    ExpressionAttributeValues=expression_attribute_values
                )

            return JsonResponse({'message': 'Record updated successfully'})
        else:
            # Insert logic (unchanged)
            data['created_at'] = datetime.datetime.now().isoformat()
            table.put_item(Item=data)
            return JsonResponse({'message': 'Record inserted successfully'})

        # if 'Item' in response:
            # # Assuming `data` contains all fields that you might want to update
            # update_expression = []
            # expression_attribute_names = {}
            # expression_attribute_values = {}
            # print('Inside update logic')

            # # Construct the update expression based on the fields in `data`
            # for key, value in data.items():
                # print("key is "+key)
                # if key not in ['user_name', 'created_date']:  # Exclude fields that should not be updated
                    # placeholder_name = f'#{key}'
                    # update_expression.append(f'{placeholder_name} = :{key}')
                    # expression_attribute_names[placeholder_name] = key
                    # expression_attribute_values[f':{key}'] = value

            # if update_expression:
                # # Join the parts of the update expression
                # update_expression_str = 'set ' + ', '.join(update_expression)

                # # Add the current date-time to the update expression
                # #update_expression_str += ', #updated_at = :updated_at'
                # #expression_attribute_names['#updated_at'] = 'updated_at'
                # #expression_attribute_values[':updated_at'] = datetime.datetime.now().isoformat()
                
                # # Update the item in DynamoDB
                # table.update_item(
                    # Key={'user_name': data['user_name']},
                    # UpdateExpression=update_expression_str,
                    # ExpressionAttributeNames=expression_attribute_names,
                    # ExpressionAttributeValues=expression_attribute_values
                # )
           
            # return JsonResponse({'message': 'Record updated successfully'})
        
        # else:
            # # Record does not exist, insert it
            # data['created_at'] = datetime.datetime.now().isoformat()  # Add creation date
            # table.put_item(Item=data)
            # return JsonResponse({'message': 'Record inserted successfully'})
        
        print("before Save data to DynamoDB")
        # # Save data to DynamoDB
        # response = table.put_item(Item=data)
        
        print("after Save data to DynamoDB")
        
        return JsonResponse({'message': 'Data saved successfully', 'response': response})
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=400)



def download_cognito_users(request):
    # Get the environment variable
    # aws_access_key_id_json = os.getenv('AWS_ACCESS_KEY_ID')
    # aws_secret_access_key_json = os.getenv('AWS_SECRET_ACCESS_KEY')

    # # Parse the JSON string
    # aws_access_key_id_dict = json.loads(aws_access_key_id_json)
    # aws_secret_access_key_dict = json.loads(aws_secret_access_key_json)

    # # Extract the value
    # aws_access_key_id_e = aws_access_key_id_dict['AWS_ACCESS_KEY_ID']
    # aws_secret_access_key_e = aws_secret_access_key_dict['AWS_SECRET_ACCESS_KEY']
    
    aws_access_key_id_json_e = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key_json_e = os.getenv('AWS_SECRET_ACCESS_KEY')
    
    # Initialize the Cognito client
    client = boto3.client(
        'cognito-idp', 
        region_name=os.getenv('AWS_REGION'), 
        aws_access_key_id=aws_access_key_id_json_e, 
        aws_secret_access_key=aws_secret_access_key_json_e
    )
    
    user_pool_id = os.getenv('USER_POOL_ID')
    
    users = []
    response = client.list_users(UserPoolId=user_pool_id)
    
    while True:
        users.extend(response['Users'])
        if 'PaginationToken' in response:
            response = client.list_users(UserPoolId=user_pool_id, PaginationToken=response['PaginationToken'])
        else:
            break
    
    # Create the HttpResponse object with the appropriate CSV header
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="cognito_users.csv"'
    
    writer = csv.writer(response)
    # Write the header
    writer.writerow(['Username', 'Email'])
    
    # Write the user data
    for user in users:
        username = user['Username']
        email = next((attr['Value'] for attr in user['Attributes'] if attr['Name'] == 'email'), 'N/A')
        writer.writerow([username, email])
    
    return response



# Function to list users
def list_users():
    user_pool_id = os.getenv('USER_POOL_ID')
    region = os.getenv('AWS_REGION')
    client = boto3.client('cognito-idp', region_name=region)
    users = []
    response = client.list_users(UserPoolId=user_pool_id)
    users.extend(response['Users'])

    while 'PaginationToken' in response:
        response = client.list_users(UserPoolId=user_pool_id, PaginationToken=response['PaginationToken'])
        users.extend(response['Users'])

    return users

def list_users_api(request):
    
    print("Inside list_users_api")
    
    # Fetch user information
    user_data = list_users()

    # Extract usernames and email addresses
    user_info = [{'Username': user['Username'], 'Email': next((attr['Value'] for attr in user['Attributes'] if attr['Name'] == 'email'), None)} for user in user_data]

    # Output the user information
    with open('users.csv', 'w') as f:
        f.write('Username,Email\n')
        for user in user_info:
            f.write(f"{user['Username']},{user['Email']}\n")
    print("User information has been saved to users.csv")
        
        

def test_cookie(request):   
    if not request.COOKIES.get('team'):
        response = HttpResponse("Visiting for the first time.")
        response.set_cookie('team', 'barcelona')
        return response
    else:
        all_cookies = request.COOKIES
        print("All cookies:", all_cookies)
        return HttpResponse("Your favorite team is {}".format(request.COOKIES['team']))

def verify_jwt_token(token, user_pool_id, region):
    """
    Verifies a JWT token using the Cognito public key retrieved from the JWKS endpoint.

    Args:
        token: The JWT token string.
        user_pool_id: Your Cognito user pool ID.
        region: The AWS region where your Cognito user pool resides.

    Returns:
        A dictionary containing the decoded claims if successful, None otherwise.

    Raises:
        jwt.exceptions.DecodeError: If the token is invalid.
        requests.exceptions.RequestException: If there's an error fetching the JWKS.
    """
    print ('Inside verify_jwt_token')
    print ('region is '+ region)
    jwks_url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
    print("Received JWT token:", token)
    try:
        # Validate the JWT format
        if token.count('.') != 2:
            raise ValueError("Invalid JWT token format. A valid JWT should contain 3 parts separated by dots.")

        # Fetch JWKS from the endpoint
        response = requests.get(jwks_url)
        response.raise_for_status()  # Raise exception for non-2xx status codes

        jwks_client = PyJWKClient(jwks_url)

        # Extract the signing key
        signing_key = jwks_client.get_signing_key_from_jwt(token).key

        # Decode the token using the signing key
        payload = jwt.decode(token, signing_key, algorithms=['RS256'], options={"verify_exp": True})

        return payload
    except ValueError as e:
        print(f"JWT format error: {e}")
        raise
    except requests.exceptions.RequestException as e:
        print(f"Error fetching JWKS: {e}")
        raise
    except DecodeError as e:
        print(f"Error decoding JWT: {e}")
        raise InvalidTokenError("Invalid token")
    except ExpiredSignatureError as e:
        print(f"Expired token: {e}")
        raise InvalidTokenError("Expired token")
    except InvalidSignatureError as e:
        print(f"Invalid signature: {e}")
        raise InvalidTokenError("Invalid token signature")
    except InvalidTokenError as e:
        print(f"Invalid token: {e}")
        raise

def verify_jwt_token1(token, user_pool_id, region):
    """
    Verifies a JWT token using the Cognito public key retrieved from JWKS endpoint.

    Args:
        token: The JWT token string.
        user_pool_id: Your Cognito user pool ID.
        region: The AWS region where your Cognito user pool resides.

    Returns:
        A dictionary containing the decoded claims if successful, None otherwise.

    Raises:
        jwt.exceptions.DecodeError: If the token is invalid.
        requests.exceptions.RequestException: If there's an error fetching the JWKS.
    """
    jwks_url = f"https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json"
    try:
        response = requests.get(jwks_url)
        response.raise_for_status()  # Raise exception for non-2xx status codes

        jwks = response.json()
        signing_key_header = RSAAlgorithm.prepare('RS256')
        signing_key = jwks['keys'][0]['n']

        payload = jwt.decode(token, signing_key, algorithms=['RS256']) #header=signing_key_header)
        return payload
    except requests.exceptions.RequestException as e:
        raise  # Re-raise the exception for handling in the view function


# Function to encrypt file content using AWS KMS
def encrypt_file_with_kms1(file_content, credentials, region):
    # Replace with your KMS key ID or ARN
    kms_key_id = os.getenv('AWS_KMS_KEY_ID') 
    
    if not kms_key_id:
        raise ValueError("KMS key ID must be set in the environment variable AWS_KMS_KEY_ID")
        
 

    # Initialize KMS client with temporary credentials
    # kms = boto3.client('kms', aws_access_key_id=kms_client['AccessKeyId'],
                       # aws_secret_access_key=kms_client['SecretAccessKey'],
                       # aws_session_token=kms_client['SessionToken'])
    kms = boto3.client('kms',
                       aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'],
                       region_name=region)                   

    # Encrypt file content using KMS
    response = kms.encrypt(
        KeyId=kms_key_id,
        Plaintext=file_content,
    )

    encrypted_content = response['CiphertextBlob']
    return encrypted_content


def encrypt_file_with_kms(file_content, credentials, region):
    """
    Encrypts the provided file content using AWS KMS and envelope encryption with the cryptography library.
    
    :param file_content: Content of the file to be encrypted (in bytes).
    :param credentials: Dictionary containing temporary AWS credentials.
    :param region: AWS region where KMS key is located.
    :return: Dictionary containing the encrypted content, encrypted DEK, and IV.
    """
    
    # Get the environment variable
    aws_kms_key_json = os.getenv('AWS_KMS_KEY_ID')

    # Parse the JSON string
    aws_kms_key_dict = json.loads(aws_kms_key_json)

    # Extract the value
    aws_kms_key_e = aws_kms_key_dict['AWS_KMS_KEY_ID']
    
    kms_key_id = aws_kms_key_e
    
    if not kms_key_id:
        raise ValueError("KMS key ID must be set in the environment variable AWS_KMS_KEY_ID")

    # Initialize KMS client with temporary credentials
    kms = boto3.client('kms',
                       aws_access_key_id=credentials['AccessKeyId'],
                       aws_secret_access_key=credentials['SecretAccessKey'],
                       aws_session_token=credentials['SessionToken'],
                       region_name=region)

    # Generate a data encryption key (DEK)
    response = kms.generate_data_key(KeyId=kms_key_id, KeySpec='AES_256')
    plaintext_dek = response['Plaintext']  # This is the raw DEK (symmetric key)
    encrypted_dek = response['CiphertextBlob']  # This is the DEK encrypted by KMS

    # Encrypt the file content using AES encryption with the DEK
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(plaintext_dek), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the file content to be a multiple of the AES block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_content = padder.update(file_content) + padder.finalize()

    # Encrypt the padded content
    encrypted_content = encryptor.update(padded_content) + encryptor.finalize()

    return {
        'encrypted_content': encrypted_content,
        'encrypted_dek': encrypted_dek,
        'iv': iv
    }

@csrf_exempt
def view_decrypted_file(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if not auth_header:
        return JsonResponse({'error': 'Missing authorization header'}, status=401)

    # Extract token from header (assuming 'Bearer' prefix)
    parts = auth_header.split()
    if parts[0] != 'Bearer' or len(parts) != 2:
        return JsonResponse({'error': 'Invalid authentication header'}, status=401)
    
    

    token = parts[1]
    user_pool_id = os.getenv('USER_POOL_ID')
    region = os.getenv('AWS_REGION')
    
    
    # Get the environment variable
    aws_access_key_id_json = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key_json = os.getenv('AWS_SECRET_ACCESS_KEY')

    # Parse the JSON string
    aws_access_key_id_dict = json.loads(aws_access_key_id_json)
    aws_secret_access_key_dict = json.loads(aws_secret_access_key_json)

    # Extract the value
    aws_access_key_id_e = aws_access_key_id_dict['AWS_ACCESS_KEY_ID']
    aws_secret_access_key_e = aws_secret_access_key_dict['AWS_SECRET_ACCESS_KEY']
      
    region = os.getenv('AWS_REGION')
    
    BUCKET_NAME = os.getenv('BUCKET_NAME') 
    AWS_ACCESS_KEY_ID = aws_access_key_id_e
    AWS_SECRET_ACCESS_KEY = aws_secret_access_key_e
      
    print("region is "+ region)
    print("AWS_ACCESS_KEY_ID " + AWS_ACCESS_KEY_ID)
    print("AWS_SECRET_ACCESS_KEY " + AWS_SECRET_ACCESS_KEY)
    
    
    # Verify the token
    try:
        payload = verify_jwt_token(token, user_pool_id, region)
    except Exception as e:
        return JsonResponse({'error': 'Token verification failed', 'message': str(e)}, status=401)
    
    # Access user information from the payload (e.g., username)
    username = payload.get('username')
    if not username:
        return JsonResponse({'error': 'Invalid token payload'}, status=401)
        
    print("username "+username)    
    request_body = json.loads(request.body)
    file_id = request_body.get('file_id')
    print("file_id "+file_id)
    if not file_id:
        return JsonResponse({'error': 'Missing file_id in request body'}, status=400)

    try:
        request_body = json.loads(request.body)
        file_id = request_body.get('file_id')
        print("file_id "+file_id)
        if not file_id:
            return JsonResponse({'error': 'Missing file_id in request body'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)
    
    print("after file_id ")
    bucket_name = os.getenv('BUCKET_NAME')
    region_name = os.getenv('AWS_REGION')
    
    # Initialize AWS clients
    s3_client = boto3.client('s3', 
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY, 
            region_name=region)
    #sts_client = boto3.client('sts', region_name=os.getenv('AWS_REGION'))    
    

    #s3_client = boto3.client('s3', region_name=region)
    s3_key = f"{file_id}"
    
    response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
    encrypted_content = response['Body'].read()
    metadata_str = response['Metadata']['metadata']
    metadata = json.loads(metadata_str)
    print("metadata")
    print(metadata)

    encrypted_encryption_key_base64 = metadata['encryption_key']
    encrypted_encryption_key = b64decode(encrypted_encryption_key_base64)

    kms_client = boto3.client('kms', region_name=region_name, aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY)

    try:
        response = kms_client.decrypt(
            CiphertextBlob=encrypted_encryption_key
        )
        encryption_key = response['Plaintext']
    except Exception as e:
        return JsonResponse({'error': f"KMS Decryption failed: {str(e)}"}, status=500)

    backend = default_backend()
    iv = b64decode(metadata['iv'])
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_decrypted_content = unpadder.update(decrypted_content) + unpadder.finalize()

    file_type = magic.from_buffer(unpadded_decrypted_content, mime=True)
    print("File type detected:", file_type)

    if file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
        try:
            docx_content = extract_docx_text(unpadded_decrypted_content)
            return JsonResponse({'file_content': docx_content})
        except Exception as e:
            return JsonResponse({'error': f'Failed to extract text from .docx: {str(e)}'}, status=500)

    elif file_type.startswith('text/'):
        try:
            decoded_content = unpadded_decrypted_content.decode('utf-8')
            return JsonResponse({'file_content': decoded_content})
        except UnicodeDecodeError:
            return JsonResponse({'error': 'Failed to decode text content'}, status=400)

    elif file_type == 'application/pdf':
        try:
            # Extract PDF content
            pdf_content = extract_pdf_text(unpadded_decrypted_content)
            return JsonResponse({'file_content': pdf_content})
        except Exception as e:
            return JsonResponse({'error': f'Failed to extract text from PDF: {str(e)}'}, status=500)

    else:
        encoded_content = b64encode(unpadded_decrypted_content).decode('utf-8')
        return JsonResponse({'file_content': encoded_content})

def extract_pdf_text(pdf_data):
    """
    Extracts text from decrypted PDF content.
    """
    pdf_reader = PdfReader(BytesIO(pdf_data))
    text = ''
    for page in pdf_reader.pages:
        text += page.extract_text()
    return text

def extract_docx_text(docx_data):
    """
    Extracts text from decrypted DOCX content.
    """
    from zipfile import ZipFile
    from xml.etree.ElementTree import XML

    with ZipFile(BytesIO(docx_data)) as docx:
        with docx.open('word/document.xml') as document_xml:
            xml_content = document_xml.read()
    
    return ''.join(XML(xml_content).itertext())


@csrf_exempt
def view_decrypted_file_bkp(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if not auth_header:
        return JsonResponse({'error': 'Missing authorization header'}, status=401)

    # Extract token from header (assuming 'Bearer' prefix)
    parts = auth_header.split()
    if parts[0] != 'Bearer' or len(parts) != 2:
        return JsonResponse({'error': 'Invalid authentication header'}, status=401)
    
    token = parts[1]
    user_pool_id = os.getenv('USER_POOL_ID')
    region = os.getenv('AWS_REGION')
    
    # Verify the token
    try:
        payload = verify_jwt_token(token, user_pool_id, region)
    except Exception as e:
        return JsonResponse({'error': 'Token verification failed', 'message': str(e)}, status=401)
    
    # Access user information from the payload (e.g., username)
    username = payload.get('username')
    if not username:
        return JsonResponse({'error': 'Invalid token payload'}, status=401)
        
    print("username "+username)    
    request_body = json.loads(request.body)
    file_id = request_body.get('file_id')
    print("file_id "+file_id)
    if not file_id:
        return JsonResponse({'error': 'Missing file_id in request body'}, status=400)

    # Parse the request body to get the file_id
    try:
        request_body = json.loads(request.body)
        file_id = request_body.get('file_id')
        print("file_id "+file_id)
        if not file_id:
            return JsonResponse({'error': 'Missing file_id in request body'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)
    
    print("after file_id ")
    # Retrieve the S3 bucket name and region from environment variables
    bucket_name = os.getenv('BUCKET_NAME')
    region_name = os.getenv('AWS_REGION')

    # Initialize S3 client
    s3_client = boto3.client('s3', region_name=region_name)

    # Define the key in S3 where the file is stored
    s3_key = f"{file_id}"
    
    # Fetch the object metadata and the encrypted file content from S3
    response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
    encrypted_content = response['Body'].read()
    metadata_str = response['Metadata']['metadata']
    metadata = json.loads(metadata_str)
    print("metadata")
    print(metadata)

    # Extract the encrypted encryption key (DEK) from the metadata
    encrypted_encryption_key_base64 = metadata['encryption_key']
    encrypted_encryption_key = b64decode(encrypted_encryption_key_base64)  # Decode the base64 encrypted DEK



    # Initialize KMS client
    kms_client = boto3.client('kms', region_name=region_name)

    # Decrypt the encrypted DEK using KMS
    try:
        response = kms_client.decrypt(
            CiphertextBlob=encrypted_encryption_key
        )
        encryption_key = response['Plaintext']
    except Exception as e:
        return JsonResponse({'error': f"KMS Decryption failed: {str(e)}"}, status=500)


    # Initialize the decryption cipher with the decrypted key
    backend = default_backend()
    iv = b64decode(metadata['iv'])  # Use the IV from metadata
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    # Decrypt the content
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()
    

    # Unpad the decrypted content (assuming padding was applied during encryption)
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_decrypted_content = unpadder.update(decrypted_content) + unpadder.finalize()

    # Determine the file type
    file_type = magic.from_buffer(unpadded_decrypted_content, mime=True)
    print("File type detected:", file_type)

    if file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
        docx_content = extract_docx_text(unpadded_decrypted_content)
        return JsonResponse({'file_content': docx_content})
        # Handle .docx files
        try:
            docx_content = extract_docx_text(unpadded_decrypted_content)
            return JsonResponse({'file_content': docx_content})
        except Exception as e:
            return JsonResponse({'error': f'Failed to extract text from .docx: {str(e)}'}, status=500)

    elif file_type.startswith('text/'):
        # If the file is a text file, decode and return it as text
        try:
            decoded_content = unpadded_decrypted_content.decode('utf-8')
            return JsonResponse({'file_content': decoded_content})
        except UnicodeDecodeError:
            return JsonResponse({'error': 'Failed to decode text content'}, status=400)
    else:
        # For binary files, return the content in base64 encoding
        encoded_content = b64encode(unpadded_decrypted_content).decode('utf-8')
        return JsonResponse({'file_content': encoded_content})

def extract_docx_text(docx_data):
    """Extracts text from a .docx file given its binary data."""
    document = Document(BytesIO(docx_data))
    text = []
    for paragraph in document.paragraphs:
        text.append(paragraph.text)
    return '\n'.join(text)
    
    print("Inside extract_docx_text")
    
    # Fetch the object metadata and the encrypted file content from S3
    response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
    encrypted_content = response['Body'].read()
    metadata = response['Metadata']

    # Extract the encryption key from the metadata
    if 'encryption_key' not in metadata:
        return JsonResponse({'error': 'Encryption key not found in metadata'}, status=400)

    encryption_key_base64 = metadata['encryption_key']
    encryption_key = b64decode(encryption_key_base64)  # Decode the base64 encryption key

    # Initialize the decryption cipher
    backend = default_backend()
    iv = b'\0' * 16  # Ensure this matches the IV used during encryption
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    # Decrypt the content
    decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

    # Unpad the decrypted content (assuming padding was applied during encryption)
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_decrypted_content = unpadder.update(decrypted_content) + unpadder.finalize()

    # Determine the file type
    file_type = magic.from_buffer(unpadded_decrypted_content, mime=True)
    print("File type detected:", file_type)

    if file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
        # Handle .docx files
        try:
            docx_content = extract_docx_text(unpadded_decrypted_content)
            return JsonResponse({'file_content': docx_content})
        except Exception as e:
            return JsonResponse({'error': f'Failed to extract text from .docx: {str(e)}'}, status=500)

    elif file_type.startswith('text/'):
        # If the file is a text file, decode and return it as text
        try:
            decoded_content = unpadded_decrypted_content.decode('utf-8')
            return JsonResponse({'file_content': decoded_content})
        except UnicodeDecodeError:
            return JsonResponse({'error': 'Failed to decode text content'}, status=400)
    else:
        # For binary files, return the content in base64 encoding
        encoded_content = b64encode(unpadded_decrypted_content).decode('utf-8')
        return JsonResponse({'file_content': encoded_content})

    try:
        # Fetch the object metadata and the encrypted file content from S3
        response = s3_client.get_object(Bucket=bucket_name, Key=s3_key)
        encrypted_content = response['Body'].read()
        metadata = response['Metadata']

        # Extract the encryption key from the metadata
        if 'encryption_key' not in metadata:
            return JsonResponse({'error': 'Encryption key not found in metadata'}, status=400)

        encryption_key_base64 = metadata['encryption_key']
        encryption_key = b64decode(encryption_key_base64)  # Decode the base64 encryption key

        # Initialize the decryption cipher
        backend = default_backend()
        iv = b'\0' * 16  # Ensure this matches the IV used during encryption
        cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()

        # Decrypt the content
        decrypted_content = decryptor.update(encrypted_content) + decryptor.finalize()

        # Unpad the decrypted content (assuming padding was applied during encryption)
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_decrypted_content = unpadder.update(decrypted_content) + unpadder.finalize()

        # Determine the file type
        file_type = magic.from_buffer(unpadded_decrypted_content, mime=True)
        print("File type detected:", file_type)

        if file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            # Handle .docx files
            try:
                docx_content = extract_docx_text(unpadded_decrypted_content)
                return JsonResponse({'file_content': docx_content})
            except Exception as e:
                return JsonResponse({'error': f'Failed to extract text from .docx: {str(e)}'}, status=500)

        elif file_type.startswith('text/'):
            # If the file is a text file, decode and return it as text
            try:
                decoded_content = unpadded_decrypted_content.decode('utf-8')
                return JsonResponse({'file_content': decoded_content})
            except UnicodeDecodeError:
                return JsonResponse({'error': 'Failed to decode text content'}, status=400)
        else:
            # For binary files, return the content in base64 encoding
            encoded_content = b64encode(unpadded_decrypted_content).decode('utf-8')
            return JsonResponse({'file_content': encoded_content})

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Global variable to hold credentials
creds = None

# Function to initiate Google OAuth2 flow

@csrf_exempt
def google_drive_auth(request):
    flow = Flow.from_client_secrets_file(
        settings.GOOGLE_DRIVE_CLIENT_SECRETS,
        scopes=['https://www.googleapis.com/auth/drive.file'],
        redirect_uri=request.build_absolute_uri(reverse('oauth2callback'))
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # Debugging: log the state and authorization URL
    print("State:", state)
    print("Authorization URL:", authorization_url)
    
    print("Session before setting state:", request.session.items())


    request.session['google_drive_auth_state'] = state
    request.session.modified = True  # Explicitly mark session as modified
    
    print("Session after setting state:", request.session.items())
    
    return redirect(authorization_url)

def oauth2callback(request):
    state = request.session.get('google_drive_auth_state')
    
    # Log the session details and state
    print("Session during callback:", request.session.items())
    print("Retrieved State:", state)


    if not state:
        print("No state found in session.")
        return redirect('http://localhost:3000/profile')  # Redirect to an error page or handle accordingly

    flow = Flow.from_client_secrets_file(
        settings.GOOGLE_DRIVE_CLIENT_SECRETS,
        scopes=['https://www.googleapis.com/auth/drive.file'],
        state=state,
        redirect_uri=request.build_absolute_uri(reverse('oauth2callback'))
    )

    # Fetch the token using the authorization response URL
    flow.fetch_token(authorization_response=request.build_absolute_uri())

    creds = flow.credentials
    request.session['google_drive_creds'] = creds.to_json()

    # Redirect to the React app's user profile page
    return redirect('http://localhost:3000/profile')

    
    
@csrf_exempt
def upload_to_google_drive(request):
    global creds
    
    # Check for existing credentials in the session
    creds_json = request.session.get('google_drive_creds', None)
    if creds_json:
        creds = service_account.Credentials.from_authorized_user_info(json.loads(creds_json))
    
    if not creds or not creds.valid:
        return redirect('google_drive_auth')
    
    if request.method == 'POST' and request.FILES.get('file'):
        file = request.FILES['file']
        file_path = default_storage.save(file.name, file)

        drive_service = build('drive', 'v3', credentials=creds)

        file_metadata = {'name': file.name}
        media = MediaIoBaseUpload(io.BytesIO(file.read()), mimetype=file.content_type)
        
        file_uploaded = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()
        
        # Remove the temporary file
        os.remove(file_path)
        
        return JsonResponse({"file_id": file_uploaded.get('id')})
    
    return HttpResponse(status=400)

@csrf_exempt
def list_google_drive_files(request):
    global creds
    creds_json = request.session.get('google_drive_creds', None)
    if creds_json:
        creds = service_account.Credentials.from_authorized_user_info(json.loads(creds_json))
    
    if not creds or not creds.valid:
        return redirect('google_drive_auth')
    
    drive_service = build('drive', 'v3', credentials=creds)
    
    results = drive_service.files().list(
        pageSize=10, fields="nextPageToken, files(id, name, mimeType, modifiedTime)"
    ).execute()
    
    items = results.get('files', [])
    
    return JsonResponse({'files': items})



@csrf_exempt
def upload_file(request):
  # Get the environment variable
  aws_access_key_id_json = os.getenv('AWS_ACCESS_KEY_ID')
  aws_secret_access_key_json = os.getenv('AWS_SECRET_ACCESS_KEY')

  # Parse the JSON string
  aws_access_key_id_dict = json.loads(aws_access_key_id_json)
  aws_secret_access_key_dict = json.loads(aws_secret_access_key_json)

  # Extract the value
  aws_access_key_id_e = aws_access_key_id_dict['AWS_ACCESS_KEY_ID']
  aws_secret_access_key_e = aws_secret_access_key_dict['AWS_SECRET_ACCESS_KEY']
  
  region = os.getenv('AWS_REGION')
  
  BUCKET_NAME = os.getenv('BUCKET_NAME') 
  AWS_ACCESS_KEY_ID = aws_access_key_id_e
  AWS_SECRET_ACCESS_KEY = aws_secret_access_key_e
  
  print("region is "+ region)
  print("AWS_ACCESS_KEY_ID " + AWS_ACCESS_KEY_ID)
  print("AWS_SECRET_ACCESS_KEY " + AWS_SECRET_ACCESS_KEY)
  
  # Initialize AWS clients
  s3_client = boto3.client('s3', 
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY, 
        region_name=region)
  #sts_client = boto3.client('sts', region_name=os.getenv('AWS_REGION'))    
  # Initialize the STS client
  sts_client = boto3.client('sts',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=region
    )
  print("After initialize")  
  if request.method == 'POST':
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    
    if not auth_header:
        return JsonResponse({'error': 'Missing authorization header'}, status=401)

    # Extract token from header (assuming 'Bearer' prefix)
    parts = auth_header.split()
    if parts[0] != 'Bearer':
        return JsonResponse({'error': 'Invalid authentication header'}, status=401)
    token = parts[1]

    # Replace with your actual Cognito user pool ID and region
    user_pool_id = os.getenv('USER_POOL_ID')
    region = os.getenv('AWS_REGION')
    
    # Replace with your bucket name and credentials (store securely)
    
    
    
      
    """Uploads a file to the S3 bucket."""
    s3 = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY_ID, 
                     aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
                     region_name=region)
    #try:
    # Assume role to get temporary credentials
    assumed_role = sts_client.assume_role(
        RoleArn='arn:aws:iam::471112980832:role/SYMRKMSRole',  # Replace with your IAM role ARN
        RoleSessionName='Session1'  # Unique session name
    )
    print("After assume role") 

    # Extract temporary credentials
    credentials = assumed_role['Credentials']

    # Initialize AWS KMS client with temporary credentials
    # kms_client = boto3.client('kms',
                              # aws_access_key_id=credentials['AccessKeyId'],
                              # aws_secret_access_key=credentials['SecretAccessKey'],
                              # aws_session_token=credentials['SessionToken'],
                              # region_name=region)




    payload = verify_jwt_token(token, user_pool_id, region)
    
    if not payload:
        return JsonResponse({'error': 'Invalid token'}, status=401)

    # Access user information from the payload (e.g., user ID)
    user_id = payload.get('username')

    # ... process data based on user_id
    # Handle file upload
    uploaded_file = request.FILES.get('file')
    if not uploaded_file:
        return JsonResponse({'error': 'No file uploaded'}, status=400)
    
    filename = uploaded_file.name  
    
    # Add folder path to filename (replace "folder_name" with your desired folder)
    filename = f"{user_id}/{filename}"
    
    
    # Encrypt the file content before uploading
    file_content = uploaded_file.read()
    encrypted_data  = encrypt_file_with_kms(file_content, credentials, region)
    encrypted_content = b64encode(encrypted_data['encrypted_content'])
    
    print("Encrypted Content:", b64encode(encrypted_data['encrypted_content']))
    print("Encrypted DEK:", b64encode(encrypted_data['encrypted_dek']))
    print("IV:", b64encode(encrypted_data['iv']))

    # Prepare metadata
    metadata = {
        'original_filename': uploaded_file.name,
        'encrypted_file_size': len(encrypted_content),  # Assuming this is the encrypted content length
        'user_id': user_id,
        'upload_date': str(datetime.now()),
        'encryption_key': b64encode(encrypted_data['encrypted_dek']).decode('utf-8'),  # Store encrypted DEK
        'iv': b64encode(encrypted_data['iv']).decode('utf-8')  # Store IV
    }

    # Convert metadata to JSON string
    metadata_json = json.dumps(metadata)
    
    
    try:
        # Create a BytesIO object from the encrypted content
        encrypted_content_io = io.BytesIO(encrypted_data['encrypted_content'])

        # Upload using upload_fileobj
        s3_client.upload_fileobj(
            encrypted_content_io,
            BUCKET_NAME,
            filename,
            ExtraArgs={'Metadata': {'metadata': metadata_json}}
        )

        return JsonResponse({'message': f'File {filename} encrypted and uploaded  successfully!'})
    except boto3.exceptions.S3UploadFailedError as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    # Upload encrypted content to S3 bucket
    # s3_client.put_object(Body=encrypted_content, Bucket=BUCKET_NAME, Key=f"{user_id}/{filename}",
                         # Metadata={'metadata': metadata_json})
    
    

    # Upload file to S3 bucket
    #s3.upload_fileobj(uploaded_file, BUCKET_NAME, filename)
    #return JsonResponse({'message': f'File {filename} encrypted and uploaded successfully!'})
        
    #except ClientError as e:
    #    print("Inside Client Error")
     #   return JsonResponse({'error': str(e)}, status=400)

def get_aws_credentials():
    secret_name = 'AWS_Access'
    region_name = 'us-west-2'

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)
    get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    print('get_secret_value_response '+get_secret_value_response)
    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        print(f"Error retrieving secret: {e}")
        return None, None, None

    # Parse the secret
    secret = get_secret_value_response['SecretString']
    secret_dict = json.loads(secret)

    # Extract credentials
    aws_access_key_id = secret_dict['AWS_ACCESS_KEY_ID']
    aws_secret_access_key = secret_dict['AWS_SECRET_ACCESS_KEY']
    aws_region = secret_dict['AWS_REGION']

    return aws_access_key_id, aws_secret_access_key, region

@csrf_exempt
def list_user_files(request):
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    # Get the environment variable
    aws_access_key_id_json = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key_json = os.getenv('AWS_SECRET_ACCESS_KEY')

    # Parse the JSON string
    aws_access_key_id_dict = json.loads(aws_access_key_id_json)
    aws_secret_access_key_dict = json.loads(aws_secret_access_key_json)

    #Extract the value
    aws_access_key_id_e = aws_access_key_id_dict['AWS_ACCESS_KEY_ID']
    aws_secret_access_key_e = aws_secret_access_key_dict['AWS_SECRET_ACCESS_KEY']
    
    # aws_access_key_id_e = os.getenv('AWS_ACCESS_KEY_ID')
    # aws_secret_access_key_e = os.getenv('AWS_SECRET_ACCESS_KEY')

    print('aws_access_key_id_e ' + aws_access_key_id_e)
    print('aws_secret_access_key_e ' + aws_secret_access_key_e)
    
    
    if not auth_header:
        return JsonResponse({'error': 'Missing authorization header'}, status=401)
    
    token = auth_header.split()[1] if 'Bearer' in auth_header else auth_header
    user_pool_id = os.getenv('USER_POOL_ID')
    region = 'us-west-2'

    # Verify the JWT token
    payload = verify_jwt_token(token, user_pool_id, region)
    
    if not payload:
        return JsonResponse({'error': 'Invalid token'}, status=401)

    user_id = payload.get('username')  # Extract user ID from the token payload
    #aws_access_key_id_f, aws_secret_access_key_f, region_f = get_aws_credentials()
    

    # Initialize S3 client
    s3_client = boto3.client('s3', aws_access_key_id=aws_access_key_id_e,
                             aws_secret_access_key=aws_secret_access_key_e,
                             region_name=region)
    
    # s3_client = boto3.client('s3', aws_access_key_id=aws_access_key_id_f,
                             # aws_secret_access_key=aws_secret_access_key_f,
                             # region_name=region_f)

    # Define the user's directory path in S3
    user_prefix = f"{user_id}/"
    
    
    bucket = "symr-user-bucket"


    # List objects in the user's directory
    response = s3_client.list_objects(Bucket="symr-user-bucket", Prefix=user_prefix)

    # Extract file names
    files = []
    if 'Contents' in response:
        for obj in response['Contents']:
            files.append({'Key': obj['Key'], 'LastModified': obj['LastModified'].isoformat()})

    return JsonResponse({'files': files})


@csrf_exempt
def delete_file(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if not auth_header:
        return JsonResponse({'error': 'Missing authorization header'}, status=401)

    # Extract token from header (assuming 'Bearer' prefix)
    parts = auth_header.split()
    if parts[0] != 'Bearer' or len(parts) != 2:
        return JsonResponse({'error': 'Invalid authentication header'}, status=401)
    
    token = parts[1]
    user_pool_id = os.getenv('USER_POOL_ID')
    region = os.getenv('AWS_REGION')
    
    # Get the environment variable
    aws_access_key_id_json = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key_json = os.getenv('AWS_SECRET_ACCESS_KEY')

    # Parse the JSON string
    aws_access_key_id_dict = json.loads(aws_access_key_id_json)
    aws_secret_access_key_dict = json.loads(aws_secret_access_key_json)

    # Extract the value
    aws_access_key_id_e = aws_access_key_id_dict['AWS_ACCESS_KEY_ID']
    aws_secret_access_key_e = aws_secret_access_key_dict['AWS_SECRET_ACCESS_KEY']
    
    # aws_access_key_id_e = os.getenv('AWS_ACCESS_KEY_ID')
    # aws_secret_access_key_e = os.getenv('AWS_SECRET_ACCESS_KEY')
      
    region = os.getenv('AWS_REGION')
    
    BUCKET_NAME = os.getenv('BUCKET_NAME') 
    AWS_ACCESS_KEY_ID = aws_access_key_id_e
    AWS_SECRET_ACCESS_KEY = aws_secret_access_key_e
      
    print("region is "+ region)
    print("AWS_ACCESS_KEY_ID " + AWS_ACCESS_KEY_ID)
    print("AWS_SECRET_ACCESS_KEY " + AWS_SECRET_ACCESS_KEY)
    
    
    # Verify the token
    try:
        payload = verify_jwt_token(token, user_pool_id, region)
    except Exception as e:
        return JsonResponse({'error': 'Token verification failed', 'message': str(e)}, status=401)
    
    # Access user information from the payload (e.g., username)
    username = payload.get('username')
    if not username:
        return JsonResponse({'error': 'Invalid token payload'}, status=401)
        
    print("username "+username)    
   
    
    request_body = json.loads(request.body)
    file_id = request_body.get('file_id')
    filename = request_body.get('file_name')
    print("file_id "+file_id)
    if not file_id:
        return JsonResponse({'error': 'Missing file_id in request body'}, status=400)

    try:
        request_body = json.loads(request.body)
        file_id = request_body.get('file_id')
        print("file_id "+file_id)
        if not file_id:
            return JsonResponse({'error': 'Missing file_id in request body'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)
    
    print("after file_id ")
    bucket_name = os.getenv('BUCKET_NAME')
    region_name = os.getenv('AWS_REGION')
    
    # Initialize AWS clients
    s3_client = boto3.client('s3', 
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY, 
            region_name=region)
    #sts_client = boto3.client('sts', region_name=os.getenv('AWS_REGION'))    
    

    #s3_client = boto3.client('s3', region_name=region)
    s3_key = f"{file_id}"
    
    response = s3_client.delete_object(Bucket=bucket_name, Key=s3_key)
    
    try:
        s3_client.delete_object(Bucket=bucket_name, Key=s3_key)
        return JsonResponse({'message': f'File {filename} deleted successfully!'})
    except boto3.exceptions.S3UploadFailedError as e:
        return JsonResponse({'error': str(e)}, status=400)
    
    


@csrf_exempt
def get_csrf_token(request):
    if not request.COOKIES.get('custom_csrf_token'):
        csrf_token = get_token(request)
        request.session['csrftoken'] = csrf_token
        response = JsonResponse({'csrftoken': csrf_token})
        #response = HttpResponse(content=csrf_token, content_type='text/plain')
        #response = HttpResponse("Visiting for the first time." )
        response.set_cookie(
            key='csrftoken',
            value=csrf_token,
            path=settings.CSRF_COOKIE_PATH,
            secure=settings.CSRF_COOKIE_SECURE,
            httponly=False,
            samesite=None,
            domain='localhost'
        )
        print("Cookie set:", response.cookies['csrftoken'].value)  # Debug print  
        return response
    else:
        all_cookies = request.COOKIES
        print("All cookies:", all_cookies)
        response = HttpResponse("Your favorite team is {}".format(request.COOKIES['csrftoken']))
        print("Response headers:", response.headers)
        return response

# Create your views here.


def calculatePMT(ir, np, pv, fv):
    """
    ir - interest rate per period
    np - number of periods
    pv - present value
    fv - future value (residual value)
    """
    pmt = (ir * (pv * math.pow((1 + ir), np) + fv)) / ((1 + ir) * (math.pow((1 + ir), np) - 1))
    print("pmt:", pmt)
    return pmt

@csrf_exempt
#@allow_all_origins
def commonResults(request):
    # Logic to process the request
    print("Hi")    
    if request.method == 'POST':
        #all_cookies = request.COOKIES
        #print("All cookies:", all_cookies)
        
        # Get the CSRF token from the request headers
        #received_token = request.headers.get('X-CSRFToken')
        
        # Get the CSRF token generated by Django
        #django_token = value = request.COOKIES['csrftoken']
        
        #print('received_token '+received_token)
        #print('django_token '+django_token)
        #print(django_token)
        
        # Validate the received token
        #if received_token != django_token:
            #return HttpResponseForbidden("CSRF token mismatch")
        
        contextBH = {}
        
        data = json.loads(request.body.decode('utf-8'))
        formData = data.get('data', {})
        form1Data = data.get('data1', {})
        tokenData = data.get('csrfmiddlewaretoken', {})
        print("tokenData:", tokenData)
        #print('csrfmiddlewaretoken:', tokenData.get('csrfmiddlewaretoken', 'None'))
        print("Data received:", data)
        M1 = formData.get('M1', 0)
        M1 = 0 if M1 is None or M1 == '' else float(M1)        
        print(M1)
        
        M2 = formData.get('M2', 0)#Monthly Expenses
        M2 = 0 if M2 is None or M2 == '' else float(M2)
       
        M3 = formData.get('M3', 0)  #Monthly Debt
        M3 = 0 if M3 is None or M3 == ''else float(M3)

        M4 = formData.get('M4', 0)  #Housing
        M4 = 0 if M4 is None or M4 == ''else float(M4)

        T1 = formData.get('T1', 0)  #
        T1 = 0 if T1 is None or T1 == ''else float(T1)

        T2 = formData.get('T2', 0)  #Investments
        T2 = 0 if T2 is None or T2 == ''else float(T2)

        T3 = formData.get('T3', 0)  #Total Debt
        T3 = 1 if T3 is None or T3 == '' else float(T3)

        T4 = formData.get('T4', 0)  #Max APR for Debt
        T4 = 0 if T4 is None or T4 == '' else T4

        EFT = form1Data.get('EFT', 0)  #Emergency Fund Threshold
        EFT = 0 if EFT is None or EFT == '' else float(EFT)
        print("EFT "+ format(EFT))

        DTI = form1Data.get('DTI', '')  #Debt To Income Threshold
        DTI = 0 if DTI is None or DTI == '' else float(DTI)
        print("DTI "+ format(DTI))

        DTA = form1Data.get('DTA', '')  #Debt To Assets Threshold
        DTA = 0 if DTA is None or DTA == '' else float(DTA)

        DCA = form1Data.get('DCA', '')  #Debt Coverage by Assets
        DCA = 0 if DCA is None or DCA == '' else float(DCA)

        HCI = form1Data.get('HCI', '')  #Housing Cost to Income Threshold
        HCI = 0 if HCI is None or HCI == '' else float(HCI)

        HOCR = form1Data.get('HOCR', '')  #Home Ownership Cost Over Current Rent
        HOCR = 0 if HOCR is None or HOCR == '' else float(HOCR)

        SR = form1Data.get('SR', '')  #Savings Ratio
        SR = 0 if SR is None or SR == '' else float(SR)

        DP = form1Data.get('DP', '')  #Down Payment Ratio of Home Price  
        DP = 0 if DP is None or DP == '' else float(DP)

        HOCC = form1Data.get('HOCC', '')  #Home Ownership Cost Coverage Fund
        HOCC = 0 if HOCC is None or HOCC == '' else float(HOCC)

        HIRT = form1Data.get('HIRT', '')  #High Interest Rate Threshold
        HIRT = 0 if HIRT is None or HIRT == '' else float(HIRT)

        section = form1Data.get('section', '')  #Section
        section = '' if section is None or section == '' else section

        print("section is "+section)
        
        #Calculate the common results and save it in variables
        slack = M1-(M2+M3+M4)
        networth = (T1+T2)-T3
        print("T1+T2" + format(T1+T2))
        R1 = (M3 /M1) * 100 #Debt / Income ratio
        R2 = (T1 / (M2 + M3 + M4))*100 #Expense Coverage Ratio
        R3 = ((T1 + T2) / (T3)) * 100 #Assets / Liabilities
        if (M3+M4 == 0):
            Debt = 1  
        else:
            Debt = M3+M4 
        print("Debt "+format(Debt))     
        R4 = (T1 + T2) / (Debt) * 100 #Assets / (Rent + Debt)
        R5 = M4 / M1 * 100 #Housing Cost Ratio
        if (T1+T2 == 0):
            save = 1
        else:
            save = T1+T2    
        R6 = (T3/(save))*100 #Debt Ratio
        R7 = (slack/M1)*100 #Savings Ratio

        context = {
                'R1': R1,
                'R2': R2,
                'R3': R3,
                'R4' : R4,
                'R5' :R5,
                'R6' :R6,
                'R7' :R7,
                'slack' :slack,
                'networth' :networth
                
            }

        print(context)   
        
        #Based on the section from which the request is got, further calculations are made
        if (section == "BH"):
            formData = data.get('data', {})
            form1Data = data.get('data1', {})
            dataBH = data.get('BHData', {})
            H1 = dataBH.get('H1', 0) #Home Price
            H1 = 0 if H1 is None or H1 == '' else float(H1)    

            H2 = dataBH.get('H2', 0) #Current Rent
            H2 = 0 if H2 is None or H2 == '' else float(H2)

            H3 = dataBH.get('H3', 0) ## of years planning to stay
            H3 = 0 if H3 is None or H3 == '' else float(H3)
            
            H4 = dataBH.get('H4', 0)  #Property Taxes (Yearly)
            H4 = 0 if H4 is None or H4 == '' else float(H4)

            H5 = dataBH.get('H5', 0)  #Property Insurance (Yearly)
            H5 = 0 if H5 is None or H5 == '' else float(H5)

            H6 = dataBH.get('H6', 0)  #Property Maintenance (yearly)
            H6 = 0 if H6 is None or H6 == '' else float(H6)

            H7 = dataBH.get('H7', 0)  #Down Payment (Separate from Savings)
            H7 = 0 if H7 is None or H7 == '' else float(H7)

            H8 = dataBH.get('H8', 0)  #Interest Rate (%)
            H8 = 0 if H8 is None or H8 == '' else float(H8)

            H9 = dataBH.get('H9', 0)  #Tenure (years)            
            H9 = 0 if H9 is None or H9 == '' else float(H9)

            HOC = 0
            val = 0
            BR3 = 0
            BR4 = 0
            SME = 0
            ES = 0

            
            
            HP_per = (DP/100) * (H1)


            #Calculation of the variables to be sent to the PMT function
            ir = (H8/100)/12  #interest rate per month
            np = H9 * 12      #number of periods (months)	
            pv = H1           #present value
            fv = 0            #future value (residual value)
            
            print("H1 " + format(H1))
            print("H8 " + format(H8))
            print("H9 " + format(H9))
            if H1 > 0 and H8 > 0 and H9 > 0:
                PMT = calculatePMT(ir, np, pv, fv)
            
                print('M4 '+ format(M4))
                print('slack '+ format(slack))
                print('T3+H1-H7 '+ format(T3+H1-H7))
                print('T3 '+ format(T3))
                print('H1 '+ format(H1))
                print('H7 '+ format(H7))

                #Calcualtion of the result variables
                HOC = (PMT) + ((H4+H5+H6)/12)
                val = (PMT) + ((H4+H5+H6)/12)
                BR3 = (val/M4)*100
                BR4 = (val/(M4+slack))*100

                print('val '+format(val))
            
                SME = (HOCC * (val + M2 + M3))
                if ((T1 - 3 * (M2 + M3 + M4)) < 0):
                    ES = 0
                else:    
                    ES = T1 - 3 * (M2 + M3 + M4)
            
                HP2chk = (DP/100)*H1 
                if math.isnan(HP2chk):
                    HP2 = 0
                else:
                    HP2 = HP2chk 

                
                contextBH = {
                    'HOC' :HOC,
                    'BR3': BR3,
                    'BR4': BR4,
                    'SME': SME,
                    'ES' : ES,
                    'HP_per' : HP_per                
                }    
            
                #context.update({
                #    'BR3': BR3,
                #    'BR4': BR4,
                #    'SME': SME,
                #    'ES' : ES                
                #})*/

                if (H7 > HP2):
                    R1a = (M3/M1) * 100
                    R2a = (T1/(M2+M3+val))*100 
                    R3a = ((T1+T2)/(T3+H1-H7)) * 100  
                    R4a = ((T1+T2)/(M3+val)) * 100  
                    R5a = (val/M1) * 100  
                    print('T3+H1-H7 '+format(T3+H1-H7))
                    contextBH.update({
                        'R1a' : R1a,
                        'R2a' : R2a,
                        'R3a' : R3a,
                        'R4a' : R4a,
                        'R5a' : R5a
                    }) 
                else:
                    R1b = (M3/M1) * 100
                    R2b = ((T1-ES)/(M2+M3+val))*100 
                    R3b = (((T1-ES)+T2)/(T3+H1-H7)) * 100  
                    R4b = (((T1-ES)+T2)/(M3+val)) * 100  
                    R5b = (val/M1) * 100  
                    
                    contextBH.update({
                    'R1a' : R1b,
                    'R2a' : R2b,
                    'R3a' : R3b,
                    'R4a' : R4b,
                    'R5a' : R5b
                    })    
            else:
                contextBH = {
                    'HOC' :HOC,
                    'BR3': BR3,
                    'BR4': BR4,
                    'SME': SME,
                    'ES' : ES,
                    'HP_per' : HP_per                
                }        
                
        
        elif (section == "DM"):
            print("INSIDE DM")
            R1a = (0/M1) * 100
            R2a = T1/(M2+0+M4) * 100
            R3a = (((T1 + T2) / 1) * 100)
            R4a = ((T1 +T2) / (0 + M4) * 100)
            R5a = (M4 / M1) * 100
            R6a = (0 / (T1 + T2)) * 100
            R7a = (slack/M1) * 100
            R2Less = ((EFT * (M2+M3+M4)) - T1) / slack
            print("Insied section DM")
            context.update({
                    'R1a' : R1a,
                    'R2a' : R2a,
                    'R3a' : R3a,
                    'R4a' : R4a,
                    'R5a' : R5a,
                    'R6a' : R6a,
                    'R7a' : R7a,
                    'R2Less' : R2Less
                }) 
        elif (section == "VP"):
            #Monthly Fixed Costs
            F1 = data.get('F1', '')  
            F2 = data.get('F2', '')  
            F3 = data.get('F3', '')  
            F4 = data.get('F4', '')  
            
            #Value Spending Amounts
            VS1 = data.get('VS1', '') 
            VS2 = data.get('VS2', '') 
            VS3 = data.get('VS3', '') 
            VS4 = data.get('VS4', '') 
            VS5 = data.get('VS5', '') 
            VS6 = data.get('VS6', '') 
            
            #Result Variables
            TFC = F1 + F2 + F3 +F4 #Total Fixed Cost
            TVC = VS1+VS2+VS3+VS4+VS5+VS6 #Total Variable Cost
            AVS = M1-M3-M4-(TFC) #Available for Value Spending
            Surplus = AVS-TVC
            context.update({
                    'TFC' : TFC,
                    'TVC' : TVC,
                    'AVS' : AVS,
                    'Surplus' : Surplus
                }) 

        print("context")        
        print(context)        
        if len(context) > 0 and len(contextBH) > 0:
            print("Inside if")    
            print(contextBH)
            return JsonResponse({'message': context, 'messageBH': contextBH})
        elif len(context) > 0 and len(contextBH) == 0:
            print("Inside else") 
            print(context) 
            return JsonResponse({'message': context})

    else:
        return JsonResponse({'error': 'Unsupported HTTP method'})


def get_next_months(n):
    today = datetime.now()
    
    months = []
    total_months = []
    
    for i in range(n):
        next_month = today + timedelta(days=30*(i+1))
        month = next_month.strftime('%B')  # Full month name
        year = next_month.year
        total_months.append(f"{month} {year}")
    
    return total_months

        
@csrf_exempt        
def payOffDebtRecos(request):
    if request.method == 'POST':
        print("Inside payOffDebtRecos")
        data = json.loads(request.body.decode('utf-8'))
        formData = data.get('data', {})
        form1Data = data.get('data1', {})
        debtData = data.get('debtData', {})
        method = data.get('method')

        M1 = formData.get('M1', 0)
        M1 = 0 if M1 is None or M1 == '' else float(M1)        
        print(M1)
        
        M2 = formData.get('M2', 0)#Monthly Expenses
        M2 = 0 if M2 is None or M2 == '' else float(M2)
       
        M3 = formData.get('M3', 0)  #Monthly Debt
        M3 = 0 if M3 is None or M3 == ''else float(M3)

        M4 = formData.get('M4', 0)  #Housing
        M4 = 0 if M4 is None or M4 == ''else float(M4)

        T1 = formData.get('T1', 0)  #
        T1 = 0 if T1 is None or T1 == ''else float(T1)

        T2 = formData.get('T2', 0)  #Investments
        T2 = 0 if T2 is None or T2 == ''else float(T2)

        T3 = formData.get('T3', 0)  #Total Debt
        T3 = 1 if T3 is None or T3 == '' else float(T3)

        T4 = formData.get('T4', 0)  #Max APR for Debt
        T4 = 0 if T4 is None or T4 == '' else T4

        EFT = form1Data.get('EFT', 0)  #Emergency Fund Threshold
        EFT = 0 if EFT is None or EFT == '' else float(EFT)
        print("EFT "+ format(EFT))

        DTI = form1Data.get('DTI', '')  #Debt To Income Threshold
        DTI = 0 if DTI is None or DTI == '' else float(DTI)
        print("DTI "+ format(DTI))

        DTA = form1Data.get('DTA', '')  #Debt To Assets Threshold
        DTA = 0 if DTA is None or DTA == '' else float(DTA)

        DCA = form1Data.get('DCA', '')  #Debt Coverage by Assets
        DCA = 0 if DCA is None or DCA == '' else float(DCA)

        HCI = form1Data.get('HCI', '')  #Housing Cost to Income Threshold
        HCI = 0 if HCI is None or HCI == '' else float(HCI)

        HOCR = form1Data.get('HOCR', '')  #Home Ownership Cost Over Current Rent
        HOCR = 0 if HOCR is None or HOCR == '' else float(HOCR)

        SR = form1Data.get('SR', '')  #Savings Ratio
        SR = 0 if SR is None or SR == '' else float(SR)

        DP = form1Data.get('DP', '')  #Down Payment Ratio of Home Price  
        DP = 0 if DP is None or DP == '' else float(DP)

        HOCC = form1Data.get('HOCC', '')  #Home Ownership Cost Coverage Fund
        HOCC = 0 if HOCC is None or HOCC == '' else float(HOCC)

        HIRT = form1Data.get('HIRT', '')  #High Interest Rate Threshold
        HIRT = 0 if HIRT is None or HIRT == '' else float(HIRT)

        values = data.get('debtData')
        
        method = data.get('method', 'SB')  #Loan Repayment method 

        print("method "+method)


        savings = T1 - (EFT * (M2 + M3 + M4))  
        slack = M1-(M2+M3+M4)    
    
        line_chart_values = []
        payable_loans = []

        ex_saving = savings
        flag = 0
        month = 0
        LineVals = []
        loans = []
        flag2 = 0
        stat = ''
        fund_months = 0
        final_months = 0
        loans.append(stat)

        print(values)
    
        if (method == "SB"):   
            print("Snowball method")         
            
            # Filter and sort loan data (values is the array of object that contains the loan data)
            values = sorted([value for value in values if float(value['amount']) > 0], key=lambda x: float(x['amount']))
            
            if ex_saving > 0:
                stat = f"You have {ex_saving} in extra savings after setting aside an emergency fund of {EFT} months' expenses, debt payments and rent.\n\n"
                loans.append(stat)
                stat = ''
            for value in values:
                if savings > float(value['amount']):
                    savings -= float(value['amount'])                    
                    stat = f"{value['name']} of {value['amount']} can be paid off immediately using extra savings.\n "
                    loans.append(stat)
                    stat = ''
                
                elif savings == float(value['amount']):
                    stat = f"{value['name']} of {value['amount']} can be paid off immediately using extra savings.\n "
                    value['amount'] -= savings
                    savings = -1
                    loans.append(stat)
                    stat = ''
                    flag = 1
                    flag2 = -1
                
                elif savings > 0:
                    value['amount'] = float(value['amount'])-savings
                    stat = ''
                    stat = f"A part of {value['name']} of {savings} can be paid off using extra savings."
                    loans.append(stat)
                
                    if slack > 0 and float(value['amount']) - slack <= 0:
                        stat = ''
                        stat += f" Remaining {value['name']} of {value['amount']} can be paid off immediately using slack this month. "
                        loans.append(stat)
                
                    elif slack <= 0:
                        stat = ''
                        stat += "\nYou do not have any extra savings beyond emergency fund or slack in your budget to pay off debt. Please increase your income or decrease your expenses to create positive slack in your budget."
                        
                        loans.append(stat)

                    flag = 1
                    flag2 = 1    
                    savings = -1 
                    stat = ''
                elif ex_saving <= 0:                
                
                    if slack > 0:
                        fund_months = ((EFT * (M2+M3+M4)) - T1) / slack
                        if flag2 == 0:
                            mon1 = int(float(value['amount']) / slack)
                            if mon1 == 0:
                                stat = f"\n{value['name']} of {value['amount']} can be paid off with slack immediately. "
                            else:
                                stat = f"\n{value['name']} of {value['amount']} can be paid off with slack in {mon1} months. "
                        
                        else:
                            mon = int((float(value['amount']) - slack) / slack)
                            if (mon > 0):
                                stat = f" Remaining {value['name']} of {value['amount']} can be paid off with slack in {mon} months. "
                            flag2 = 0
                        
                        loans.append(stat)
                        
                        if float(value['amount']) > 0:
                            line_chart_values.append({'name': value['name'], 'amount': float(value['amount'])})
                            month += float(value['amount']) / slack
                        
                    elif slack <= 0:
                        stat = "\n\nYou do not have any extra savings beyond emergency fund or slack in your budget to pay off debt. Please increase your income or decrease your expenses to create positive slack in your budget."
                        loans.append(stat)    
                    
                    savings = -1     
                if savings == -1 and flag == 1:
                    stat = ''
                    if flag2 == 0:
                        if slack > 0:
                            mon2 = int(float(value['amount']) / slack)
                            if mon2 == 0:
                                stat += f"\n{value['name']} of {value['amount']} can be paid off with slack immediately. "
                            else:
                                stat += f"\n{value['name']} of {value['amount']} can be paid off with slack in {mon2} months. "                        
                        flag2 = 0
                    else:
                        if slack > 0:
                            mon = int((float(value['amount']) - slack) / slack)
                            if mon > 0:
                                stat = f" Remaining {value['name']} of {value['amount']} can be paid off with slack in {mon} months. "
                        
                        flag2 = 0
                    
                    loans.append(stat)
                    
                    line_chart_values.append({'name': value['name'], 'amount': float(value['amount'])})
                    if slack > 0:
                        month += float(value['amount']) / slack    
            
            if int(month) > 0:
                stat = ""
                if int(fund_months) > 0:
                    final_months = int(month) + int(fund_months)
                
                else:
                    final_months = int(month)
                
                stat += f"\n\nYou will be debt free in {final_months} months. See the chart below for a visual schedule of paying off debt."
                loans.append(stat)

            
        elif (method == "AV"):

            print("Avalanche method")            
            # Filter and sort loan data (values is the array of object that contains the loan data)
            values = sorted([value for value in values if int(value['amount']) > 0], key=lambda x: float(x['apr']), reverse=True)
            
            if ex_saving > 0:
                stat = f"You have {ex_saving} in extra savings after setting aside an emergency fund of {EFT} months' expenses, debt payments and rent.\n\n"
                loans.append(stat)
            
            for value in values:
                if savings > float(value['amount']):
                    savings -= float(value['amount'])
                    stat = f"{value['name']} of {value['amount']} can be paid off immediately using extra savings. "
                    loans.append(stat)
                
                elif savings == float(value['amount']):
                    stat = f"{value['name']} of {value['amount']} can be paid off immediately using extra savings."
                    value['amount'] -= savings
                    savings = -1
                    loans.append(stat)
                    flag = 1
                
                elif savings > 0:
                    value['amount'] = float(value['amount']) - savings
                    stat = f"A part of {value['name']} of {savings} can be paid off using extra savings."
                    loans.append(stat)
                
                    if slack > 0 and float(value['amount']) - slack <= 0:
                        stat += f" Remaining {value['name']} of {value['amount']} can be paid off immediately using slack this month. "
                        loans.append(stat)
                
                    elif slack <= 0:
                        stat += "\nYou do not have any extra savings beyond emergency fund or slack in your budget to pay off debt. Please increase your income or decrease your expenses to create positive slack in your budget."
                        loans.append(stat)
                
                    flag2 = 1
                    savings = -1
                    loans.append(stat)
                    flag = 1
                
                elif ex_saving <= 0:
                    if slack > 0:
                        fund_months = ((EFT * (M2 + M3 + M4)) - T1) / slack
                        if flag2 == 0:
                            mon1 = int(float(value['amount']) / slack)
                            
                            if mon1 == 0:
                                stat = f"\n{value['name']} of {value['amount']} can be paid off with slack immediately."
                            else:
                                stat = f"\n{value['name']} of {value['amount']} can be paid off with slack in {int(float(value['amount']) / slack)} months."
                        
                        else:
                            mon = int((float(value['amount']) - slack) / slack)
                            
                            if mon > 0:
                                stat = f"Remaining {value['name']} of {value['amount']} can be paid off with slack in {mon} months."
                            
                            flag2 = 0
                        
                        loans.append(stat)
                        
                        if float(value['amount']) > 0:
                            line_chart_values.append({'name': value['name'], 'amount': float(value['amount']), 'apr': int(value['apr'])})
                            month += float(value['amount']) / slack

                    elif slack <= 0:
                        stat = "\n\nYou do not have any extra savings beyond emergency fund or slack in your budget to pay off debt. Please increase your income or decrease your expenses to create positive slack in your budget."
                        loans.append(stat)
                    
                if flag == 1:
                    stat = ""
                    
                    if flag2 == 0:
                        if slack > 0:
                            mon2 = int(float(value['amount']) / slack)
                            
                            if mon2 == 0:
                                stat += f"\n{value['name']} of {value['amount']} can be paid off with slack immediately."
                            else:
                                stat += f"\n{value['name']} of {value['amount']} can be paid off with slack in {int(float(value['amount']) / slack)} months."
                    
                    else:
                        if slack > 0:
                            mon = int((float(value['amount']) - slack) / slack)
                            
                            if mon > 0:
                                stat += f"Remaining {value['name']} of {float(value['amount']) - slack} can be paid off with slack in {mon} months."
                        
                        elif slack <= 0:
                            stat += "\nYou do not have any extra savings beyond emergency fund or slack in your budget to pay off debt. Please increase your income or decrease your expenses to create positive slack in your budget."
                        
                        flag2 = 0

                    loans.append(stat)
                    
                    if float(value['amount']) > 0:
                        line_chart_values.append({'name': value['name'], 'amount': float(value['amount']), 'apr': int(value['amount'])})
                        
                        if slack > 0:
                            month += float(value['amount']) / slack   
            
            if int(month) > 0:
                stat = ""
                
                if int(fund_months) > 0:
                    final_months = int(month) + int(fund_months)
                else:
                    final_months = int(month)
                
                stat += f"\n\nYou will be debt free in {final_months} months. See the chart below for a visual schedule of paying off debt."
                loans.append(stat)
            
            months = int(month)
            get_next_months(int(month))

        return JsonResponse({
                'line_chart_values': line_chart_values,
                'payable_loans': loans
            })    
    else:
        return JsonResponse({'error': 'Unsupported HTTP method'})    
    

def allocateSavings (request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        resultData = data.get('resultData')
        M1 = data.get('M1', '')  #Monthly Income
        M2 = data.get('M2', '')  #Monthly Expenses
        M3 = data.get('M3', '')  #Monthly Debt
        M4 = data.get('M4', '')  #Housing        
        T1 = data.get('T1', '')  #
        T2 = data.get('T2', '')  #Investments
        T3 = data.get('T3', '')  #Total Debt
        T4 = data.get('T4', '')  #Max APR for Debt
        EFT = data.get('EFT', '')  #Emergency Fund Threshold
        HOCC = data.get('HOCC', '')
        DTI = data.get('DTI', '')  #Debt To Income Threshold
        DTA = data.get('DTA', '')  #Debt To Assets Threshold
        DCA = data.get('DCA', '')  #Debt Coverage by Assets
        HCI = data.get('HCI', '')  #Housing Cost to Income Threshold
        HOCR = data.get('HOCR', '')  #Home Ownership Cost Over Current Rent
        SR = data.get('SR', '')  #Savings Ratio
        DP = data.get('DP', '')  #Down Payment Ratio of Home Price  
        HOCC = data.get('HOCC', '')  #Home Ownership Cost Coverage Fund
        HIRT = data.get('HIRT', '')  #High Interest Rate Threshold
        DP = data.get('DP', '')
        GL1 = data.get('GL1', '') #Goal Details
        GL2 = data.get('GL2', '')
        GL3 = data.get('GL3', '')
        GL4 = data.get('GL4', '')
        GLT1 = data.get('GLT1', '')
        GLT2 = data.get('GLT2', '')
        GLT3 = data.get('GLT3', '')
        GLT4 = data.get('GLT4', '')
        Ln = data.get('Ln', '') #Lumpsum Amount
        
        goalStats = ''
        recos = []
        
       
        
        ##Emergency Fund Coverage Calculation
        if Ln > 0 and resultData['R2'] < EFT * 100 and resultData['R2'] > 0:
            goalStats = "You should allocate Lumpsum amount to boost your Emergency Fund.\n"
            
            if (T1 + Ln) > EFT * (M2 + M3 + M4):
                goalStats += f"Add a portion of Lumpsum amount ({(EFT * (M2 + M3 + M4) - T1)}) to your Savings {T1} to bring Expense Coverage Ratio to {EFT * 100}%.\n"
            
                LNew = Ln- (EFT* (M2 + M3 + M4) - T1)
                T1New = EFT * (M2 + M3 + M4)
                EFC = EFT * (M2 + M3 + M4) - T1
                recos.append(goalStats)
        else:
            goalStats += f"Boost Savings {T1} by using the Lumpsum Amount {data['L']}.\n"
            
            if resultData['slack'] > 0:
                months_to_boost = ((EFT * (M2 + M3 + M4) - Ln) / resultData['slack'])
                
                goalStats += f"You have {resultData['slack']} surplus in your budget every month, you can use this to boost your Emergency Fund to at least {EFT * 100}% of expenses. This will take {months_to_boost} months. Then start using your monthly slack towards your financial goals.\n"
                
            LNew = 0
            EFC = Ln
            recos.append(goalStats)
            
        ##Debt Interest Rate
        if LNew > 0:
            if T4 and T3 > 0:                
                if T4 > HIRT:
                    goalStats += "High Debt or Interest rate (APR)\n"
                    goalStats += "You have high interest rate debt. Consider paying off your debt. \n"
                    if LNew >= T3:
                        goalStats += f"You can pay off your entire Debt of {T3}.\n"
                        T3New = 0
                        LNew = LNew - T3
                        POD = T3
                    elif T3 > LNew:
                        goalStats += f"You can pay off a portion {LNew} of your Debt.\n"
                        if resultData['slack'] > 0:
                            goalStats += f"You have {resultData['slack']} surplus in your budget every month, you can use this to first pay off your remaining debt and then start saving for your financial goals.\n"
                        T3New = T3 - LNew
                        LNew = 0
                        POD = LNew
                    recos.append(goalStats)        
                elif T4 < HIRT:
                    goalStats += "Low Interest Rate Debt (APR)\n"
                    if LNew >= (DTA/100) * (T1 + T2):
                        if T3 > (DTA/100) * (T1 + T2):
                            goalStats += "You have less interest rate debt. Consider paying off part of your debt.\n"
                            goalStats += f"You can pay off {((DTA/100) * (T1 + T2))} of your debt.\n"
                            T3New = 0
                            LNew = LNew - ((DTA/100) * (T1 + T2))
                            POD = ((DTA/100) * (T1 + T2))
                        else:
                            goalStats += f"You can pay off your entire Debt of {T3}.\n"
                            T3New = 0
                            LNew = LNew - T3
                            POD = T3
                    else:
                        if T3 > 0 and LNew > 0:
                            if T3 < LNew:
                                goalStats += f"You can pay off your entire Debt of { T3 }\n"
                                T3New = 0
                                LNew = LNew - T3
                                POD = LNew
                            else:
                                if resultData['slack'] > 0:
                                    goalStats += f"You have {resultData['slack']} surplus in your budget every month, you can use this to first pay off your remaining debt and then start saving for your financial goals.\n"
                                T3New = T3 - LNew
                                LNew = 0
                                POD = LNew    
                    recos.append(goalStats)  
        
        #T#Tenure Allotment    
        if LNew > 0:
            if GL1 > 0 or GL2 > 0:
                goalStats += "Financial Goal Allotment \n"
                values = [
                    {'name': "Education", 'amount': GL1, 'tenure': GLT1},
                    {'name': "Travel", 'amount': GL2, 'tenure': GLT2},
                    {'name': "Investment", 'amount': GL3, 'tenure': GLT3},
                    {'name': "Other", 'amount': GL4, 'tenure': GLT4}
                ]
                values = [value for value in values if value['tenure'] > 0]
                values.sort(key=lambda x: x['tenure'])

                ex_savings = T1 - EFT * (M2 + M3 +M4)
                
                ES = ex_savings if ex_savings > 0 else 0 
                GA = 0
                for val in values:
                    if val['amount'] > 0:
                        i = 0
                        if LNew - val['amount'] >= 0:
                            LNew -= val['amount']
                            if i == 0:
                                goalStats += f"\n Allocate a portion {val['amount']} of lumpsum amount to achieve your Goal {val['name']}. "
                                GA += val['amount']
                            else:
                                goalStats += f"\n\n Allocate a portion {val['amount']} of lumpsum amount to achieve your Goal {val['name']}. "
                                GA += val['amount']
                            i += 1
                            recos.append(goalStats)
                        else:
                            if (LNew + ES) - val['amount'] >= 0:
                                goalStats += f"Allocate remaining lumpsum amount of {LNew} and extra savings of {ES} to achieve your Goal {val['name']}. "
                                GA = LNew
                                LNew = 0
                                recos.append(goalStats)
                            else:
                                if LNew > 0:
                                    if resultData['slack'] > 0:
                                        months = (val['amount'] - LNew) / resultData['slack']
                                    goalStats += f"\nAllocate lumpsum amount of {LNew} towards a portion of your Goal {val['name']}. "
                                    GA = LNew
                                    if months > 0:
                                        goalStats += f"Remaining amount can be saved using slack in {int(months)} months."
                                    LNew = 0
                                    recos.append(goalStats)
                                else:
                                    if resultData['slack'] > 0:
                                        months1 = val['amount'] / resultData['slack']
                                        goalStats += f"\nSlack of {resultData['slack']} can be used to achieve your Goal {val['name']}. It will take {int(months1)} months to achieve it."
                                    recos.append(goalStats)
        if Ln > 300:
            ##Calculation of the result variables
            R1a = (M3/M1)*100
            R2a = (T1New/(M2+M3+M4))*100
            R3a = ((T1New + T2) / T3New) * 100
            R4a = (T1New / (M3 + M4)) * 100
            R5a = (M4 / M1)
            S2 = M1 - (M2 + M3 + M4)
            
            result = {
                "R1a" : R1a,
                "R2a" : R2a,
                "R3a" : R3a,
                "R4a" : R4a,
                "R5a" : R5a,
                "S2" : S2,
                
            }
        return json.dumps({
                'recos': recos,
                'result': result
            }, indent=4)
    else:
        return JsonResponse({'error': 'Unsupported HTTP method'})            
        

def saveForGoal (request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        resultData = data.get('resultData')
        M1 = data.get('M1', '')  #Monthly Income
        M2 = data.get('M2', '')  #Monthly Expenses
        M3 = data.get('M3', '')  #Monthly Debt
        M4 = data.get('M4', '')  #Housing        
        T1 = data.get('T1', '')  #
        T2 = data.get('T2', '')  #Investments
        T3 = data.get('T3', '')  #Total Debt
        T4 = data.get('T4', '')  #Max APR for Debt
        EFT = data.get('EFT', '')  #Emergency Fund Threshold
        HOCC = data.get('HOCC', '')
        DTI = data.get('DTI', '')  #Debt To Income Threshold
        DTA = data.get('DTA', '')  #Debt To Assets Threshold
        DCA = data.get('DCA', '')  #Debt Coverage by Assets
        HCI = data.get('HCI', '')  #Housing Cost to Income Threshold
        HOCR = data.get('HOCR', '')  #Home Ownership Cost Over Current Rent
        SR = data.get('SR', '')  #Savings Ratio
        DP = data.get('DP', '')  #Down Payment Ratio of Home Price  
        HOCC = data.get('HOCC', '')  #Home Ownership Cost Coverage Fund
        HIRT = data.get('HIRT', '')  #High Interest Rate Threshold
        DP = data.get('DP', '')
        goal_amount = data.get('SGL1', '') #Goal Details
        goal_timeline = data.get('SGL2', '')
        financing = data.get('SGL3', '')
        loan_rate = data.get('SGL4', '')
        loan_tenure = data.get('SGL5', '')
        
        time1 = 0
        time2 = 0
        time3 = 0        
        shortfall = 0
        
        goalStats = ''
        payment = 0
        extra_savings = 0
        debt_to_reduce = 0
        savings_used = 0
        
        goalStats = ''
        recos = []
        
        if resultData['R2'] < (EFT * 100):
            shortfall = (T1 - EFT) * (M2 + M3 + M4)
            time1 = int(abs(shortfall / resultData['slack']))
            goal_stats += f"You need to first save up for {EFT} months of expenses. It will take you {time1} month(s) using your slack amount of {resultData['slack']}.\n\n"
        elif resultData['R2'] > (EFT * 100):
            time1 = 0
            extra_savings = (T1 - EFT) * (M2 + M3 + M4)
        
        if T3 > (DTA/ 100) * (T1 + T2):
            goal_stats += f"You have excessive debt, reduce it to {DTA}% of your assets."
            debt_to_reduce = T3 - (DTA/ 100) * (T1 + T2)

            if extra_savings > 0:
                if extra_savings > debt_to_reduce:
                    goal_stats += f" You can use {extra_savings} from your savings to reduce your debt."
                    extra_savings -= debt_to_reduce
                    savings_used = debt_to_reduce
                    debt_to_reduce = 0
                else:
                    debt_to_reduce -= extra_savings
                    goal_stats += f" You can use {extra_savings} from your savings to partially reduce your debt."
                    savings_used = extra_savings
                    extra_savings = 0 
                    time2 = int(debt_to_reduce / resultData['slack'])
                    goal_stats += f" You can further reduce your debt using your slack in {time2} month(s)."
            else:
                time2 = int(abs(debt_to_reduce / resultData['slack']))
                goal_stats += f" You can reduce your debt using your slack in {time2} months."

            if T1 > 0 or T2 > 0:
                goal_stats += f"\nYour final debt will be {(DTA/ 100) * (T1 + T2)} or less.\n\n"
        
        if goal_amount > 0:
            if extra_savings > goal_amount:
                goal_stats += f"You can achieve this goal immediately using {extra_savings} from your savings.\n\n"
                savings_used = extra_savings
                extra_savings = 0
                goal_amount = 0
            elif extra_savings > 0:
                goal_stats += f"You can use {extra_savings} from your savings to partially fund your goal.\n\n"
                savings_used = extra_savings
                extra_savings = 0
                goal_amount -= savings_used

            time3 = int(abs(goal_amount / resultData['slack']))
            total_months = time1 + time2 + time3
            years = int(total_months / 12)

            if goal_amount > 0:
                if years <= goal_timeline:
                    if time3 > 0:
                        goal_stats += f"You can use slack {resultData['slack']} to achieve your goal in {time3} month(s)."

                elif financing == "No":
                    goal_stats += f"Your given timeline for achieving this goal is too short to achieve without debt. \nHowever, you can stretch your timeline to {total_months} months ({years} years) to achieve your goal using your slack amount of {resultData['slack']}. \n OR turn on the financing option to see how you can use debt."
                
                elif financing == "Yes":
                    payment = calculatePMT((loan_rate / 100) / 12, loan_tenure * 12, goal_amount, 0)
                    goal_stats += f"You need to finance {goal_amount} for achieving your goal and have a monthly payment of {int(payment)}."

                    if payment > resultData['slack']:
                        goal_stats += f"\nYour monthly payment will exceed your slack {resultData['slack']}. You will need to reduce your expenses or other debt payments."    
            
        if payment > 0:
            NewM3 = M3 + payment 
        else:
            NewM3 = M3
        
        if savings_used > 0:
            T1New = T1 - savings_used
        else:
            T1New = T1
            
        if resultData['slack'] > 0:
            S = resultData['slack'] - payment
        else:
            S = resultData['slack']
            
        ##Result Variables
        R1a = (NewM3/M1)*100
        R2a = (T1New /(M2 +M3 + M4))* 100
        R4a = (T1New /(M3 + M4))* 100
        
        post_result = {
            "R1a" : R1a,
            "R2a" : R2a,
            "R4a" : R4a,
        }
        return json.dumps({
                'goal_stats': goal_stats,
                'post_result': post_result
            }, indent=4)                   
        
    else:
        return JsonResponse({'error': 'Unsupported HTTP method'})                 
            
def investRecos(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        resultData = data.get('resultData')
        M1 = data.get('M1', '')  #Monthly Income
        M2 = data.get('M2', '')  #Monthly Expenses
        M3 = data.get('M3', '')  #Monthly Debt
        M4 = data.get('M4', '')  #Housing        
        T1 = data.get('T1', '')  #
        T2 = data.get('T2', '')  #Investments
        T3 = data.get('T3', '')  #Total Debt
        T4 = data.get('T4', '')  #Max APR for Debt 
        EWRR = data.get('EWRR', '' )   
        EFT = data.get('EFT', '' )   
        stock_ret = data.get('STAR', '') 
        stock_allo = data.get('STA', '')
        bond_ret = data.get('BDAR', '')
        bond_allo = data.get('BDA', '')
        real_ret = data.get('REAR', '')
        real_allo = data.get('REA', '')
        alt_ret = data.get('ALAR', '')
        alt_allo = data.get('ALA', '')
        
        INVValues = []
        recoStats = ''
        extra_savings = 0
        debt_to_reduce = 0
        FVS = 0
        FVB = 0
        FVR = 0        
        FVA = 0 
        LineVals = []
        FV = 0
        RT = 0	
        i = 12
        
        ## Below are the variables for calculating p, r and s for Stocks, Bonds, Real Estate, Alternatives respectively.
        ps = 0
        rs = 0
        ss = 0
        pb = 0
        rb = 0
        sb = 0
        pr = 0
        rr = 0
        sr = 0
        pa = 0
        ra = 0
        sa = 0
        
        slack = resultData['slack']
        
        init_inv = (T1 - 3 * (M2 + M3 + M4)) + T2 
        addl_inv = slack
        
        monthly_exp = M2 + M3 + M4 
        ret_amt = int((M2 + M3 + M4) * 12 * (100 / EWRR))
        
        reco_stats += f"Based on your monthly expenses {monthly_exp}, you will need {ret_amt} to retire.\n"

        if resultData['R2'] > (EFT * 100):
            extra_savings = T1 - EFT * (M2 + M3 + M4)
            reco_stats += f"You can invest {extra_savings} from savings after setting aside {EFT} months of emergency funds.\n"

        if T2 > 0:
            reco_stats += f"You can invest {T2} from Investments according to the asset allocation provided.\n"

        if slack > 0:
            reco_stats += f"You can invest {slack} from Slack every month according to the asset allocation provided.\n"

        if T1 > EFT * (M2 + M3 + M4):
            init_inv = (T1 - 3 * (M2 + M3 + M4)) + T2
        else:
            init_inv = T2    
            
        if init_inv > 0:
            # Setting the values
            LineVals = []

            if stock_ret > 0 and stock_allo > 0:
                ps = init_inv * (stock_allo / 100)
                rs = (stock_ret / 100) / 12
                ss = slack * (stock_allo / 100)
                LineVals.append({'name': 'Stocks', 'ps': ps, 'rs': rs, 'ss': ss})

            if bond_ret > 0 and bond_allo > 0:
                pb = init_inv * (bond_allo / 100)
                rb = (bond_ret / 100) / 12
                sb = slack * (bond_allo / 100)

            if real_ret > 0 and real_allo > 0:
                pr = init_inv * (real_allo / 100)
                rr = (real_ret / 100) / 12
                sr = slack * (real_allo / 100)

            if alt_ret > 0 and alt_allo > 0:
                pa = init_inv * (alt_allo / 100)
                ra = (alt_ret / 100) / 12
                sa = slack * (alt_allo / 100)    
        
            # Calculation of the Retirement Time (RT)
            while RT == 0:
                t = i
                FVS = 0
                FVB = 0
                FVR = 0
                FVA = 0

                if stock_ret > 0 and stock_allo > 0:
                    FVS1 = ps * (pow((1 + rs), t))
                    FVS2 = ss * (((pow((1 + rs), t)) - 1) / rs)
                    FVS = int(FVS1) + int(FVS2)

                if bond_ret > 0 and bond_allo > 0:
                    FVB1 = pb * (pow((1 + rb), t))
                    FVB2 = sb * (((pow((1 + rb), t)) - 1) / rb)
                    FVB = int(FVB1) + int(FVB2)

                if real_ret > 0 and real_allo > 0:
                    FVR1 = pr * (pow((1 + rr), t))
                    FVR2 = sr * (((pow((1 + rr), t)) - 1) / rr)
                    FVR = int(FVR1) + int(FVR2)

                if alt_ret > 0 and alt_allo > 0:
                    FVA1 = pa * (pow((1 + ra), t))
                    FVA2 = sa * (((pow((1 + ra), t)) - 1) / ra)
                    FVA = int(FVA1) + int(FVA2)

                FV = int(FVS) + int(FVB) + int(FVR) + int(FVA)

                if FV >= ret_amt:
                    # print("Yeah")
                    RT = i
                    INVValues = {
                        'STAR': stock_ret,
                        'STA': stock_allo,
                        'BDAR': bond_ret,
                        'BDA': bond_allo,
                        'REAR': real_ret,
                        'REA': real_allo,
                        'ALAR': alt_ret,
                        'ALA': alt_allo,
                        'Slack': slack,
                        'ret_amt': ret_amt,
                        'init_inv': init_inv
                    }
                else:
                    RT = 0
                    i += 12    
        if RT > 0:
            reco_stats += f"Your chosen asset allocation will take {RT/12} years to build the retirement corpus.\n"
            
        return json.dumps({
                'reco_stats': reco_stats,
                'INVValues': INVValues
            }, indent=4) 
    else:
        return JsonResponse({'error': 'Unsupported HTTP method'})       
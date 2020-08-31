#!/bin/python3
#
# heartbeat.py
# Author: Brian Jopling, April 2020 (officially published August 2020)
#
# Description: Calls all endpoints in an API Gateway.
# Usage: Deployed as a Lambda function w/ Python 3.7 runtime.
# Pre-requisites:
#   IAM) Lambda role must have the following policy actions:
#       - cognito-idp:admin_initiate_auth
#       - apigateway:get_resources 
#   Lambda Env Vars) Lambda must have the following env vars:
#       - API_ID
#       - API_DOMAIN
#       - COGNITO_USER
#       - COGNITO_PASS  (encrypted with KMS)
#       - COGNITO_CLIENT_ID
#       - COGNITO_CLIENT_SECRET (encrypted with KMS)
#       - COGNITO_USERPOOL_ID
#
# Post-requisites:
#   A CloudWatch Rule should be setup to invoke this Lambda on a schedule
#   desired by the owner.
########################################

#############
#  IMPORTS  #
#############

import json
import boto3
import os
from botocore.vendored import requests
from base64 import b64decode
from base64 import b64encode
import hmac
import hashlib

#############
#  GLOBALS  #
#############

# Immutable globals; retrieved from env vars.
API_ID = os.environ["API_ID"]
API_DOMAIN = os.environ["API_DOMAIN"]
COGNITO_USER = os.environ["COGNITO_USER"]
COGNITO_PASS_ENC = os.environ["COGNITO_PASS"]
COGNITO_CLIENT_ID = os.environ["COGNITO_CLIENT_ID"]
COGNITO_USERPOOL_ID = os.environ["COGNITO_USERPOOL_ID"]
COGNITO_CLIENT_SECRET = os.environ["COGNITO_CLIENT_SECRET"]


#############
# FUNCTIONS #
#############

# Main
def lambda_handler(event, context):
    apigw = boto3.client("apigateway")
    auth_token = get_auth_token()
    apis = get_resources_with_methods(apigw.get_resources(restApiId=API_ID))
    call_apis(apis, auth_token)
    return {
        'statusCode': 200
    }


# Returns access token used by Cognito.
def get_auth_token():
    decrypted_pass = decrypt(COGNITO_PASS_ENC)
    decrypted_client_secret = decrypt(COGNITO_CLIENT_SECRET)
    cognito = boto3.client("cognito-idp")
    secret_hash = get_secret_hash(decrypted_client_secret)
    cog_resp = cognito.admin_initiate_auth(
        AuthFlow='ADMIN_NO_SRP_AUTH',
        AuthParameters={
            'USERNAME': COGNITO_USER,
            'PASSWORD': decrypted_pass,
            'SECRET_HASH': secret_hash
        },
        ClientId=COGNITO_CLIENT_ID,
        UserPoolId=COGNITO_USERPOOL_ID
    )
    return cog_resp['AuthenticationResult']['IdToken']


# Accepts response from apigw get_resources() call.
# Returns dictionary object containing resources with their methods.
# e.g.
# { '/updatestudent': ['OPTIONS', 'POST'], '/getconversation': ['GET', 'OPTIONS'] }
def get_resources_with_methods(resp):
    dict_apis = {}
    for ep in resp['items']:
        try:
            res_methods = []
            for method in ep['resourceMethods']:
                res_methods.append(method)
            dict_apis[ep['path']] = res_methods
        except KeyError as e:
            print("Resource %s has no methods, skipping." % ep['path'])
    return dict_apis
    
    
# Accepts dict in the format of { '/resource': ['METHOD', 'METHOD'] }
# Makes synchronous http requests to each resource. Returns nothing.
def call_apis(apis, auth_token):
    for resource in apis.keys():
        url = "%s%s" % (API_DOMAIN, resource)
        for method in apis[resource]:
            try:
                r = requests.request(method, url, headers={'Authorization': auth_token})
                print("Called %s %s, returned %s" % (url, method, r.status_code))
            except Exception as e:
                print("Failed to call %s %s due to %s" % (resource, method, str(e)))
                

####################
# HELPER FUNCTIONS #
####################
                
# AWS expects the SECRET_HASH to follow BASE64(HMAC_SHA256_HASH)
def get_secret_hash(decrypted_client_secret):
    digest = get_hmac_sha256(decrypted_client_secret)
    return b64encode(digest).decode()

# AWS expects the hmac to follow HMAC_SHA256(ClientSecret, Username + ClientID)
def get_hmac_sha256(decrypted_client_secret):
    return hmac.new(decrypted_client_secret.encode('utf-8'),
              msg=(COGNITO_USER + COGNITO_CLIENT_ID).encode('utf-8'),
              digestmod=hashlib.sha256
             ).digest()

# Decrypts encrypted values using KMS key.
def decrypt(d):
    return boto3.client('kms').decrypt(CiphertextBlob=b64decode(d))['Plaintext'].decode('utf-8')
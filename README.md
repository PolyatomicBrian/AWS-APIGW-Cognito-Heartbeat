# AWS-APIGW-Cognito-Heartbeat

#### Brian Jopling, April 2020 (officially published August 2020)

A Lambda function that programmatically sends a request to every resource in an API Gateway mapping that requires Cognito authorization.


## Usage

Deployed as an AWS Lambda function w/ the `Python 3.7` runtime.


## Prerequisites

1. **[IAM]** The Lambda IAM role must have the following policy actions:
    - `cognito-idp:admin_initiate_auth`
    - `apigateway:get_resources`

2. **[Lambda Environment Variables]** The Lambda must have the following environment variables:
    - `API_ID`
    - `API_DOMAIN`
    - `COGNITO_USER`
    - `COGNITO_PASS`  **(encrypted with KMS)**
    - `COGNITO_CLIENT_ID`
    - `COGNITO_CLIENT_SECRET` **(encrypted with KMS)**
    - `COGNITO_USERPOOL_ID`

## Postrequisites (after deployment)

1. Setup a CloudWatch Event Rule to ping this Lambda as often as you desire.

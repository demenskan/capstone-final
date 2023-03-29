import jwt
import hashlib
import logging
import json
import ipaddress
import re
import socket
import struct
import os
from ipaddress import IPv4Network
# E.G. curl -H "Accept: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.StuYX978pQGnCeeaj2E1yBYwQvZIodyDTCJWXdsxBGI" https://rsa3qcz20m.execute-api.us-west-1.amazonaws.com/Prod/mask-to-cidr?value=240.0.0.0

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    This function gets a mask and returns a cidr prefix
    there must be a valid JWT on the header
    """
    #
    #jwt_key=os.environ['JWT_KEY']
    jwt_key="my2w7wjd7yXF64FIADfJxNs1oupTGAuW"
    try:
        mask=event["queryStringParameters"]["value"]
        auth_token=event["headers"]["authorization"].replace('Bearer ','')
        jwt_decoded=jwt.decode(auth_token,jwt_key, algorithms = 'HS256')
        if 'role' in jwt_decoded:
            prefix=IPv4Network('0.0.0.0/'+mask).prefixlen
            if prefix==0:
                response = {
                    "statusCode": 403,
                    "body" : json.dumps("Invalid mask")
                }
            else:
                response = {
                    "statusCode": 200,
                    "body" : json.dumps({ "function" : "cidrToMask", "prefix" : prefix })
                }
        else:
            response = {
                "statusCode": 403,
                "body" : json.dumps("Unauthorized")
            }    
    except Exception as e:
        logger.info(e)
        response = {
            "statusCode": 403,
            "body" : json.dumps("Unauthorized")
        }    
    #logger.info(event)
    return response

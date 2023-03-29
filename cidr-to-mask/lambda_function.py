import jwt
import hashlib
import logging
import json
import os
import socket
import struct
#from ipaddress import IPv4Network
#e.g. curl -H "Accept: application/json" -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYWRtaW4ifQ.StuYX978pQGnCeeaj2E1yBYwQvZIodyDTCJWXdsxBGI" https://rsa3qcz20m.execute-api.us-west-1.amazonaws.com/Prod/cidr-to-mask?value=30
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    """
    This function gets a mask and returns a cidr prefix
    there must be a valid JWT on the header
    """
    #jwt_key=os.environ['JWT_KEY']
    jwt_key="my2w7wjd7yXF64FIADfJxNs1oupTGAuW"
    try:
        prefix=int(event["queryStringParameters"]["value"])
        logger.info("prefix" + str(prefix))
        logger.info("headers:" + json.dumps(event['headers']))
        auth_token=event["headers"]["authorization"].replace('Bearer ','')
        logger.info("auth_token: " + auth_token)
        jwt_decoded=jwt.decode(auth_token,jwt_key, algorithms = 'HS256')
        logger.info("role: " + jwt_decoded['role'])
        if 'role' in jwt_decoded:
            mask=socket.inet_ntoa(struct.pack(">I", (0xffffffff << (32 - prefix)) & 0xffffffff))
            response = {
                "statusCode": 200,
                "body" : json.dumps({ "function" : "cidrToMask", "mask" : mask })
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


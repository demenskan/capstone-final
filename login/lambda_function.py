import jwt
import hashlib
import sys
import logging
import pymysql
import json
import os
# test => curl -X POST -H "Content-Type: application/json" -d '{"username": "admin", "password" : "secret"}' https://rsa3qcz20m.execute-api.us-west-1.amazonaws.com/Prod/list

# rds settings
"""
rds_host  = os.environ['DB_HOST']
user_name = os.environ['DB_USER']
password = os.environ['DB_PASS']
db_name = os.environ['DB_NAME']
"""
rds_host  = "mysqlforlambda.cbm6k6ibrhug.us-west-1.rds.amazonaws.com"
user_name = "admin"
password = "Polloloco88$"
db_name = "ExampleDB"



logger = logging.getLogger()
logger.setLevel(logging.INFO)

# create the database connection outside of the handler to allow connections to be
# re-used by subsequent function invocations.
try:
    conn = pymysql.connect(host=rds_host, user=user_name, passwd=password, db=db_name, connect_timeout=5)
except pymysql.MySQLError as e:
    logger.error("ERROR: Unexpected error: Coud not connect to MySQL instance.")
    logger.error(e)
    sys.exit()

logger.info("SUCCESS: Connection to RDS MySQL instance succeeded")


def lambda_handler(event, context):
    """
    This function creates a new RDS database table and writes records to it
    """
    #jwtKey=os.environ["JWT_KEY"]
    jwtKey="my2w7wjd7yXF64FIADfJxNs1oupTGAuW"

    with conn.cursor() as cur:
        logger.info(event)
        #logger.info(event['body'])
        #data=json.loads(event['body'])
        data=json.loads(event['body'])
        logger.info("data: " + json.dumps(data))
        username=data['username']
        password=data['password']
        #splits the body string into parameters
        #body=event['body'].split("&")
        #parameter={}
        #for par in body:
        #    tupla=par.split("=")
        #    parameter[tupla[0]]=tupla[1]
        #username=parameter['username']
        #password=parameter['password']
        query="select salt, password, role from users where username=%s"
        cur.execute(query,(username,))
        try:
            row=cur.fetchone()
            logger.info(row)
            salt=row[0]
            passwd_db=row[1]
            role=row[2]
            hashed_pass=hashlib.sha512((password+salt).encode()).hexdigest()
            logger.info("hashed pass:" + hashed_pass)
            logger.info("pass db:" + passwd_db)
            if passwd_db==hashed_pass:
                enJWT = jwt.encode({"role": role}, jwtKey, algorithm='HS256')
                response = {
                    "statusCode": 200,
                    "body" : json.dumps({ "data" : enJWT })
                }
            else:
                response = {
                    "statusCode": 403,
                    "body" : json.dumps("wrong")
                }
        except:
            response = {
                "statusCode": 403,
                "body" : json.dumps("wrong")
            }
    return response


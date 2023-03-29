import jwt
import hashlib
import sys
import logging
import pymysql
import json

# rds settings

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
    #message = event['Records'][0]['body']
    #data = json.loads(message)
    #CustID = data['CustID']
    #Name = data['Name']

    item_count = 0
    #sql_string = f"select * from users where username='admin'"

    with conn.cursor() as cur:
        #cur.execute("DROP TABLE IF EXISTS users")
        #cur.execute("CREATE TABLE users (username varchar(100) DEFAULT NULL, password varchar(500) DEFAULT NULL,salt varchar(300) DEFAULT NULL,role varchar(100) DEFAULT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb3")
        #cur.execute("LOCK TABLES users WRITE")
        #cur.execute("INSERT INTO users VALUES ('admin','15e24a16abfc4eef5faeb806e903f78b188c30e4984a03be4c243312f198d1229ae8759e98993464cf713e3683e891fb3f04fbda9cc40f20a07a58ff4bb00788','F^S%QljSfV','admin'),('noadmin','89155af89e8a34dcbde088c72c3f001ac53486fcdb3946b1ed3fde8744ac397d99bf6f44e005af6f6944a1f7ed6bd0e2dd09b8ea3bcfd3e8862878d1709712e5','KjvFUC#K*i','editor'),('bob','2c9dab627bd73b6c4be5612ff77f18fa69fa7c2a71ecedb45dcec45311bea736e320462c6e8bfb2421ed112cfe54fac3eb9ff464f3904fe7cc915396b3df36f0','F^S%QljSfV','viewer'),('demenskan',NULL,'iFvF@G8KMu','editor')")
        #cur.execute("UNLOCK TABLES")
        #cur.execute("create table if not exists Customer ( CustID  int NOT NULL, Name varchar(255) NOT NULL, PRIMARY KEY (CustID))")
        #cur.execute(sql_string)
        #conn.commit()
        #logger.info(event)
        logger.info(event['body'])
        #logger.info(type(event['body']))
        #data=json.loads(event['body'])
        #splits the body string into parameters
        body=event['body'].split("&")
        parameter={}
        for par in body:
            tupla=par.split("=")
            parameter[tupla[0]]=tupla[1]

        username=parameter['username']
        password=parameter['password']
        query="select salt, password, role from users where username=%s"
        logger.info(parameter)
        #logger.info("username=["+username+"];pass=["+password+"]")
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
                response = {
                    "statusCode": 200,
                    "body" : json.dumps("Pass OK!")
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

    #return "%d items" %(item_count)
    return response


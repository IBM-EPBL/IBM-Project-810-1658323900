import mysql.connector
import hashlib
import secrets

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="spoonkawinsp",
  database="PROJECTS"
)

def create_user(name, email, role, password):
  cursor = mydb.cursor()
  password = hashlib.md5((password + "customer-care-registry").encode()).hexdigest()
  query = "INSERT INTO USERS (NAME, EMAIL, ROLE) VALUES ('{}', '{}', '{}')".format(name, email, role)
  try:
    cursor.execute(query)
  except:
    return False
  mydb.commit()
  query = "SELECT ID FROM USERS WHERE EMAIL='{}' AND ROLE='{}' AND IS_DELETED=0".format(email, role)
  cursor.execute(query)
  user_id = cursor.fetchone()[0]
  secret_key = secrets.token_hex()
  query = "INSERT INTO AUTHENTICATION VALUES ({}, '{}', '{}')".format(user_id, password, secret_key)
  cursor.execute(query)
  mydb.commit()
  return secret_key

def authentication(email, password, role):
  cursor = mydb.cursor()
  password = hashlib.md5((password + "customer-care-registry").encode()).hexdigest()
  print(password)
  query = "SELECT ID FROM USERS WHERE EMAIL='{}' AND ROLE='{}' AND IS_DELETED=0".format(email, role)
  cursor.execute(query)
  row = cursor.fetchone()
  if(not row):
    return False
  user_id = row[0]
  query = "SELECT SECRET_KEY FROM AUTHENTICATION WHERE USER_ID={} AND PASSWORD='{}'".format(user_id, password)
  cursor.execute(query)
  row = cursor.fetchone()
  if (not row):
    return False
  secret_key = row[0]
  return secret_key


def is_authenticated(secret_key, role):
  cursor = mydb.cursor()
  query = "SELECT USER_ID FROM AUTHENTICATION WHERE SECRET_KEY = '{}'".format(secret_key);
  cursor.execute(query)
  row = cursor.fetchone()
  if (not row):
    return False
  user_id = row[0]
  query = "SELECT * FROM USERS WHERE ID={} AND ROLE='{}' AND IS_DELETED=0".format(user_id, role)
  cursor.execute(query)
  row = cursor.fetchone()
  if (not row):
    return False

  return True
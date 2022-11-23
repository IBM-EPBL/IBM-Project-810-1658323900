import mysql.connector
import hashlib
import secrets
import string
import random

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="spoonkawinsp",
  database="projects"
)

def create_user(name, email, role, password):
  cursor = mydb.cursor()
  password = hashlib.md5((password + "customer-care-registry").encode()).hexdigest()
  query = "INSERT INTO USERS (NAME, EMAIL, ROLE) VALUES ('{}', '{}', '{}')".format(name, email, role)
  print(query)
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


def check_user(email):
  cursor = mydb.cursor()
  query = "SELECT * FROM USERS WHERE EMAIL='{}' AND IS_DELETED=0".format(email)
  cursor.execute(query)
  user = cursor.fetchone()
  if(user):
    return True
  return False


def change_password(email, password):
  password = hashlib.md5((password + "customer-care-registry").encode()).hexdigest()
  cursor = mydb.cursor()
  query = "SELECT * FROM USERS WHERE EMAIL='{}' AND IS_DELETED=0".format(email)
  cursor.execute(query)
  user = cursor.fetchone()
  user_id = user[0]
  query = "UPDATE AUTHENTICATION SET PASSWORD='{}' WHERE USER_ID='{}'".format(password, user_id)
  cursor.execute(query)
  mydb.commit()
  return user

def accept_or_reject(role, status, id):
  cursor = mydb.cursor()
  if (role == "admin"):
    admin = admin_details(admin_id=id)
    email = admin[2]
  else:
    agent = agent_details(agent_id=id)
    email = agent[2]
  if(status=='accept'):
    query = "UPDATE USERS SET ROLE='{}' WHERE ID={}".format(role, id)
  else:
    query = "UPDATE USERS SET IS_DELETED=1 WHERE ID={}".format(id)
  cursor.execute(query)
  mydb.commit()

  return email

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


def dashboard_details(user_id=None, agent_id=None):
  details = dict()
  if(user_id):
    tickets = fetch_user_tickets(user_id=user_id)
  elif(agent_id):
    tickets = fetch_agent_tickets(agent_id=agent_id)
  else:
    tickets = fetch_all_tickets()
  details["ticket_count"] = len(tickets)
  details["Open"] = {"total":0, "percent":0}
  details["Pending"] = {"total":0, "percent":0}
  details["On Hold"] = {"total":0, "percent":0}
  details["Solved"] = {"total":0, "percent":0}
  details["Closed"] = {"total":0, "percent":0}
  for ticket in tickets.values():
      details[ticket["status"]]["total"] += 1
      details[ticket["status"]]["percent"] = int((details[ticket["status"]]["total"]/details["ticket_count"])*100)

  return details


def fetch_all_users():
  cursor = mydb.cursor()
  query = "SELECT * FROM USERS WHERE ROLE='user' AND IS_DELETED=0"
  cursor.execute(query)
  rows = cursor.fetchall()

  return rows


def fetch_all_agents():
  agents = dict()
  cursor = mydb.cursor()
  query = "SELECT * FROM USERS WHERE ROLE='agent' AND IS_DELETED=0"
  cursor.execute(query)
  rows = cursor.fetchall()
  for agent in rows:
    query = "SELECT COUNT(*) FROM TICKETS WHERE AGENT_ID ={} AND STATUS='Pending' AND IS_DELETED=0".format(agent[0])
    cursor.execute(query)
    pending = cursor.fetchone()
    query = "SELECT COUNT(*) FROM TICKETS WHERE AGENT_ID ={} AND STATUS='Solved' AND IS_DELETED=0".format(agent[0])
    cursor.execute(query)
    solved = cursor.fetchone()
    agents[agent[0]] = {"name": agent[1], "email": agent[2], "pending": pending[0], "solved": solved[0]}

  return agents


def fetch_requested_users(role):
  agents = dict()
  admins = dict()
  cursor = mydb.cursor()
  if(role=="agent"):
    query = "SELECT * FROM USERS WHERE ROLE='r-agt' AND IS_DELETED=0"
    cursor.execute(query)
    rows = cursor.fetchall()
    for agent in rows:
      agents[agent[0]] = {"id": agent[0], "name": agent[1], "email": agent[2]}

    return agents
  else:
    if(role=="r-adm"):
      query = "SELECT * FROM USERS WHERE ROLE='r-adm' AND IS_DELETED=0"
    else:
      query = "SELECT * FROM USERS WHERE ROLE='admin' AND IS_DELETED =0"
    cursor.execute(query)
    rows = cursor.fetchall()
    for admin in rows:
      admins[admin[0]] = {"id": admin[0], "name": admin[1], "email": admin[2]}

    return admins

def user_details(secret_key=None, user_id=None, ticket_id=None):
  cursor = mydb.cursor()
  if(secret_key):
    query = "SELECT USER_ID FROM AUTHENTICATION WHERE SECRET_KEY = '{}'".format(secret_key)
    cursor.execute(query)
    row = cursor.fetchone()
    user_id = row[0]
  if(ticket_id):
    query = "SELECT * FROM TICKETS WHERE TICKET_ID='{}'".format(ticket_id)
    cursor.execute(query)
    row = cursor.fetchone()
    user_id = row[2]
  query = "SELECT * FROM USERS WHERE ID={} AND ROLE='user' AND IS_DELETED=0".format(user_id)
  cursor.execute(query)
  row = cursor.fetchone()

  return row


def agent_details(secret_key=None, agent_id=None):
  cursor = mydb.cursor()
  if(secret_key):
    query = "SELECT USER_ID FROM AUTHENTICATION WHERE SECRET_KEY = '{}'".format(secret_key)
    cursor.execute(query)
    row = cursor.fetchone()
    agent_id = row[0]
  query = "SELECT * FROM USERS WHERE ID={} AND IS_DELETED=0".format(agent_id)
  cursor.execute(query)
  row = cursor.fetchone()

  return row

def create_ticket(secret_key, short_description, issue):
  cursor = mydb.cursor()
  user_detail = user_details(secret_key)
  user_id = user_detail[0]
  letters = string.ascii_lowercase+string.digits
  id = "".join([random.choice(letters) for i in range(6)])
  query = "INSERT INTO TICKETS(TICKET_ID, USER_ID) VALUES ('{}', {})".format(id, user_id)
  cursor.execute(query)
  mydb.commit()
  query = "SELECT ID FROM TICKETS WHERE TICKET_ID= '{}'".format(id)
  cursor.execute(query)
  row = cursor.fetchone()
  ticket_id = row[0]
  query = "INSERT INTO TICKET_DETAILS VALUES({},'{}','{}')".format(ticket_id, short_description, issue)
  cursor.execute(query)
  mydb.commit()

  return ticket_id


def fetch_user_tickets(user_id, status=None, ticket_id=None):
  ticket_details = dict()
  cursor = mydb.cursor()
  if(ticket_id):
    query = "SELECT * FROM TICKETS WHERE USER_ID={} AND TICKET_ID='{}' AND IS_DELETED=0".format(user_id, ticket_id)
  elif(status):
    query = "SELECT * FROM TICKETS WHERE USER_ID={} AND STATUS='{}' AND IS_DELETED=0".format(user_id, status)
  else:
    query = "SELECT * FROM TICKETS WHERE USER_ID={} AND IS_DELETED=0".format(user_id)
  cursor.execute(query)
  rows = cursor.fetchall()
  for i in range(len(rows)):
    cur = rows[i]
    ticket_details[i] = dict()
    ticket_id = cur[0]
    query = "SELECT * FROM TICKET_DETAILS WHERE TICKET_ID={}".format(ticket_id)
    cursor.execute(query)
    ticket_details_rows = cursor.fetchone()
    ticket_details[i]["id"] = cur[1]
    ticket_details[i]["description"] = ticket_details_rows[1]
    if(len(ticket_details_rows[2])<50):
      ticket_details[i]["issue"] = ticket_details_rows[2]
    else:
      ticket_details[i]["issue"] = ticket_details_rows[2]
    ticket_details[i]["agent"] = "Un Assigned" if cur[3]==0 else "Assigned"
    if(cur[5]=='Open'):
      ticket_details[i]["css"] = "bg-label-primary"
    elif (cur[5] == 'Pending'):
      ticket_details[i]["css"] = "bg-label-danger"
    elif (cur[5] == 'On Hold'):
      ticket_details[i]["css"] = "bg-label-warning"
    elif (cur[5] == 'Solved'):
      ticket_details[i]["css"] = "bg-label-success"
    else:
      ticket_details[i]["css"] = "bg-label-secondary"
    ticket_details[i]["status"] = cur[5]
    ticket_details[i]["created"] = cur[8].strftime("%d") + "-" + cur[8].strftime("%m") + "-" + cur[8].strftime("%Y")

  return ticket_details


def update_user_ticket(user_id, ticket_id, description, issue):
  cursor = mydb.cursor()
  query = "SELECT ID FROM TICKETS WHERE TICKET_ID='{}' AND USER_ID={}".format(ticket_id, user_id)
  cursor.execute(query)
  row = cursor.fetchone()
  if(not row):
    return False
  id = row[0]

  query = "UPDATE TICKET_DETAILS SET SHORT_DESCRIPTION='{}', ISSUE='{}' WHERE TICKET_ID ={}".format(description, issue, id)
  cursor.execute(query)
  mydb.commit()


def delete_user_ticket(user_id=None, ticket_id=None):
  cursor = mydb.cursor()
  if(user_id):
    query = "UPDATE TICKETS SET IS_DELETED=1 WHERE TICKET_ID='{}' AND USER_ID={}".format(ticket_id, user_id)
  else:
    query = "UPDATE TICKETS SET IS_DELETED=1 WHERE TICKET_ID='{}'".format(ticket_id)
  cursor.execute(query)
  mydb.commit()


def fetch_agent_tickets(agent_id, ticket_id=None, status=None):
  ticket_details = dict()
  cursor = mydb.cursor()
  if(ticket_id):
    query = "SELECT * FROM TICKETS WHERE AGENT_ID={} AND TICKET_ID='{}' AND IS_DELETED=0".format(agent_id, ticket_id)
  elif(status):
    query = "SELECT * FROM TICKETS WHERE AGENT_ID={} AND STATUS='{}' AND IS_DELETED=0".format(agent_id, status)
  else:
    query = "SELECT * FROM TICKETS WHERE AGENT_ID={} AND IS_DELETED=0".format(agent_id)
  cursor.execute(query)
  rows = cursor.fetchall()
  for i in range(len(rows)):
    cur = rows[i]
    ticket_details[i] = dict()
    ticket_id = cur[0]
    query = "SELECT * FROM TICKET_DETAILS WHERE TICKET_ID={}".format(ticket_id)
    cursor.execute(query)
    ticket_details_rows = cursor.fetchone()
    ticket_details[i]["id"] = cur[1]
    ticket_details[i]["description"] = ticket_details_rows[1]
    if(len(ticket_details_rows[2])<50):
      ticket_details[i]["issue"] = ticket_details_rows[2]
    else:
      ticket_details[i]["issue"] = ticket_details_rows[2]
    ticket_details[i]["agent"] = "Un Assigned" if cur[3]==0 else "Assigned"
    if(cur[5]=='Open'):
      ticket_details[i]["css"] = "bg-label-primary"
    elif (cur[5] == 'Pending'):
      ticket_details[i]["css"] = "bg-label-danger"
    elif (cur[5] == 'On Hold'):
      ticket_details[i]["css"] = "bg-label-warning"
    elif (cur[5] == 'Solved'):
      ticket_details[i]["css"] = "bg-label-success"
    else:
      ticket_details[i]["css"] = "bg-label-secondary"
    ticket_details[i]["status"] = cur[5]
    ticket_details[i]["created"] = cur[8].strftime("%d") + "-" + cur[8].strftime("%m") + "-" + cur[8].strftime("%Y")

  return ticket_details


def set_ticket_status(id, status):
  cursor = mydb.cursor()
  query = "UPDATE TICKETS SET STATUS='{}' WHERE TICKET_ID='{}'".format(status, id)
  cursor.execute(query)
  mydb.commit()
  query = "SELECT * FROM TICKETS WHERE TICKET_ID='{}' AND IS_DELETED=0".format(id)
  print(query)
  cursor.execute(query)
  user_ticket_detail = dict()
  ticket = cursor.fetchone()
  user = user_details(user_id=ticket[2])
  user_ticket_detail["email"] = user[2]
  query = "SELECT * FROM TICKET_DETAILS WHERE TICKET_ID='{}'".format(ticket[0])
  cursor.execute(query)
  ticket_detail = cursor.fetchone()
  user_ticket_detail["short_description"] = ticket_detail[1]
  user_ticket_detail["issue"] = ticket_detail[2]

  return user_ticket_detail


def set_ticket_agent(id, agent_id):
  cursor = mydb.cursor()
  query = "UPDATE TICKETS SET AGENT_ID='{}', STATUS='Pending' WHERE TICKET_ID='{}'".format(agent_id, id)
  cursor.execute(query)
  mydb.commit()



def admin_details(secret_key=None, admin_id=None):
  cursor = mydb.cursor()
  if(secret_key):
    query = "SELECT USER_ID FROM AUTHENTICATION WHERE SECRET_KEY = '{}'".format(secret_key)
    cursor.execute(query)
    row = cursor.fetchone()
    admin_id = row[0]

  query = "SELECT * FROM USERS WHERE ID={} AND IS_DELETED=0".format(admin_id)
  cursor.execute(query)
  row = cursor.fetchone()

  return row


def fetch_all_tickets(status=None, ticket_id=None):
  ticket_details = dict()
  cursor = mydb.cursor()
  if (ticket_id):
    query = "SELECT * FROM TICKETS WHERE TICKET_ID='{}' AND IS_DELETED=0".format(ticket_id)
  elif (status):
    query = "SELECT * FROM TICKETS WHERE STATUS='{}' AND IS_DELETED=0".format(status)
  else:
    query = "SELECT * FROM TICKETS WHERE IS_DELETED=0"
  cursor.execute(query)
  rows = cursor.fetchall()
  print(query)
  for i in range(len(rows)):
    cur = rows[i]
    ticket_details[i] = dict()
    ticket_id = cur[0]
    query = "SELECT * FROM TICKET_DETAILS WHERE TICKET_ID={}".format(ticket_id)
    cursor.execute(query)
    ticket_details_rows = cursor.fetchone()
    ticket_details[i]["id"] = cur[1]
    ticket_details[i]["description"] = ticket_details_rows[1]
    if (len(ticket_details_rows[2]) < 50):
      ticket_details[i]["issue"] = ticket_details_rows[2]
    else:
      ticket_details[i]["issue"] = ticket_details_rows[2]
    ticket_details[i]["user"] = user_details(user_id=cur[2])
    if cur[3] == 0:
      ticket_details[i]["agent"] = 0
    else:
      agent = agent_details(agent_id=cur[3])
      ticket_details[i]["agent"] = agent
    if (cur[5] == 'Open'):
      ticket_details[i]["css"] = "bg-label-primary"
    elif (cur[5] == 'Pending'):
      ticket_details[i]["css"] = "bg-label-danger"
    elif (cur[5] == 'On Hold'):
      ticket_details[i]["css"] = "bg-label-warning"
    elif (cur[5] == 'Solved'):
      ticket_details[i]["css"] = "bg-label-success"
    else:
      ticket_details[i]["css"] = "bg-label-secondary"
    ticket_details[i]["status"] = cur[5]
    ticket_details[i]["created"] = cur[8].strftime("%d") + "-" + cur[8].strftime("%m") + "-" + cur[8].strftime("%Y")

  return ticket_details
from app import app
import os
import psycopg2
from flask import jsonify
from flask_jwt_extended import JWTManager
import psycopg2.extras
from flask_bcrypt import Bcrypt
import jwt
import datetime
import app.controllers.ssi as ssi

SECRET_KEY = "SECRET_KEY"

bcrypt = Bcrypt(app)
JWTManager(app)

def get_db_connection():
    # conn = psycopg2.connect(host='https://146.190.157.57',
    conn = psycopg2.connect(host='127.0.0.1',
                            port='5432',
                            database='postgres',
                            user=os.environ['DB_USERNAME'],
                            password=os.environ['DB_PASSWORD'])
    return conn

def login_org(request):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    jsonData = request.get_json()
    if jsonData['login'] != "" and jsonData['password'] != "":
        cursor.execute("SELECT * FROM organizations WHERE login='" + jsonData['login'] + "'")
        account = cursor.fetchone()
        if account[1] == jsonData['login'] and bcrypt.check_password_hash(account[4], jsonData['password']):
            token = jwt.encode({'login':jsonData['login'], 'exp': datetime.datetime.now() + datetime.timedelta(hours=12)}, SECRET_KEY)
            return jsonify(login=jsonData['login'],token=token.decode('UTF-8'))
        return "Bad Request", 400
    return "Intern Erro", 500

def saveCredential(request):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    jsonData = request.get_json()
    try:
        cursor.execute("""
            INSERT INTO credentials(
                name,
                type,
                season,
                condition,
                prescription,
                email,
                createDate,
                doctor,
                squad
            ) VALUES('%s','%s','%s','%s','%s','%s','%s','%s','%s')
        """%(jsonData['name'], jsonData['type'], jsonData['season'], jsonData['condition'], jsonData['prescription'], jsonData['email'], jsonData['createDate'], jsonData['doctor'], jsonData['squad']))
        conn.commit()
        return jsonify({'message': 'success'}), 200
    except:
        return "Intern Erro", 500


def user_by_login(login):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    print(login)
    if login != "":
        cursor.execute("SELECT * FROM organizations WHERE login='" + login + "'")
        account = cursor.fetchone()
        print(account)
        if account:
            return account
        return None
    return None

def get_credentials(email):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if email != "":
        cursor.execute("SELECT * FROM credentials WHERE email='" + email + "'")
        credentials = cursor.fetchall()
        if credentials:
            return credentials
        return None
    else:
        cursor.execute("SELECT * FROM credentials")
        credentials = cursor.fetchall()
        if credentials:
            return credentials
        return None
    return None

def updateVerkey(verkey):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute("""
            UPDATE organizations
            SET verkey = '%s'
            WHERE login = '00.000.000/0000-00';
        """%(verkey))
        conn.commit()
        return jsonify({'message': 'success'}), 200
    except:
        return "Intern Erro", 500
    return "Intern Erro", 500

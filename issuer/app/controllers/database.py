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
    conn = psycopg2.connect(host='localhost',
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
    if login != "":
        cursor.execute("SELECT * FROM users WHERE login='" + login + "'")
        account = cursor.fetchone()
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

# ############################################# AUTH

def updateRegister(request):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    jsonData = request.get_json()
    if jsonData['id'] != "":
        try:
            cursor.execute("""
                UPDATE users
                SET name = '%s',
                    phone = '%s',
                    gender = '%s',
                    dateOfBirth = '%s',
                    address = '%s',
                    maritalStatus = '%s',
                    multipleBirth = '%s',
                    contactRelationship = '%s',
                    contactName = '%s',
                    contactPhone = '%s',
                    contactAddress = '%s',
                    contactGender = '%s',
                    languages = '%s',
                    preferredLanguage = '%s',
                    generalPractitioner = '%s'
                WHERE id = %s;
            """%(jsonData['name'], jsonData['phone'], jsonData['gender'], jsonData['dateOfBirth'], jsonData['address'], jsonData['maritalStatus'], jsonData['multipleBirth'], jsonData['contactRelationship'], jsonData['contactName'], jsonData['contactPhone'], jsonData['contactAddress'], jsonData['contactGender'], jsonData['languages'], jsonData['preferredLanguage'], jsonData['generalPractitioner'], jsonData['id']))
            conn.commit()
            return jsonify({'message': 'success'}), 200
        except:
            return "Intern Erro", 500
    return "Intern Erro", 500

def register(request):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    jsonData = request.get_json()
    if jsonData['login'] != "" and jsonData['password'] != "":
        try:
            pw_hash = bcrypt.generate_password_hash(jsonData['password']).decode('utf-8')
            cursor.execute("""
                INSERT INTO users(
                    login,
                    name,
                    phone,
                    password,
                    gender,
                    dateOfBirth,
                    address,
                    maritalStatus,
                    multipleBirth,
                    contactRelationship,
                    contactName,
                    contactPhone,
                    contactAddress,
                    contactGender,
                    languages,
                    preferredLanguage,
                    generalPractitioner,
                    walletConfig,
                    walletCredentials
                ) VALUES('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s')
            """%(jsonData['login'], jsonData['name'], jsonData['phone'], pw_hash, jsonData['gender'], jsonData['dateOfBirth'], jsonData['address'], jsonData['maritalStatus'], jsonData['multipleBirth'], jsonData['contactRelationship'], jsonData['contactName'], jsonData['contactPhone'], jsonData['contactAddress'], jsonData['contactGender'], jsonData['languages'], jsonData['preferredLanguage'], jsonData['generalPractitioner'], "", ""))
            conn.commit()
            return jsonData['login']
        except:
            return "Intern Erro"
    return "Intern Erro"

def login(request):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    jsonData = request.get_json()
    if jsonData['login'] != "" and jsonData['password'] != "":
        cursor.execute("SELECT * FROM users WHERE login='" + jsonData['login'] + "'")
        account = cursor.fetchone()
        if account[1] == jsonData['login'] and bcrypt.check_password_hash(account[4], jsonData['password']):
            token = jwt.encode({'login':jsonData['login'], 'exp': datetime.datetime.now() + datetime.timedelta(hours=12)}, SECRET_KEY)
            return jsonify(login=jsonData['login'],token=token.decode('UTF-8'))
        return "Bad Request", 400
    return "Intern Erro", 500

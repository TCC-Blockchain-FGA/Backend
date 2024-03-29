from app import app
from flask import Flask, request, jsonify, redirect, url_for
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
import jwt
from flask_cors import CORS, cross_origin
import app.controllers.database as database
import app.controllers.ssi as ssi
import asyncio
from functools import wraps
import requests
import json

ssi.init()

CORS(app, supports_credentials=True)
JWTManager(app)
bcrypt = Bcrypt(app)

SECRET_KEY = "SECRET_KEY"

def async_action(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapped

def auth(token):
    jsonData = request.get_json()
    data = jwt.decode(jsonData['token'], SECRET_KEY)
    user = database.user_by_login(data['login'])
    return user

@app.route("/testRequestsSend", methods=["GET", "POST"])
def testRequestsSend():
    URL = "https://146.190.157.57:5000/testRequestsReceiver"
    location = "Teste"
    PARAMS = {'data': location}
    r = requests.get(url = URL, params = PARAMS, verify=False)
    print(r)

    API_ENDPOINT = "https://146.190.157.57:5000/testRequestsReceiver"
    data = {'api_dev_key':'API_KEY',
            'api_option':'paste',
            'api_paste_code':'source_code',
            'api_paste_format':'python'}
    r = requests.post(url = API_ENDPOINT, data = data, verify=False)
    return "Success"

@app.route("/testRequestsReceiver", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
@async_action
async def testRequestsReceiver():
    if request.form.get('step') == '2':
        data = (request.form.get('c_cred_offer_json'), request.form.get('c_cred_def_id'))
    elif request.form.get('step') == '3':
        data = (request.form.get('c_cred_json'), request.form.get('c_cred_def_id'))
    else:
        data = request.form.get('data')
    res = await ssi.issue_credential(data, request.form.get('step'), request.form.get('login'))
    return res


@app.route("/testRequestsReceiver2", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
@async_action
async def testRequestsReceiver2():
    if request.form.get('step') != '1':
        data = (request.form.get('c_proof_req'), request.form.get('c_schema_id'), request.form.get('c_cred_def_id'))
    else:
        data = request.form.get('data')
    return await ssi.validate_credential(data, request.form.get('step'))


@app.route("/", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
@async_action
async def home():
    return "Success"

@app.route("/generateCredential", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
@async_action
async def generateCredential():
    database.saveCredential(request)
    jsonData = request.get_json()
    return "Success", 200

@app.route("/getCredentials", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def getCredentials():
    jsonData = request.get_json()
    return jsonify(database.get_credentials(jsonData['email']))

@app.route("/loginOrg", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def loginOrg():
    return database.login_org(request)

@app.route("/userData", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def userData():
    user = auth(request)
    if not user:
        return "Bad Request", 400
    return jsonify({"id": user[0], "login": user[1],"phone": user[2],"name": user[3],"gender": user[5],"dateOfBirth": user[6],"address": user[7],"maritalStatus": user[8],"multipleBirth": user[9],"contactRelationship": user[10],"contactName": user[11],"contactPhone": user[12],"contactAddress": user[13],"contactGender": user[14],"languages": user[15],"preferredLanguage": user[16],"generalPractitioner": user[17], "walletConfig": user[18], "walletCredentials": user[19]}), 200

@app.route("/login", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def login():
    return database.login(request)

@app.route("/register", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def register():
    return database.register(request)

@app.route("/userByLogin", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def userByLogin():
    jsonData = request.get_json()
    user = database.user_by_login(jsonData['login'])
    return jsonify(user)

@app.route("/updateRegister", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def updateRegister():
    return database.updateRegister(request)

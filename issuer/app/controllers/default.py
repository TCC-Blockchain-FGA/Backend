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

def auth(request):
    jsonData = request.get_json()
    data = jwt.decode(jsonData['token'], SECRET_KEY)
    user = database.user_by_login(data['login'])
    return user

@app.route("/testRequestsSend", methods=["GET", "POST"])
def testRequestsSend():
    URL = "https://146.190.157.57:5001/testRequestsReceiver"
    location = "Teste"
    PARAMS = {'data': location}
    r = requests.get(url = URL, params = PARAMS, verify=False)

    API_ENDPOINT = "https://146.190.157.57:5001/testRequestsReceiver"
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
    await ssi.issue_credential(request.args.get('login'))
    return "Success"

@app.route("/testRequestsReceiver2", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
@async_action
async def testRequestsReceiver2():
    await ssi.validate_credential()
    return "Success"

@app.route("/", methods=["GET", "POST"])
def home():
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
    return jsonify({"id": user[0], "login": user[1],"name": user[2],"phone": user[3],"verkey": user[5]}), 200

@app.route("/userByLogin", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def userByLogin():
    jsonData = request.get_json()
    user = database.user_by_login(jsonData['login'])
    return jsonify(user)

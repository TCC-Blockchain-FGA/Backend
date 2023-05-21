from app import app
from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
import jwt
from flask_cors import CORS, cross_origin
import app.controllers.database as database
import app.controllers.ssi as ssi

ssi.init()

CORS(app, support_credentials=True)
JWTManager(app)
bcrypt = Bcrypt(app)

SECRET_KEY = "SECRET_KEY"

def auth(token):
    jsonData = request.get_json()
    data = jwt.decode(jsonData['token'], SECRET_KEY)
    user = database.user_by_login(data['login'])
    return user

@app.route("/", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
async def home():
    await ssi.create_wallet_and_set_trust_anchor("nilo")
    return "OK"

@app.route("/userData", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def userData():
    user = auth(request)
    if not user:
        return "Bad Request", 400
    return jsonify({"login": user[1],"phone": user[2],"name": user[3],"gender": user[5],"dateOfBirth": user[6],"address": user[7],"maritalSates": user[8],"multipleBirth": user[9],"contactRelationship": user[10],"contactName": user[11],"contactPhone": user[12],"contactAddress": user[13],"contactGender": user[14],"languages": user[15],"preferredLanguage": user[16],"generalPractitioner": user[17]}), 200

@app.route("/login", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def login():
    return database.login(request)

@app.route("/register", methods=["GET", "POST"])
@cross_origin(supports_credentials=True)
def register():
    return database.register(request)

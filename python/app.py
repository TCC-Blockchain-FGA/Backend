from flask import Flask
import database as database
import ssi as ssi

app = Flask(__name__)

ssi.init()

@app.route("/")
async def home():
    await ssi.create_wallet_and_set_trust_anchor("nilo")
    return "OK"

@app.route('/db')
def index():
    print(database.get_books())
    return "ok"

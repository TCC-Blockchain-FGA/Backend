from app import app

if __name__ == "__main__":
	# app.run(ssl_context=("cert.pem", "key.pem"), debug=True, host='0.0.0.0')
	app.run(debug=True, host='0.0.0.0', ssl_context='adhoc')

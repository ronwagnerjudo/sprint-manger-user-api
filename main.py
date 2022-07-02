import os
import json
from pickle import TRUE
import flask
import jwt
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request


#--------------------------------APP CONFIG-----------------------------------------
app = flask.Flask(__name__)
app.secret_key = os.urandom(12).hex()
CORS(app,  supports_credentials=True)

#------------------------------DATEBASE----------------------------------------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users-sprint-manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class UsersSprintManager(db.Model):
	__tablename__ = "users"
	id = db.Column(db.Integer, primary_key=True)
	credentials = db.Column(db.Text, unique=True)
	sub = db.Column(db.String(100), unique=True)
	user_preference = db.Column(db.String(20))
	sprint_time = db.Column(db.Integer)
	start_work_hours = db.Column(db.Integer)
	end_work_hours = db.Column(db.Integer)

db.create_all()
db.session.commit()

#--------------------------------JWT--------------------------------------------------
JWT_SECRET = "app.secret_key"
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 600

#--------------------------------GOOGLE SCOPES----------------------------------------
google_scopes = ['openid', 'https://www.googleapis.com/auth/calendar', 
		'https://www.googleapis.com/auth/userinfo.email', 
		'https://www.googleapis.com/auth/userinfo.profile']

def credentials_to_dict(credentials):
	return {'token': credentials.token,
		'refresh_token': credentials.refresh_token,
		'token_uri': credentials.token_uri,
		'client_id': credentials.client_id,
		'client_secret': credentials.client_secret,
		'scopes': credentials.scopes}


#--------------------------------APP--------------------------------------------------
@app.route('/login', methods=["GET", "POST"])
def login():
	flow = Flow.from_client_secrets_file("./client_secret.json", scopes=google_scopes)
	flow.redirect_uri = flask.request.base_url + "/callback"
	# Enable offline access so that you can refresh an access token without
	# re-prompting the user for permission. Recommended for web server apps.
	# Enable incremental authorization. Recommended as a best practice.
	authorization_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="consent")
	
	# Store the state so the callback can verify the auth server response.
	flask.session["state"] = state
	return flask.redirect(authorization_url)

@app.route('/login/callback', methods=["GET", "POST"])
def callback():
	# Specify the state when creating the flow in the callback so that it can
	# verified in the authorization server response.
	if not flask.session["state"] == flask.request.args["state"]:
		flask.abort(403)
	state = flask.session["state"]

	flow = Flow.from_client_secrets_file("./client_secret.json", scopes=google_scopes, state=state)
	flow.redirect_uri = flask.url_for("callback", _external=True)

	# Use the authorization server's response to fetch the OAuth 2.0 tokens.
	authorization_response = flask.request.url
	flow.fetch_token(authorization_response=authorization_response)
	credentials = flow.credentials
	credentials_dict = credentials_to_dict(credentials) 

	token = credentials_dict["token"]
	userinfo_response = requests.get(f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={token}")
	userinfo = userinfo_response.json()
	sub_id = userinfo["id"]

	# Adding new user info (sub id and creds) into the db, if the user still don't  exist
	user_exists = UsersSprintManager.query.filter_by(sub=sub_id).first()
	if not user_exists:
		new_user = UsersSprintManager(
			credentials = json.dumps(credentials_dict),
			sub = sub_id,
			user_preference = "",
			sprint_time = 14,
			start_work_hours = 9,
			end_work_hours = 19
		)
		db.session.add(new_user)
		db.session.commit()

	jwt_token = jwt.encode({"sub": sub_id}, JWT_SECRET, JWT_ALGORITHM)
	 
	resp = flask.make_response(flask.redirect("http://127.0.0.1:3000/tasks"))
	resp.set_cookie("jwt", jwt_token)
	return resp

@app.route('/userinfo')
def userinfo():
	if not flask.request.cookies.get("jwt"):
		response = flask.jsonify({"status": 401, "error": "Missing Creds"})
		return response, 401
	try: 
		cookie_jwt = jwt.decode(flask.request.cookies.get("jwt"), JWT_SECRET, JWT_ALGORITHM)
		user = UsersSprintManager.query.filter_by(sub=cookie_jwt["sub"]).first()
		credentials = json.loads(user.credentials)
		creds = Credentials.from_authorized_user_info(credentials, google_scopes)
		if not creds or not creds.valid:
			if creds and creds.expired and creds.refresh_token:
				creds.refresh(Request())
				credentials = credentials_to_dict(creds)
				refreshed_creds_text = json.dumps(credentials)
				current_user = cookie_jwt["sub"]
				creds_to_update = UsersSprintManager.query.filter_by(sub=current_user).first()
				creds_to_update.credentials = refreshed_creds_text
				db.session.commit()

			else:
				return 401

		token = credentials["token"]
		userinfo_response = requests.get(f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={token}")
		userinfo = userinfo_response.json()

		return flask.jsonify({"email": userinfo["email"], "picture": userinfo["picture"]}), 200
	except jwt.ExpiredSignatureError:
		response = flask.jsonify({"status": 401, "error": "Expried permissons!"})
		return response, 401
	except ValueError:
		print(ValueError)
		response = flask.jsonify({"status": 401, "error": "Not Valid creds!"})
		return response, 401

@app.route('/user-settings', methods=["GET", "POST"])
def user_settings():
	if not flask.request.cookies.get("jwt"):
		response = flask.jsonify({"status": 401, "error": "Missing Creds"})
		return response, 401
	try:
		cookie_jwt = jwt.decode(flask.request.cookies.get("jwt"), JWT_SECRET, JWT_ALGORITHM)
		
		if cookie_jwt:
			sub = cookie_jwt["sub"]
			user = UsersSprintManager.query.filter_by(sub=sub).first()
			if user:
				user_preference = flask.request.form.get("user_preference")
				sprint_time = flask.request.form.get("sprint_time")
				start_work_hours = flask.request.form.get("start_work_hours")
				end_work_hours = flask.request.form.get("end_work_hours")

				user.user_preference = user_preference
				user.sprint_time = sprint_time
				user.start_work_hours = start_work_hours
				user.end_work_hours = end_work_hours
				db.session.commit()

				return flask.jsonify({"message": "User settings changed"}), 200

	except jwt.ExpiredSignatureError:
		response = flask.jsonify({"status": 401, "error": "Expried permissons!"})
		return response, 401
	except ValueError:
		print(ValueError)
		response = flask.jsonify({"status": 401, "error": "Not Valid creds!"})
		return response, 401

@app.route('/get-user-details', methods=["GET", "POST"])
def get_user_details():
	if not flask.request.cookies.get("jwt"):
		response = flask.jsonify({"status": 401, "error": "Missing Creds"})
		return response, 401
	print(type(flask.request.cookies.get("jwt")))
	try:
		cookie_jwt = jwt.decode(flask.request.cookies.get("jwt"), JWT_SECRET, JWT_ALGORITHM)
		
		if cookie_jwt:
			sub = cookie_jwt["sub"]
			user = UsersSprintManager.query.filter_by(sub=sub).first()
			if user:
				user_creds_json = json.loads(user.credentials)
				user_preference = user.user_preference
				user_sprint_time = user.sprint_time
				user_start_work_hours = user.start_work_hours
				user_end_work_hours = user.end_work_hours
				return flask.jsonify(user_details={"sub": sub, "userCredentials": user_creds_json, "userPreference": user_preference,
				 "userSprintTime": user_sprint_time, "userStartWorkHours": user_start_work_hours, "userEndWorkHours": user_end_work_hours}), 200
			else:
				return flask.jsonify({"error": "User credntials not found"}), 404
		else:
			return flask.jsonify({"error": "Not valid token"}), 403


	except jwt.ExpiredSignatureError:
		response = flask.jsonify({"status": 401, "error": "Expried permissons!"})
		return response, 401
	except ValueError:
		print(ValueError)
		response = flask.jsonify({"status": 401, "error": "Not Valid creds!"})
		return response, 401


@app.route('/logout')
def logout():
	resp = flask.make_response(flask.redirect("http://127.0.0.1:3000"))
	resp.delete_cookie("jwt")
	return resp

if __name__ == '__main__':
	app.run(port=5000, debug=True)

# export OAOUTHLIB_INSECURE_TRANSPORT=true
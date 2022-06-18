import os
import json
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
    sub = db.Column(db.String, unique=True)

db.create_all()
db.session.commit()

#--------------------------------JWT--------------------------------------------------
JWT_SECRET = 'secret'
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
@app.route('/login', methods=["GET","POST"])
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
            sub = sub_id
        )
        db.session.add(new_user)
        db.session.commit()

    jwt_token = jwt.encode({"sub": sub_id}, JWT_SECRET, JWT_ALGORITHM)

    resp = flask.make_response(flask.redirect("https://127.0.0.1:3000/tasks"))
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
        print(credentials)
        creds = Credentials(credentials)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                refreshed_creds = creds.refresh(Request())
                credentials = credentials_to_dict(refreshed_creds)
                print(credentials)
                refreshed_creds_text = json.dumps(credentials)
                current_user = cookie_jwt["sub"]
                print("!!!!!!!!!!!!!!!!!!!!")
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


@app.route('/get-credentials', methods=["POST"])
def get_creds():
    if not flask.request.cookies.get("jwt"):
        response = flask.jsonify({"status": 401, "error": "Missing Creds"})
        return response, 401
    try:
        cookie_jwt = jwt.decode(flask.request.cookies.get("jwt"), JWT_SECRET, JWT_ALGORITHM)
        
        if cookie_jwt:
            sub = cookie_jwt["sub"]
            user = UsersSprintManager.query.filter_by(sub=sub).first()
            if user:
                user_creds_json = json.loads(user.credentials)
                return flask.jsonify({"sub": sub, "user_credentials": user_creds_json}), 200
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
    resp = flask.make_response(flask.redirect("https://127.0.0.1:3000"))
    resp.delete_cookie("jwt")
    return resp

if __name__ == '__main__':
    app.run(port=5000, debug=True, ssl_context='adhoc')
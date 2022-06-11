import os
import json
import flask
import jwt
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request

# app config
app = flask.Flask(__name__)
app.secret_key = os.urandom(12)
CORS(app,  supports_credentials=True)

# db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users-sprint-manager.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class UsersSprintManager(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    credentials = db.Column(db.Text, unique=True)
    sub_id = db.Column(db.String, unique=True)

db.create_all()
  
# jwt
JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 600

# google scopes
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

@app.route('/login', methods=["GET","POST"])
def login():
    flow = Flow.from_client_secrets_file('./client_secrets.json', scopes=google_scopes)
    flow.redirect_uri = flask.request.base_url + "/callback"
    # Enable offline access so that you can refresh an access token without
    # re-prompting the user for permission. Recommended for web server apps.
    # Enable incremental authorization. Recommended as a best practice.
    authorization_url, state = flow.authorization_url(access_type='offline',include_granted_scopes='true')
    
    # Store the state so the callback can verify the auth server response.
    flask.session['state'] = state
    return flask.redirect(authorization_url)

@app.route('/login/callback', methods=["GET", "POST"])
def callback():
    # Specify the state when creating the flow in the callback so that it can
    # verified in the authorization server response.
    state = flask.session['state']

    flow = Flow.from_client_secrets_file('./client_secrets.json', scopes=google_scopes, state=state)
    flow.redirect_uri = flask.url_for("callback", _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = credentials_to_dict(flow.credentials) #save in database and sub id

    token = credentials["token"]
    userinfo_response = requests.get(f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={token}")
    userinfo = userinfo_response.json()
    sub_id = userinfo["sub"]

    # Adding new user info (sub id and creds0 into the db, if the user still don't  exist
    new_user = UsersSprintManager(
        credentials = json.dumps(credentials),
        sub_id = sub_id
    )
    db.session.add(new_user)
    db.session.commit()

    jwt_token = jwt.encode(sub_id, JWT_SECRET, JWT_ALGORITHM)

    resp = flask.make_response(flask.redirect("https://127.0.0.1:3000/tasks"))
    resp.set_cookie("creds", jwt_token)
    return resp, flask.jsonify({credentials})

@app.route('/userinfo')
def userinfo():
    if not flask.request.cookies.get('creds'):
        response = flask.jsonify({"status": 401, "error": "Missing Creds"})
        return response, 401
    try: 
        google_creds = jwt.decode(flask.request.cookies.get('creds'), JWT_SECRET, JWT_ALGORITHM)
        creds = Credentials(google_creds)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                return 401
        
        token = google_creds["token"]
        userinfo_response = requests.get(f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={token}")
        userinfo = userinfo_response.json()

        return flask.jsonify(user_info={"email": userinfo["email"], "picture": userinfo["picture"]}), 200
    except jwt.ExpiredSignatureError:
        response = flask.jsonify({"status": 401, "error": "Expried permissons!"})
        return response, 401
    except ValueError:
        print(ValueError)
        response = flask.jsonify({"status": 401, "error": "Not Valid creds!"})
        return response, 401


@app.route("/logout")
def logout():
    resp = flask.make_response(flask.redirect("https://127.0.0.1:3000"))
    resp.delete_cookie("creds")
    return resp

if __name__ == '__main__':
    app.run(port=5000, debug=True)
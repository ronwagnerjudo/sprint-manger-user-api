import os
import json
import flask
import jwt
import logging
from datetime import datetime, timedelta
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
import requests
from google.oauth2 import id_token
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request

logging.basicConfig(level=logging.INFO)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

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
    sprint_start_date = db.Column(db.String(20))
    sprint_end_date = db.Column(db.String(20))
    start_work_hours = db.Column(db.Integer)
    end_work_hours = db.Column(db.Integer)

db.create_all()
db.session.commit()

#--------------------------------JWT--------------------------------------------------
JWT_SECRET = os.environ["GOOGLE_JWT_SECRET"]
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 600

#--------------------------------GOOGLE SCOPES----------------------------------------
google_scopes = ['openid', 'https://www.googleapis.com/auth/calendar', 
        'https://www.googleapis.com/auth/userinfo.email', 
        'https://www.googleapis.com/auth/userinfo.profile']

GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]

def credentials_to_dict(credentials):
    return {'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes}

#------------------------------------------FUNCTIONS------------------------------------

def default_sprint_start():
    today = datetime.today()
    tomorrow = today + timedelta(days=1)

    return datetime.strftime(tomorrow, "%d/%m/%Y")

def default_sprint_end():
    today = datetime.today()
    tomorrow = today + timedelta(days=15)

    return datetime.strftime(tomorrow, "%d/%m/%Y")


#--------------------------------APP--------------------------------------------------
@app.route('/', methods=["GET"])
def status():
    return {'status': "200"}, 200

@app.route('/login', methods=["GET", "POST"])
def login():
    logging.info("Starting flow.")
    flow = Flow.from_client_secrets_file("./client_secret.json", scopes=google_scopes)
    flow.redirect_uri = flask.request.host_url + "api/user-api/login/callback"
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
    logging.info("Checking state.")
    if not flask.session["state"] == flask.request.args["state"]:
        logging.info("No state.")
        flask.abort(403)
    state = flask.session["state"]
    logging.info("Comparing state.")

    flow = Flow.from_client_secrets_file("./client_secret.json", scopes=google_scopes, state=state)
    flow.redirect_uri = flask.request.host_url + "api/user-api/login/callback"

    # Use the authorization server's response to fetch the OAuth 2.0 tokens.
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)
    logging.info("Access token fetched")
    credentials = flow.credentials
    credentials_dict = credentials_to_dict(credentials)

    token_id = flow.oauth2session.token["id_token"] 
    try:
        logging.info("Verify ID token.")
        idinfo = id_token.verify_oauth2_token(token_id, Request(), GOOGLE_CLIENT_ID)
        sub_id = idinfo['sub']
        logging.info("ID token is valid.")
    except ValueError:
        logging.info("Invalid token.")
        return flask.jsonify({"error": f"Sorry, invalid token. {ValueError}"})

    # Adding new user info (sub id and creds) into the db, if the user still don't  exist.
    logging.info("Querying db.")
    user_exists = UsersSprintManager.query.filter_by(sub=sub_id).first()
    if not user_exists:
        logging.info("Adding new user to db.")
        new_user = UsersSprintManager(
            credentials = json.dumps(credentials_dict),
            sub = sub_id,
            user_preference = "",
            sprint_start_date = default_sprint_start(),
            sprint_end_date = default_sprint_end(),
            start_work_hours = 9,
            end_work_hours = 19
        )
        db.session.add(new_user)
        db.session.commit()
        logging.info("New user add to db.")

    logging.info("Creating JWT.")
    jwt_token = jwt.encode(idinfo, JWT_SECRET, JWT_ALGORITHM)
    resp = flask.make_response(flask.redirect(flask.request.host_url))
    logging.info("Setting cookie.")
    resp.set_cookie("jwt", jwt_token)
    return resp

@app.route('/userinfo')
def userinfo():
    if not flask.request.cookies.get("jwt"):
        logging.info("JWT not found.")
        response = flask.jsonify({"status": 401, "error": "Missing Creds"})
        return response, 401
    try:
        logging.info("Decoding JWT.") 
        cookie_jwt = jwt.decode(flask.request.cookies.get("jwt"), JWT_SECRET, JWT_ALGORITHM, audience=GOOGLE_CLIENT_ID)
        logging.info("JWT decoded.")
        logging.info("Finding user acording to the JWT.")
        user = UsersSprintManager.query.filter_by(sub=cookie_jwt["sub"]).first()
        if user:
            logging.info("User found in the DB.")
            credentials = json.loads(user.credentials)
            creds = Credentials.from_authorized_user_info(credentials, google_scopes)
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    logging.info("Creds expired.")
                    try:
                        creds.refresh(Request())
                        logging.info("Creds refreshed.")
                    except:
                        logging.info("Credentials could not be refreshed.")
                        return flask.jsonify({"error": "Credentials could not be refreshed, possibly the authorization was revoked by the user."}), 500
                    credentials = credentials_to_dict(creds)
                    refreshed_creds_text = json.dumps(credentials)
                    current_user = cookie_jwt["sub"]
                    logging.info("Searching user in DB.")
                    creds_to_update = UsersSprintManager.query.filter_by(sub=current_user).first()
                    creds_to_update.credentials = refreshed_creds_text
                    db.session.commit()
                    logging.info("Updated new creds.")
                else:
                    return flask.jsonify({"error": "No creds/creds not expired/no refresh token."}), 401
        else:
            logging.info("User was not found in DB.")
            return flask.jsonify({"message": "Sorry, user was not found in the DB."}), 404

        token = credentials["token"]
        logging.info("Init get response to google userinfo.")
        try:
            userinfo_response = requests.get(f"https://www.googleapis.com/oauth2/v1/userinfo?access_token={token}")
            logging.info("Sent get request to google userinfo.")
        except:
            logging.info("Problem with the response to google userinfo.")
            return flask.jsonify({"message": "Problem with response."}), userinfo_response.status_code

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
        logging.info("JWT not found.")
        response = flask.jsonify({"status": 401, "error": "Missing Creds"})
        return response, 401
    try:
        logging.info("Decoding JWT.")
        cookie_jwt = jwt.decode(flask.request.cookies.get("jwt"), JWT_SECRET, JWT_ALGORITHM, audience=GOOGLE_CLIENT_ID)
        if cookie_jwt:
            logging.info("JWT decoded.")
            sub = cookie_jwt["sub"]
            logging.info("Searching user by JWT.")
            user = UsersSprintManager.query.filter_by(sub=sub).first()
            if user:
                logging.info("User found.")
                data = json.loads(flask.request.data)
                user_preference = data["user_preference"]
                sprint_start_date = data["sprint_start_date"]
                sprint_end_date = data["sprint_end_date"]
                start_work_hours = data["start_work_hours"]
                end_work_hours = data["end_work_hours"]
                logging.info("Getting data from the front-end")

                user.user_preference = user_preference
                user.sprint_start_date = sprint_start_date
                user.sprint_end_date = sprint_end_date
                user.start_work_hours = start_work_hours
                user.end_work_hours = end_work_hours
                db.session.commit()
                logging.info("Changed user settings in the DB.")
                return flask.jsonify({"message": "User settings changed"}), 200

            else:
                logging.info("User not found in DB.")
                return flask.jsonify({"error": "User not found in DB"}), 404
        else:
            logging.info("JWT token not valid.")
            return flask.jsonify({"error": "Not valid token."}), 403

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
        logging.info("JWT not found.")
        response = flask.jsonify({"status": 401, "error": "Missing Creds"})
        return response, 401

    try:
        logging.info("Decoding JWT.")
        cookie_jwt = jwt.decode(flask.request.cookies.get("jwt"), JWT_SECRET, JWT_ALGORITHM, audience=GOOGLE_CLIENT_ID)
        if cookie_jwt:
            logging.info("JWT decoded.")
            sub = cookie_jwt["sub"]
            logging.info("Searching user by JWT.")
            user = UsersSprintManager.query.filter_by(sub=sub).first()
            if user:
                logging.info("User found.")
                user_creds_json = json.loads(user.credentials)
                user_preference = user.user_preference
                user_sprint_start_date = user.sprint_start_date
                user_sprint_end_date = user.sprint_end_date
                user_start_work_hours = user.start_work_hours
                user_end_work_hours = user.end_work_hours
                
                return flask.jsonify(user_details={"sub": sub, "userCredentials": user_creds_json,
                 "userSprintStartDate": user_sprint_start_date, "userSprintEndtDate": user_sprint_end_date, "userStartWorkHours": user_start_work_hours, "userEndWorkHours": user_end_work_hours}), 200
            else:
                logging.info("User not found in DB.")
                return flask.jsonify({"error": "User not found in DB"}), 404
        else:
            logging.info("JWT token not valid.")
            return flask.jsonify({"error": "Not valid token"}), 403

    except jwt.ExpiredSignatureError:
        response = flask.jsonify({"status": 401, "error": "Expried permissons!"})
        return response, 401
    except ValueError:
        print(ValueError)
        response = flask.jsonify({"status": 401, "error": "Not Valid creds!"})
        return response, 401

@app.route('/get-user-private-details')
def user_private_details():
    if not flask.request.cookies.get("jwt"):
        logging.info("JWT not found.")
        response = flask.jsonify({"status": 401, "error": "Missing Creds"})
        return response, 401

    try:
        logging.info("Decoding JWT.")
        cookie_jwt = jwt.decode(flask.request.cookies.get("jwt"), JWT_SECRET, JWT_ALGORITHM, audience=GOOGLE_CLIENT_ID)
        if cookie_jwt:
            logging.info("JWT decoded.")
            sub = cookie_jwt["sub"]
            logging.info("Searching user by JWT.")
            user = UsersSprintManager.query.filter_by(sub=sub).first()
            if user:
                logging.info("User found.")
                user_creds_json = json.loads(user.credentials)
                user_preference = user.user_preference
                user_sprint_start_date = user.sprint_start_date
                user_sprint_end_date = user.sprint_end_date
                user_start_work_hours = user.start_work_hours
                user_end_work_hours = user.end_work_hours
                
                return flask.jsonify(user_details={"sub": sub, "userCredentials": user_creds_json, "userPreference": user_preference,
                 "userSprintStartDate": user_sprint_start_date, "userSprintEndtDate": user_sprint_end_date, "userStartWorkHours": user_start_work_hours, "userEndWorkHours": user_end_work_hours}), 200
            else:
                logging.info("User not found in DB.")
                return flask.jsonify({"error": "User not found in DB"}), 404
        else:
            logging.info("JWT token not valid.")
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
    resp = flask.make_response(flask.redirect(flask.request.host_url))
    resp.delete_cookie("jwt")
    logging.info("User loged out.")
    return resp

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=True)


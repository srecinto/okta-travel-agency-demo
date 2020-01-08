import base64
import json
import csv

from config import default_settings

from flask import Flask, render_template, url_for, redirect, session, jsonify, request
from flask_oidc import OpenIDConnect
from utils.okta import OktaAuth, OktaAdmin

app = Flask(__name__)

with open('client_secrets.json', 'w') as outfile:
    oidc_config = {
        "web": {
            "auth_uri": "{0}/v1/authorize".format(default_settings["issuer"]),
            "client_id": default_settings["client_id"],
            "client_secret": default_settings["client_secret"],
            "redirect_uris": [
                default_settings["redirect_uri"]
            ],
            "okta_api_token": default_settings["okta_api_token"],
            "issuer": "{0}".format(default_settings["issuer"]),
            "token_uri": "{0}/v1/token".format(default_settings["issuer"]),
            "token_introspection_uri": "{0}/v1/introspect".format(default_settings["issuer"]),
            "userinfo_uri": "{0}/v1/userinfo".format(default_settings["issuer"])
        }
    }
    
    json.dump(oidc_config, outfile)

app.config.update({
    'SECRET_KEY': default_settings["app_secret_key"],
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_RESOURCE_SERVER_ONLY': True,
    'OIDC_DEBUG': True,
    'OIDC_COOKIE_SECURE': True,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_INTROSPECTION_AUTH_METHOD': 'bearer',
    'OIDC_SCOPES': ["openid", "profile", "email", "offline_access"],
    # 'OVERWRITE_REDIRECT_URI': 'https://fa5b4be2a1d7479989c0cb3a8c57628c.vfs.cloud9.us-east-2.amazonaws.com/authorization-code/callback',
    'OIDC_CALLBACK_ROUTE': '/authorization-code/callback'
})


oidc = OpenIDConnect(app)

@app.route("/")
def home():
    return render_template("home.html", oidc=oidc)


@app.route("/login")
def login():
    bu = oidc.client_secrets['issuer'].split('/oauth2')[0]
    cid = oidc.client_secrets['client_id']

    destination = "{0}/profile".format(default_settings["settings"]["app_base_url"])
    state = {
        'csrf_token': session['oidc_csrf_token'],
        'destination': oidc.extra_data_serializer.dumps(destination).decode('utf-8')
    }
    return render_template("login.html", config=default_settings, oidc=oidc, baseUri=bu, clientId=cid, state=base64.b64encode(bytes(json.dumps(state),'utf-8')).decode('utf-8'))


@app.route("/profile")
def profile():
    info = oidc.user_getinfo(["sub", "name", "email", "locale"])
    access_token = oidc.get_access_token()
    print("access_token: {0}".format(access_token))
    okta_admin = OktaAdmin(default_settings)
    user = okta_admin.get_user(info["sub"])
    # user_profile = user["profile"]
    # app_user = okta_admin.get_user_application_by_current_client_id(user["id"])
    app_info = okta_admin.get_applications_by_user_id(user["id"])
    app_list = []
    for app_data in app_info:
        parsed_input = json.loads(json.dumps(app_data))
        app_name = parsed_input["label"]
        app_url = parsed_input["_links"]["appLinks"][0]["href"]
        app_logo = parsed_input["_links"]["logo"][0]["href"]
        app_dict= dict(appname=app_name,appurl=app_url,applogo=app_logo)
        app_list.append(app_dict)


    print(info)
    print(app_list)
    return render_template("profile.html", profile=info, oidc=oidc, applist=app_list)


@app.route("/logout", methods=["POST"])
def logout():
    oidc.logout()

    return redirect(url_for("home", _external="True", _scheme="https"))

@app.route("/import")
def importusers():
    info = oidc.user_getinfo(["sub", "name", "email", "locale"])

    return render_template("import.html", profile=info, oidc=oidc)

@app.route('/upload.html',methods = ['POST'])
def upload_route_summary():
    if request.method == 'POST':
        info = oidc.user_getinfo(["sub", "name", "email", "locale"])

        # Create variable for uploaded file
        f = request.files['fileupload']

        #store the file contents as a string
        fstring = f.read().decode('utf-8')

        #create list of dictionaries keyed by header row
        csv_dicts = [{k: v for k, v in row.items()} for row in csv.DictReader(fstring.splitlines(), skipinitialspace=True)]

        for user_info in csv_dicts:
            okta_admin = OktaAdmin(default_settings)
            info = oidc.user_getinfo(["sub", "name", "email", "locale"])
            user_data = {
                "profile": {
                    "firstName": user_info['firstName'].replace("'", ""),
                    "lastName": user_info['lastName'].replace("'", ""),
                    "email": user_info['email'].replace("'", ""),
                    "login": user_info['email'].replace("'", ""),
                    "mobilePhone": user_info['mobilePhone'].replace("'", "")
                }
            }
            app_info = okta_admin.create_user(user_data,True)
            print(app_info)

    return render_template("upload.html", profile=info, oidc=oidc)


if __name__ == '__main__':
    app.run(host="localhost", port=8080, debug=True)

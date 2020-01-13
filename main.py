import os
import base64
import json
import csv

from config import default_settings

from flask import Flask, render_template, url_for, redirect, session, jsonify, request
from flask import send_from_directory
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

    # print("oidc_config: {0}".format(json.dumps(oidc_config, indent=4, sort_keys=True)))
    # print("default_settings: {0}".format(default_settings))

    json.dump(oidc_config, outfile, indent=4, sort_keys=True)

    app_config = {
        'SECRET_KEY': default_settings["app_secret_key"],
        'PREFERRED_URL_SCHEME': 'https',
        'OIDC_CLIENT_SECRETS': 'client_secrets.json',
        'OIDC_DEBUG': True,
        'OIDC_COOKIE_SECURE': True,
        'OIDC_USER_INFO_ENABLED': True,
        'OIDC_INTROSPECTION_AUTH_METHOD': 'bearer',
        'OIDC_SCOPES': ["openid", "profile", "email", "offline_access"],
        'OVERWRITE_REDIRECT_URI': default_settings["redirect_uri"],
        'OIDC_CALLBACK_ROUTE': '/authorization-code/callback'
    }

    # print("app_config: {0}".format(app_config))

app.config.update(app_config)

oidc = OpenIDConnect(app)

@app.route('/<path:filename>')
def serve_static_html(filename):
    """ serve_static_html() generic route function to serve files in the 'static' folder """
    print("serve_static_html('{0}')".format(filename))
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static'), filename)


@app.route("/")
def home():
    user_info = get_user_info()

    return render_template("home.html", oidc=oidc, user_info=user_info)


@app.route("/login")
def login():
    destination = "{0}/profile".format(default_settings["settings"]["app_base_url"])
    state = {
        'csrf_token': session['oidc_csrf_token'],
        'destination': oidc.extra_data_serializer.dumps(destination).decode('utf-8')
    }
    return render_template("login.html", config=default_settings, oidc=oidc, state=base64.b64encode(bytes(json.dumps(state),'utf-8')).decode('utf-8'))


@app.route("/signup")
def signup():

    return render_template("signup.html", config=default_settings, oidc=oidc)


@app.route("/profile")
def profile():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)
    user = okta_admin.get_user(user_info["sub"])
    print(user)
    app_info = okta_admin.get_applications_by_user_id(user["id"])

    return render_template("profile.html", oidc=oidc, applist=app_info, user_info=user_info)


@app.route("/logout")
def logout():
    oidc.logout()

    return redirect(url_for("home", _external="True", _scheme="https"))


@app.route("/import")
def importusers():
    user_info = get_user_info()

    return render_template("import.html", user_info=user_info, oidc=oidc)


@app.route('/upload',methods = ['POST'])
def upload_route_summary():
    if request.method == 'POST':
        user_info = get_user_info()
        okta_admin = OktaAdmin(default_settings)
        
        # List Group and find a Travel Agency
        user = okta_admin.get_user(user_info["sub"])
        group_info = okta_admin.get_user_groups(user["id"])
        for group_data in group_info:
            print(group_data)
            if "TravelAgency_" in group_data["profile"]["name"]:
                group_name = group_data["profile"]["name"]
                break

        # Create variable for uploaded file
        f = request.files['fileupload']

        #store the file contents as a string
        fstring = f.read().decode('utf-8')

        #create list of dictionaries keyed by header row
        csv_dicts = [{k: v for k, v in row.items()} for row in csv.DictReader(fstring.splitlines(), skipinitialspace=True)]
        return_list = []
        return_users = []
        for user_record in csv_dicts:
            user_data = {
                "profile": {
                    "firstName": user_record['firstName'].replace("'", ""),
                    "lastName": user_record['lastName'].replace("'", ""),
                    "email": user_record['email'].replace("'", ""),
                    "login": user_record['email'].replace("'", ""),
                    "mobilePhone": user_record['mobilePhone'].replace("'", ""),
                    "travelAgencyGroup": group_name
                }
            }
            return_users.append(user_data)
            import_users = okta_admin.create_user(user_data,True)
            return_list.append(import_users)
            
    return render_template("upload.html", user_info=user_info, oidc=oidc,returnlist=return_list, userlist=return_users)



@app.route("/users")
def users():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)
    
    # List Group and find a Travel Agency
    user = okta_admin.get_user(user_info["sub"])
    group_info = okta_admin.get_user_groups(user["id"])
    for group_data in group_info:
        print(group_data)
        if "TravelAgency_" in group_data["profile"]["name"]:
            group_id = group_data["id"]
            break

    group_user_list = okta_admin.get_user_list_by_group_id(group_id)
    return render_template("users.html", user_info=user_info, oidc=oidc, groupinfo=group_info,userlist= group_user_list)


@app.route("/suspenduser")
def suspenduser():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)
    user_id = request.args.get('user_id')
    suspend_user = okta_admin.suspend_user(user_id)
    user_info2 = okta_admin.get_user(user_id)

    if not suspend_user:
        message = "User " + user_info2['profile']['firstName'] + " "+  user_info2['profile']['lastName'] +  " Suspended"
    else:
        message = "Error During Suspension"    
    
    return redirect(url_for("users", _external="True", _scheme="https",message=message))

@app.route("/unsuspenduser")
def unsuspenduser():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)
    user_id = request.args.get('user_id')
    unsuspend_user = okta_admin.unsuspend_user(user_id)
    user_info2 = okta_admin.get_user(user_id)

    if not unsuspend_user:
        message = "User " + user_info2['profile']['firstName'] + " "+  user_info2['profile']['lastName'] +  " Un-Suspended"
    else:
        message = "Error During Un-Suspension"    
    
    return redirect(url_for("users", _external="True", _scheme="https",message=message))

@app.route("/resetpassword")
def resetpassword():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)
    user_id = request.args.get('user_id')
    reset_password = okta_admin.reset_password_for_user(user_id)
    user_info2 = okta_admin.get_user(user_id)

    if not reset_password:
        message = "Password Reset for User " + user_info2['profile']['firstName'] + " "+  user_info2['profile']['lastName'] 
    else:
        message = "Error During Password Reset"    
        
    return redirect(url_for("users", _external="True", _scheme="https",message=message))

@app.route("/userupdate")
def userupdate():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)
    user_id = request.args.get('user_id')
    user_info2 = okta_admin.get_user(user_id)

    return render_template("userupdate.html", user_info=user_info, oidc=oidc, user_info2=user_info2)
    
    
@app.route("/updateuserinfo", methods=["POST"])
def updateuserinfo():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)
    user_id = request.form.get('user_id')
    first_name = request.form.get('firstname')
    last_name = request.form.get('lastname')
    email = request.form.get('email')
    mobile_phone = request.form.get('phonenumber')

    user_data = {
                "profile": {
                    "firstName": first_name,
                    "lastName": last_name,
                    "email": email,
                    "mobilePhone": mobile_phone
                }
            }
    user_update_response = okta_admin.update_user(user_id,user_data)

    if user_update_response:
        message = "User " + first_name + " "+  last_name+ " was Updated"
    else:
        message = "Error During Update"    
        
    
    return redirect(url_for("userupdate", _external="True", _scheme="https",user_id=user_id,message=message))
    

@app.route("/usercreate")
def usercreate():
    user_info = get_user_info()

    return render_template("usercreate.html", user_info=user_info, oidc=oidc)
    
@app.route("/createuserinfo", methods=["POST"])
def createuserinfo():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)
    first_name = request.form.get('firstname')
    last_name = request.form.get('lastname')
    email = request.form.get('email')
    mobile_phone = request.form.get('phonenumber')

    # List Group and find a Travel Agency
    user = okta_admin.get_user(user_info["sub"])
    group_info = okta_admin.get_user_groups(user["id"])
    for group_data in group_info:
        print(group_data)
        if "TravelAgency_" in group_data["profile"]["name"]:
            group_name = group_data["profile"]["name"]
            break
        
    user_data = {
                "profile": {
                    "firstName": first_name,
                    "lastName": last_name,
                    "email": email,
                    "login": email,
                    "mobilePhone": mobile_phone,
                    "travelAgencyGroup": group_name
                }
            }
    user_create_response = okta_admin.create_user(user_data)
    if user_create_response:
        message = "User " + first_name + " "+  last_name+ " was Created"
    else:
        message = "Error During Create"    
        
    
    return redirect(url_for("users", _external="True", _scheme="https",message=message))


def get_user_info():
    user_info = None
    try:
        user_info = oidc.user_getinfo(["sub", "name", "email", "locale"])
    except:
        print("User is not authenticated")

    return user_info


if __name__ == '__main__':
    app.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)), debug=True)

import os
import base64
import json
import csv
import html
import requests

from config import default_settings
from functools import wraps
from flask import Flask, render_template, url_for, redirect, session, jsonify, request
from flask import send_from_directory, make_response
from flask_oidc import OpenIDConnect

from utils.okta import OktaAuth, OktaAdmin, TokenUtil


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

    json.dump(oidc_config, outfile, indent=4, sort_keys=True)

    app_config = {
        'SECRET_KEY': default_settings["app_secret_key"],
        'PREFERRED_URL_SCHEME': 'https',
        'OIDC_CLIENT_SECRETS': 'client_secrets.json',
        'OIDC_DEBUG': True,
        'OIDC_COOKIE_SECURE': True,
        'OIDC_USER_INFO_ENABLED': False,
        'OIDC_INTROSPECTION_AUTH_METHOD': 'bearer',
        'OIDC_SCOPES': ["openid", "profile", "email", "offline_access"],
        'OVERWRITE_REDIRECT_URI': default_settings["redirect_uri"],
        'OIDC_CALLBACK_ROUTE': '/authorization-code/callback'
    }

    # print("app_config: {0}".format(app_config))

app.config.update(app_config)

oidc = OpenIDConnect(app)


def is_authenticated(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        print("authenticated()")
        token = oidc.get_access_token()

        if is_token_valid_remote(token):
            return f(*args, **kws)
        else:
            print("Access Denied")
            return make_response(redirect(url_for("home", _external="True", _scheme="https")))

    return decorated_function

def is_token_valid_remote(token):
    print("is_token_valid_remote(token)")
    result = False
    okta_auth = OktaAuth(default_settings)

    instrospect_response = okta_auth.introspect(token=token)
    print("instrospect_response: {0}".format(instrospect_response))

    if "active" in instrospect_response:
        result = instrospect_response["active"]

    return result

def requires_admin(f):
    @wraps(f)
    def decorated_function(*args, **kws):
        print("requires_admin()")
        token = oidc.get_access_token()

        if is_admin(token):
            return f(*args, **kws)
        else:
            print("Admin Access Denied")
            return make_response(redirect(url_for("profile", _external="True", _scheme="https")))

    return decorated_function

def is_admin(token):
    print("is_admin(token)")
    result = False
    okta_auth = OktaAuth(default_settings)
    check_admin = TokenUtil.get_single_claim_from_token(token,"taa")
    result = check_admin

    return result

@app.route('/<path:filename>')
def serve_static_html(filename):
    """ serve_static_html() generic route function to serve files in the 'static' folder """
    print("serve_static_html('{0}')".format(filename))
    root_dir = os.path.dirname(os.path.realpath(__file__))
    return send_from_directory(os.path.join(root_dir, 'static'), filename)


@app.route("/")
def home():
    user_info = get_user_info()
    user_group = get_travel_agency_group_by_user_info(user_info)

    return render_template("home.html", oidc=oidc, user_info=user_info, config=default_settings, travel_agency_group=user_group)


@app.route("/login")
def login():
    destination = "{0}/profile".format(default_settings["settings"]["app_base_url"])
    state = {
        'csrf_token': session['oidc_csrf_token'],
        'destination': oidc.extra_data_serializer.dumps(destination).decode('utf-8')
    }
    return render_template("login.html", config=default_settings, oidc=oidc, state=base64.b64encode(bytes(json.dumps(state),'utf-8')).decode('utf-8'))


@app.route("/dlogin")
def dlogin():
    destination = "{0}/profile".format(default_settings["settings"]["app_base_url"])
    state = {
        'csrf_token': session['oidc_csrf_token'],
        'destination': oidc.extra_data_serializer.dumps(destination).decode('utf-8')
    }
    return render_template("dlogin.html", config=default_settings, oidc=oidc)

@app.route("/customlogin",methods = ['POST'])
def customlogin():
    okta_auth = OktaAuth(default_settings)
    username = request.form.get('username')
    password = request.form.get('password')
   
    sm_target_url = request.form.get('targeturl')
    # sm_target_url = "http://siteminder.aaoktapoc.com/aa/"
    mylogin = okta_auth.authenticate(username=username, password=password)
    if "errorCode" in mylogin:
        print(mylogin)
        return mylogin
        
    okta_session = mylogin['sessionToken']
    
    url = "http://siteminder.aaoktapoc.com/siteminderagent/forms/login.fcc"
  
    body1 = {
            'SMENC': 'UTF-8',
            'USER': username,
            'PASSWORD': password,
            'SMLOCALE': 'US-EN',
            'smauthreason':'0',
            'smquerydata': '',
            'smagentname':'-SM-wpOSNS%2bHnACGSFfU2LeLl1S9VHG%2bfNtIay5TxC8zTPp173oee0TJBtH6YZckDNOC',
            'target':sm_target_url
        }
    
    sm_response = requests.post(url,data=body1)
    print(sm_response.content)
    sm_response_string = sm_response.content.decode("utf-8") 
    if "Your credentials are not valid for" in sm_response_string:
        return sm_response_string
        
    sm_content = sm_response.content.decode("utf-8") 
    sm_session = sm_response.history[0].cookies['SMSESSION']
    
    # return redirect("https://aaoktapoc.oktapreview.com/login/sessionCookieRedirect?token=" + session + "&redirectUrl=https%3A%2F%2Faaoktapoc.oktapreview.com%2Fapp%2FUserHome")
    return render_template("customlogin.html",sm_session=sm_session, targeturl=sm_target_url, okta_session=okta_session, sm_content=sm_content)
    



@app.route("/signup")
def signup():

    return render_template("signup.html", config=default_settings, oidc=oidc)


@app.route("/profile")
@is_authenticated
def profile():
        user_info = get_user_info()
        okta_admin = OktaAdmin(default_settings)
        user = okta_admin.get_user(user_info["sub"])
        user_group = get_travel_agency_group_by_user(user)
        app_info = okta_admin.get_applications_by_user_id(user["id"])

        return render_template("profile.html", oidc=oidc, applist=app_info, user_info=user_info, config=default_settings, travel_agency_group=user_group)


@app.route("/logout")
def logout():
    oidc.logout()

    return redirect(url_for("home", _external="True", _scheme="https"))


@app.route("/import")
@is_authenticated
@requires_admin
def importusers():
    user_info = get_user_info()
    user_group = get_travel_agency_group_by_user_info(user_info)
    return render_template("import.html", user_info=user_info, oidc=oidc, config=default_settings, travel_agency_group=user_group)


@app.route('/upload',methods = ['POST'])
@is_authenticated
@requires_admin
def upload_route_summary():
    if request.method == 'POST':
        user_info = get_user_info()
        okta_admin = OktaAdmin(default_settings)


        # Group Name from Claims
        token = oidc.get_access_token()
        group_name = TokenUtil.get_single_claim_from_token(token,"tagrp")
        user_group = get_travel_agency_group_by_name(group_name)

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

    return render_template("upload.html", user_info=user_info, oidc=oidc,returnlist=return_list, userlist=return_users, config=default_settings, travel_agency_group=user_group)



@app.route("/users")
@is_authenticated
@requires_admin
def users():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)

    token = oidc.get_access_token()
    group_name = TokenUtil.get_single_claim_from_token(token,"tagrp")
    user_group = get_travel_agency_group_by_name(group_name)
    group_id = user_group["id"]

    group_user_list = okta_admin.get_user_list_by_group_id(group_id)
    return render_template("users.html", user_info=user_info, oidc=oidc, userlist= group_user_list, config=default_settings, travel_agency_group=user_group)


@app.route("/suspenduser")
@is_authenticated
@requires_admin
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
@is_authenticated
@requires_admin
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
@is_authenticated
@requires_admin
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
@is_authenticated
@requires_admin
def userupdate():
    user_info = get_user_info()
    okta_admin = OktaAdmin(default_settings)
    user_id = request.args.get('user_id')
    user_info2 = okta_admin.get_user(user_id)

    user_group = get_travel_agency_group_by_user(user_info2)

    return render_template("userupdate.html", user_info=user_info, oidc=oidc, user_info2=user_info2, config=default_settings, travel_agency_group=user_group)


@app.route("/updateuserinfo", methods=["POST"])
@is_authenticated
@requires_admin
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
@is_authenticated
@requires_admin
def usercreate():
    user_info = get_user_info()
    user_group = get_travel_agency_group_by_user_info(user_info)

    return render_template("usercreate.html", user_info=user_info, oidc=oidc, config=default_settings, travel_agency_group=user_group)

@app.route("/admincreateuser", methods=["POST"])
def admincreateuser():
    print("Admin Create User()")

    okta_admin = OktaAdmin(default_settings)
    first_name = request.form.get('firstname')
    last_name = request.form.get('lastname')
    email = request.form.get('email')
    login = request.form.get('login')
    mobile_phone = request.form.get('phonenumber')

    if not login:
        login = email

    #  Group and find a Travel Agency
    token = oidc.get_access_token()
    group_name = TokenUtil.get_single_claim_from_token(token,"tagrp")


    user_data = {
                "profile": {
                    "firstName": first_name,
                    "lastName": last_name,
                    "email": email,
                    "login": login,
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

@app.route("/signupcreateuser", methods=["POST"])
def signupcreateuser():
    print("Signup Create User()")

    okta_admin = OktaAdmin(default_settings)
    first_name = request.form.get('firstname')
    last_name = request.form.get('lastname')
    email = request.form.get('email')
    login = request.form.get('login')
    mobile_phone = request.form.get('phonenumber')
    password = request.form.get('password')
    group_name =  request.form.get('groupname')

    if not login:
        login = email

    user_data = {
            "profile": {
                "firstName": first_name,
                "lastName": last_name,
                "email": email,
                "login": login,
                "mobilePhone": mobile_phone,
                "travelAgencyGroup": group_name
            },
             "credentials": {
                "password" : { "value": password }
              }
        }

    user_create_response = okta_admin.create_user(user_data)
    if "errorCode" in user_create_response:
        print(user_create_response)
        message = "<p>Error During Registration</p>" + user_create_response['errorCauses'][0]['errorSummary']
        return redirect(url_for("signup", _external="True", _scheme="https",message=message))
    else:
        print(user_create_response)
        print("User " + first_name + " "+  last_name + " was Created")
        return redirect(url_for("login", _external="True", _scheme="https"))

    return redirect(url_for("signup", _external="True", _scheme="https",message=message))


def get_travel_agency_group_by_user_info(user_info):
    print("get_travel_agency_group()")
    user_group = None

    if user_info:
        okta_admin = OktaAdmin(default_settings)
        user = okta_admin.get_user(user_info["sub"])
        user_group = get_travel_agency_group_by_user(user)

    return user_group


def get_travel_agency_group_by_user(user):
    print("get_travel_agency_group_by_user()")
    user_group = None

    if user:
        travel_agency_group_name = None

        if "travelAgencyGroup" in user["profile"]:
            travel_agency_group_name = user["profile"]["travelAgencyGroup"]
            user_group = get_travel_agency_group_by_name(travel_agency_group_name)

    return user_group


def get_travel_agency_group_by_name(travel_agency_group_name):
    print("get_travel_agency_group_by_name()")
    user_group = None

    if travel_agency_group_name:
        okta_admin = OktaAdmin(default_settings)
        user_groups = okta_admin.get_groups_by_name(travel_agency_group_name)
        # print("user_groups: {0}".format(user_groups))
        if len(user_groups) > 0:
            # just grab the first one... there should only be one match for now
            user_group = user_groups[0]

            # Decorated group info
            travel_agency_data = user_group["profile"]["description"].split("||")
            user_group["profile"]["description_label"] = travel_agency_data[0]
            user_group["profile"]["description_url"] = travel_agency_data[1]

    return user_group


def get_user_info():
    user_info = None
    try:
        user_info = oidc.user_getinfo(["sub", "name", "email", "locale"])
    except:
        print("User is not authenticated")

    return user_info

if __name__ == '__main__':
    app.run(host=os.getenv("IP", "0.0.0.0"), port=int(os.getenv("PORT", 8080)), debug=True)

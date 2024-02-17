import json, jwt, time

# import ssl
import urllib.parse as urlparse
import requests
from datetime import datetime

from auth import (
    authenticate_user_credentials,
    authenticate_client,
    generate_access_token,
    generate_authorization_code,
    verify_authorization_code,
    verify_client_info,
    JWT_LIFE_SPAN,
)
from flask import Flask, redirect, render_template, request, Response
from urllib.parse import urlencode

app = Flask(__name__)


@app.route("/oauth2/v1/authorize")
def auth():
    # Describe the access request of the client and ask user for approval
    print(request.args)
    print(request.remote_addr)
    client_id = request.args.get("client_id")
    print("Request IP:", request.headers.get("Cf-Connecting-Ip"))
    redirect_url = request.args.get("redirect_uri")
    state = request.args.get("state")

    if None in [client_id, redirect_url]:
        return json.dumps({"error": "invalid_request"}), 400

    if not verify_client_info(client_id, redirect_url):
        return json.dumps({"error": "invalid_client"})

    authorization_code = generate_authorization_code(client_id, redirect_url)

    url = process_redirect_url(redirect_url, authorization_code, state)

    # return render_template(
    #     "AC_grant_access.html",
    #     client_id=client_id,
    #     redirect_url=redirect_url,
    #     state=state,
    # )
    return redirect(url, code=302)


def process_redirect_url(redirect_url, authorization_code, state):
    # Prepare the redirect URL
    url_parts = list(urlparse.urlparse(redirect_url))
    queries = dict(urlparse.parse_qsl(url_parts[4]))
    queries.update({"code": authorization_code})
    queries.update({"state": state})
    url_parts[4] = urlencode(queries)
    url = urlparse.urlunparse(url_parts)
    return url


@app.route("/sso", methods=["GET"])
def sso():

    okta_idp_url = "https://id.amazon.nicopowered.com/sso/idps/0oablnnj4mQFmp0yT697"

    r1 = requests.get(okta_idp_url, allow_redirects=False)
    returl = r1.headers["Location"]
    parsed = urlparse.urlparse(returl)
    state = urlparse.parse_qs(parsed.query)["state"][0]

    # print(r1.headers())
    token = request.args.get("token")
    URL = "https://id.amazon.nicopowered.com/oauth2/aus7ijxo2pJ3ZPfdD697/v1/introspect"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {
        "token": token,
        "client_id": "0oa7guxsceKOlHPXV697",
        "token_type_hint": "access_token",
    }
    r = requests.post(url=URL, headers=headers, data=data)
    print(r.json()["active"])
    if r.json()["active"] == True:
        authorization_code = generate_authorization_code(
            data["client_id"],
            "https://id.amazon.nicopowered.com/oauth2/v1/authorize/callback",
        )
        okta_url = process_redirect_url(
            "https://id.amazon.nicopowered.com/oauth2/v1/authorize/callback",
            authorization_code,
            state,
        )
        return redirect(okta_url, code=302)
    else:
        return json.dumps(r.json())


@app.route("/signin", methods=["GET", "POST"])
def signin():
    # Issues authorization code
    username = request.form.get("username")
    password = request.form.get("password")
    client_id = request.form.get("client_id")
    redirect_url = request.form.get("redirect_url")
    state = request.form.get("state")

    if None in [username, password, client_id, redirect_url]:
        return json.dumps({"error": "invalid_request"}), 400

    if not verify_client_info(client_id, redirect_url):
        return json.dumps({"error": "invalid_client"})

    if not authenticate_user_credentials(username, password):
        return json.dumps({"error": "access_denied"}), 401

    authorization_code = generate_authorization_code(client_id, redirect_url)

    url = process_redirect_url(redirect_url, authorization_code, state)

    return redirect(url, code=302)


@app.route("/oauth2/v1/userinfo", methods=["GET"])
def userinfo():
    access_token = request.headers.get("Authorization").replace("Bearer ", "")
    with open("public.pem", "rb") as file:
        public_key = file.read()
    access_token = jwt.decode(
        access_token, public_key, verify=True, algorithms=["RS256"]
    )

    if (
        datetime.fromtimestamp(int(access_token["exp"])) - datetime.now()
    ).total_seconds() > 0:
        payload = json.dumps(
            {
                "display_name": "Sample User",
                "email": "user7@vigneshl.com",
                "preferred_username": "user6",
                "email_verified": "false",
            }
        )

        # time.sleep(10)
        return Response(payload, mimetype="application/json")
    else:
        return "Token Expired"


@app.route("/login/callback", methods=["GET", "POST"])
def callback():
    time.sleep(10)
    return json.dumps({"success": "invalid_request"}), 200


@app.route("/oauth2/v1/token", methods=["POST"])
def exchange_for_token():
    print("Request IP:", request.headers.get("Cf-Connecting-Ip"))
    # Issues access token
    authorization_code = request.form.get("code")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    redirect_url = request.form.get("redirect_uri")

    if None in [authorization_code, client_id, client_secret, redirect_url]:
        return json.dumps({"error": "invalid_request"}), 400

    if not authenticate_client(client_id, client_secret):
        return json.dumps({"error": "invalid_client"}), 400

    if not verify_authorization_code(authorization_code, client_id, redirect_url):
        return json.dumps({"error": "access_denied"}), 400

    access_token = generate_access_token()
    tokenJSON = json.dumps(
        {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": JWT_LIFE_SPAN,
            "scope": "openid email profile",
        }
    )

    print(Response(tokenJSON, mimetype="application/json"))
    return Response(tokenJSON, mimetype="application/json")


if __name__ == "__main__":
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # context.load_cert_chain('domain.crt', 'domain.key')
    # app.run(port = 5000, debug = True, ssl_context = context)
    app.run(port=8080, debug=True)

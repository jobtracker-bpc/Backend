from six.moves.urllib.parse import urlencode
from authlib.integrations.flask_client import OAuth
from flask import url_for
from flask import session
from flask import render_template
from flask import redirect
from flask import jsonify
from flask import Flask
from dotenv import load_dotenv, find_dotenv
from werkzeug.exceptions import HTTPException
from os import environ as env
from jose import jwt
from flask_cors import cross_origin
from six.moves.urllib.request import urlopen
import json
from functools import wraps
from google.cloud import datastore
from flask import request, _request_ctx_stack, Response
import requests
import os
os.environ.setdefault("GCLOUD_PROJECT", "job-tracker-365423")

from functools import wraps
import json

from six.moves.urllib.request import urlopen
from flask_cors import cross_origin, CORS
from jose import jwt


import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'
client = datastore.Client()
CORS(app)

USERS = "users"
JOBS = "jobs"
SKILLS = "skills"
CONTACTS = "contacts"

# Values from auth0
CLIENT_ID = 'N0FhVfdkCdgFNMV5N1epwRfurdqwW7yL'
CLIENT_SECRET = 'uDTy-uqOkRj3JwiFsc8B0lc72DGbRmvxOGarTRy0YTaI-FjQAHIOfWYBIuSjh21F'
DOMAIN = 'dev-j3jbfoh6.us.auth0.com'


ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{DOMAIN}/.well-known/openid-configuration'
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Decode the JWT supplied in the Authorization header


@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

# Verify the JWT in the request's Authorization header


def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                         "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Invalid header. "
                         "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Invalid header. "
                         "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                             "incorrect claims,"
                             " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                             "Unable to parse authentication"
                             " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                         "No RSA key in JWKS"}, 401)

# Check if JWT generated by new user


def verify_jwt_for_user(token):

    jsonurl = urlopen("https://" + DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Invalid header. "
                         "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Invalid header. "
                         "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                             "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                             "description":
                             "incorrect claims,"
                             " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                             "description":
                             "Unable to parse authentication"
                             " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                         "No RSA key in JWKS"}, 401)


@app.route('/')
def root():
    return render_template('home.html')

# Get users


@app.route('/users', methods=['GET'])
def users_get():
    if 'application/json' not in request.accept_mimetypes:
        res = Flask.make_response(Flask, {"Error": "MIME type not supported"})
        res.status_code = 406
        return res

    if request.method == 'GET':
        query = client.query(kind=USERS)
        q_limit = int(request.args.get('limit', 5))
        q_offset = int(request.args.get('offset', 0))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + \
                str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        output = {"users": results}
        if next_url:
            output["next"] = next_url
        return Response(json.dumps(output), status=200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)

# Create a boat if the Authorization header contains a valid JWT


@app.route('/jobs', methods=['POST', 'GET'])
def jobs_post_get():
    if 'application/json' not in request.accept_mimetypes:
        res = Flask.make_response(Flask, {"Error": "MIME type not supported"})
        res.status_code = 406
        return res

    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()

        new_job = datastore.entity.Entity(key=client.key(JOBS))
        new_job.update({"company": content["company"], "job_title": content["job_title"],
                        "job_link": content["job_link"], "date_applied": content["date_applied"],
                        "interview": content["interview"], "status": content["status"], "user": payload["sub"]})
        client.put(new_job)
        new_job["id"] = new_job.key.id
        new_job["self"] = request.url + '/' + str(new_job.key.id)
        return Response(json.dumps(new_job), status=201)

    elif request.method == 'GET':
        payload = verify_jwt(request)
        query = client.query(kind=JOBS)
        query = query.add_filter('user', '=', payload["sub"])
        q_limit = int(request.args.get('limit', 5))
        q_offset = int(request.args.get('offset', 0))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        total_results = list(query.fetch())
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + \
                str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        for e in results:
            e["self"] = request.url + '/' + str(e.key.id)

        output = {"jobs": results}
        output["total_jobs"] = len(total_results)
        if next_url:
            output["next"] = next_url

        return Response(json.dumps(output), status=200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)


@app.route('/jobs/<job_id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def job_by_id(job_id):

    if 'application/json' not in request.accept_mimetypes:
        res = Flask.make_response(Flask, {"Error": "MIME type not supported"})
        res.status_code = 406
        return res

    payload = verify_jwt(request)

    job_key = client.key(JOBS, int(job_id))
    job = client.get(key=job_key)

    if job["user"] != payload["sub"]:
        return {"Error": "This job belongs to another user"}, 403

    if request.method == 'DELETE':

        if json.dumps(job) == 'null':
            return {"Error": "No job with this job_id exists"}, 404

        client.delete(job_key)
        return ('', 204)

    elif request.method == 'GET':

        job["id"] = job.key.id
        job["self"] = request.url

        return Response(json.dumps(job), 200)

    elif request.method == 'PUT':

        content = request.get_json()

        job.update({"company": content["company"], "job_title": content["job_title"],
                    "job_link": content["job_link"], "date_applied": content["date_applied"],
                    "interview": content["interview"], "status": content["status"]})

        client.put(job)
        job["id"] = job.key.id
        job["self"] = request.host_url + 'jobs/' + str(job.key.id)
        return Response(json.dumps(job), 200)

    elif request.method == 'PATCH':

        content = request.get_json()
        query = client.query(kind=JOBS)
        results = list(query.fetch())

        for attribute in content:
            job.update({attribute: content[attribute]})

        client.put(job)
        job["id"] = job.key.id
        job["self"] = request.host_url + 'jobs/' + str(job.key.id)
        return Response(json.dumps(job), 200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)


@app.route('/contacts', methods=['POST', 'GET'])
def contacts_post_get():
    if 'application/json' not in request.accept_mimetypes:
        res = Flask.make_response(Flask, {"Error": "MIME type not supported"})
        res.status_code = 406
        return res

    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_contact = datastore.entity.Entity(key=client.key(CONTACTS))
        new_contact.update({"name": content["name"], "company": content["company"],
                            "position": content["position"], "phone_number": content["phone_number"],
                            "email": content["email"], "linkedin": content["linkedin"], "user": payload["sub"]})
        client.put(new_contact)
        new_contact["id"] = new_contact.key.id
        new_contact["self"] = request.url + '/' + str(new_contact.key.id)
        return Response(json.dumps(new_contact), status=201)

    elif request.method == 'GET':
        payload = verify_jwt(request)
        query = client.query(kind=CONTACTS)
        query = query.add_filter('user', '=', payload["sub"])
        q_limit = int(request.args.get('limit', 5))
        q_offset = int(request.args.get('offset', 0))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        total_results = list(query.fetch())
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + \
                str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        for e in results:
            e["self"] = request.url + '/' + str(e.key.id)

        output = {"contacts": results}
        output["total_contacts"] = len(total_results)
        if next_url:
            output["next"] = next_url

        return Response(json.dumps(output), status=200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)


@app.route('/contacts/<contact_id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def contact_by_id(contact_id):

    if 'application/json' not in request.accept_mimetypes:
        res = Flask.make_response(Flask, {"Error": "MIME type not supported"})
        res.status_code = 406
        return res

    payload = verify_jwt(request)

    contact_key = client.key(CONTACTS, int(contact_id))
    contact = client.get(key=contact_key)

    if contact["user"] != payload["sub"]:
        return {"Error": "This contact belongs to another user"}, 403

    if request.method == 'DELETE':

        if json.dumps(contact) == 'null':
            return {"Error": "No contact with this contact_id exists"}, 404

        client.delete(contact_key)
        return ('', 204)

    elif request.method == 'GET':
        contact["id"] = contact.key.id
        contact["self"] = request.url
        return Response(json.dumps(contact), 200)

    elif request.method == 'PUT':
        content = request.get_json()
        contact.update({"name": content["name"], "company": content["company"],
                        "position": content["position"], "phone_number": content["phone_number"],
                        "email": content["email"], "linkedin": content["linkedin"], "user": payload["sub"]})
        client.put(contact)
        contact["id"] = contact.key.id
        contact["self"] = request.host_url + 'contacts/' + str(contact.key.id)
        return Response(json.dumps(contact), 200)

    elif request.method == 'PATCH':
        content = request.get_json()
        for attribute in content:
            contact.update({attribute: content[attribute]})
        client.put(contact)
        contact["id"] = contact.key.id
        contact["self"] = request.host_url + 'contacts/' + str(contact.key.id)
        return Response(json.dumps(contact), 200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)


@app.route('/skills', methods=['POST', 'GET'])
def skills_post_get():
    if 'application/json' not in request.accept_mimetypes:
        res = Flask.make_response(Flask, {"Error": "MIME type not supported"})
        res.status_code = 406
        return res

    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()

        new_skill = datastore.entity.Entity(key=client.key(SKILLS))
        new_skill.update(
            {"skill_name": content["skill_name"], "skill_priority": content["skill_priority"], "user": payload["sub"]})
        client.put(new_skill)
        new_skill["id"] = new_skill.key.id
        new_skill["self"] = request.url + '/' + str(new_skill.key.id)
        return Response(json.dumps(new_skill), status=201)

    elif request.method == 'GET':
        payload = verify_jwt(request)
        query = client.query(kind=SKILLS)
        query = query.add_filter('user', '=', payload["sub"])
        q_limit = int(request.args.get('limit', 5))
        q_offset = int(request.args.get('offset', 0))
        l_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        total_results = list(query.fetch())
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + \
                str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["self"] = request.url + '/' + str(e.key.id)
        output = {"skills": results}
        output["total_skills"] = len(total_results)
        if next_url:
            output["next"] = next_url

        return Response(json.dumps(output), status=200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)


@app.route('/skills/<skill_id>', methods=['GET', 'DELETE', 'PUT', 'PATCH'])
def skill_by_id(skill_id):

    if 'application/json' not in request.accept_mimetypes:
        res = Flask.make_response(Flask, {"Error": "MIME type not supported"})
        res.status_code = 406
        return res

    payload = verify_jwt(request)

    skill_key = client.key(SKILLS, int(skill_id))
    skill = client.get(key=skill_key)

    if skill["user"] != payload["sub"]:
        return {"Error": "This skill belongs to another user"}, 403
    if request.method == 'DELETE':
        if json.dumps(skill) == 'null':
            return {"Error": "No skill with this skill_id exists"}, 404
        client.delete(skill_key)
        return '', 204
    elif request.method == 'GET':
        skill["id"] = skill.key.id
        skill["self"] = request.url
        return Response(json.dumps(skill), 200)
    elif request.method == 'PUT':
        content = request.get_json()
        skill.update(
            {"skill_name": content["skill_name"], "skill_priority": content["skill_priority"]})
        client.put(skill)
        skill["id"] = skill.key.id
        skill["self"] = request.host_url + 'skills/' + str(skill.key.id)
        return Response(json.dumps(skill), 200)
    elif request.method == 'PATCH':
        content = request.get_json()
        for attribute in content:
            skill.update({attribute: content[attribute]})
        client.put(skill)
        skill["id"] = skill.key.id
        skill["self"] = request.host_url + 'skills/' + str(skill.key.id)
        return Response(json.dumps(skill), 200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)


# Generate a JWT from the Auth0 domain and return it
@app.route('/login')
def login_user():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True))


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token
    payload = verify_jwt_for_user(token["id_token"])
    query = client.query(kind=USERS)
    results = list(query.fetch())

    new_user_bool = True
    for e in results:
        if e["user_id"] == payload["sub"]:
            new_user_bool = False
    if new_user_bool:
        new_user = datastore.entity.Entity(key=client.key(USERS))
        new_user.update({"user_id": payload["sub"]})
        client.put(new_user)

    return {"JWT": token["id_token"], "USERID": payload["sub"]}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)


import json
import os
from urllib.request import urlopen

from flask import (Flask, Response, jsonify, request)
from flask_cors import CORS
from google.cloud import datastore
from jose import jwt

os.environ.setdefault("GCLOUD_PROJECT", "job-tracker-365423")

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
AUDIENCE = 'https://dev-j3jbfoh6.us.auth0.com/api/v2/'
CLIENT_SECRET = 'uDTy-uqOkRj3JwiFsc8B0lc72DGbRmvxOGarTRy0YTaI-FjQAHIOfWYBIuSjh21F'
DOMAIN = 'dev-j3jbfoh6.us.auth0.com'


ALGORITHMS = ["RS256"]

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

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
                audience=AUDIENCE,
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

# Get users

@app.route('/users', methods=['GET'])
def users_get():
    if 'application/json' not in request.accept_mimetypes:
        res = Flask.make_response(Flask, {"Error": "MIME type not supported"})
        res.status_code = 406
        return res

    if request.method == 'GET':
        query = client.query(kind=USERS)
        results = list(query.fetch())
        return Response(json.dumps(results), status=200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)

# Create a job if the Authorization header contains a valid JWT

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
        return Response(json.dumps(new_job), status=201)

    elif request.method == 'GET':
        payload = verify_jwt(request)
        query = client.query(kind=JOBS)
        query = query.add_filter('user', '=', payload["sub"])
        results = list(query.fetch())

        for e in results:
            e["id"] = e.key.id

        return Response(json.dumps(results), status=200)
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

        return Response(json.dumps(job), 200)

    elif request.method == 'PUT':

        content = request.get_json()

        job.update({"company": content["company"], "job_title": content["job_title"],
                    "job_link": content["job_link"], "date_applied": content["date_applied"],
                    "interview": content["interview"], "status": content["status"]})

        client.put(job)
        job["id"] = job.key.id
        return Response(json.dumps(job), 200)

    elif request.method == 'PATCH':
        content = request.get_json()

        for attribute in content:
            job.update({attribute: content[attribute]})

        client.put(job)
        job["id"] = job.key.id
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

        results = list(query.fetch())

        for e in results:
            e["id"] = e.key.id

        return Response(json.dumps(results), status=200)
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
        return Response(json.dumps(contact), 200)

    elif request.method == 'PUT':
        content = request.get_json()
        contact.update({"name": content["name"], "company": content["company"],
                        "position": content["position"], "phone_number": content["phone_number"],
                        "email": content["email"], "linkedin": content["linkedin"], "user": payload["sub"]})
        client.put(contact)
        contact["id"] = contact.key.id
        return Response(json.dumps(contact), 200)

    elif request.method == 'PATCH':
        content = request.get_json()
        for attribute in content:
            contact.update({attribute: content[attribute]})
        client.put(contact)
        contact["id"] = contact.key.id
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
        return Response(json.dumps(new_skill), status=201)

    elif request.method == 'GET':
        payload = verify_jwt(request)
        query = client.query(kind=SKILLS)
        query = query.add_filter('user', '=', payload["sub"])

        results = list(query.fetch())

        for e in results:
            e["id"] = e.key.id

        return Response(json.dumps(results), status=200)
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
        return Response(json.dumps(skill), 200)
    elif request.method == 'PUT':
        content = request.get_json()
        skill.update(
            {"skill_name": content["skill_name"], "skill_priority": content["skill_priority"]})
        client.put(skill)
        skill["id"] = skill.key.id
        return Response(json.dumps(skill), 200)
    elif request.method == 'PATCH':
        content = request.get_json()
        for attribute in content:
            skill.update({attribute: content[attribute]})
        client.put(skill)
        skill["id"] = skill.key.id
        return Response(json.dumps(skill), 200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)

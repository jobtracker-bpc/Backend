
import json
import os
from urllib.request import urlopen

from flask import Flask, Response, jsonify, request
from flask_cors import CORS
from google.cloud import datastore
from jose import jwt
from operator import itemgetter

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
                        "interview": content["interview"], "status": content["status"], "contacts": content["contacts"], "skills": content["skills"], "user": payload["sub"]})
        client.put(new_job)
        new_job["id"] = new_job.key.id

        # for each skill in the job skill array, add the job to the skill's jobs array and update the skill frequency
        for skill in new_job["skills"]:
            skill_key = client.key(SKILLS, int(skill["id"]))
            skill_to_update = client.get(key=skill_key)
            updated_job_list = skill_to_update["jobs"]
            updated_job_list.append({"id":new_job.key.id, "job_title": new_job["job_title"], "company":new_job["company"]})
            skill_to_update.update({"jobs": updated_job_list})
            skill_to_update.update({"skill_frequency": len(skill_to_update["jobs"])})
            client.put(skill_to_update)

                 # for each contact in the job contact array, add the job to the contact's jobs array
        for contact in new_job["contacts"]:
            contact_key = client.key(CONTACTS, int(contact["id"]))
            contact_to_update = client.get(key=contact_key)
            updated_job_list = contact_to_update["jobs"]
            updated_job_list.append({"id":new_job.key.id, "job_title": new_job["job_title"], "company":new_job["company"]})
            contact_to_update.update({"jobs": updated_job_list})
            client.put(contact_to_update)
        
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

        # remove job from all skills
        if len(job["skills"]) > 0:
            for skill in job["skills"]:
                skill_to_change = client.get(key=client.key(SKILLS, skill["id"]))
                for job_to_remove in skill_to_change["jobs"]:
                    if int(job_to_remove["id"]) == int(job_id):
                        skill_to_change["jobs"].remove(job_to_remove)
                        skill_to_change["skill_frequency"] -= 1
                        client.put(skill_to_change)

        # remove job from all contacts
        if len(job["contacts"]) > 0:
            for contact in job["contacts"]:
                contact_to_change = client.get(key=client.key(CONTACTS, contact["id"]))
                for job_to_remove in contact_to_change["jobs"]:
                    if int(job_to_remove["id"]) == int(job_id):
                        contact_to_change["jobs"].remove(job_to_remove)
                        client.put(contact_to_change)

        client.delete(job_key)
        return ('', 204)

    elif request.method == 'GET':

        job["id"] = job.key.id
        return Response(json.dumps(job), 200)

    elif request.method == 'PUT':

        content = request.get_json()

        job.update({"company": content["company"], "job_title": content["job_title"],
                    "job_link": content["job_link"], "date_applied": content["date_applied"],
                    "interview": content["interview"], "status": content["status"], "contacts": content["contacts"], "skills": content["skills"], "user": payload["sub"]})

        client.put(job)

        # for each skill in the job skill array, add the job to the skill's jobs array and update the skill frequency
        for skill in job["skills"]:
            skill_key = client.key(SKILLS, int(skill["id"]))
            skill_to_update = client.get(key=skill_key)
            updated_job_list = skill_to_update["jobs"]
            updated_job_list.append({"id":job.key.id, "job_title": job["job_title"], "company":job["company"]})
            skill_to_update.update({"jobs": updated_job_list})
            skill_to_update.update({"skill_frequency": len(skill_to_update["jobs"])})
            client.put(skill_to_update)

         # for each contact in the job contact array, add the job to the contact's jobs array
        for contact in job["contacts"]:
            contact_key = client.key(CONTACTS, int(contact["id"]))
            contact_to_update = client.get(key=contact_key)
            updated_job_list = contact_to_update["jobs"]
            updated_job_list.append({"id":job.key.id, "job_title": job["job_title"], "company":job["company"]})
            contact_to_update.update({"jobs": updated_job_list})
            client.put(contact_to_update)

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
                            "email": content["email"], "linkedin": content["linkedin"], "jobs": [], "user": payload["sub"]})
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

        # remove skill from all jobs
        if len(contact["jobs"]) > 0:
            for job in contact["jobs"]:
                job_to_change = client.get(key=client.key(JOBS, job["id"]))
                for contact_to_remove in job_to_change["skills"]:
                    if int(contact_to_remove["id"]) == int(contact_id):
                        job_to_change["skills"].remove(contact_to_remove)
                        client.put(job_to_change)

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
        new_skill.update({"skill_name": content["skill_name"], "skill_proficiency": content["skill_proficiency"],
                        "skill_frequency": 0, "jobs": [], "user": payload["sub"]})
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
    
        # remove skill from all jobs
        if len(skill["jobs"]) > 0:
            for job in skill["jobs"]:
                job_to_change = client.get(key=client.key(JOBS, job["id"]))
                for skill_to_remove in job_to_change["skills"]:
                    if int(skill_to_remove["id"]) == int(skill_id):
                        job_to_change["skills"].remove(skill_to_remove)
                        client.put(job_to_change)

        client.delete(skill_key)
        return '', 204
    elif request.method == 'GET':
        skill["id"] = skill.key.id
        return Response(json.dumps(skill), 200)
    elif request.method == 'PUT':
        content = request.get_json()
        skill.update(
            {"skill_name": content["skill_name"], "skill_proficiency": content["skill_proficiency"],
            "skill_frequency": len(content["jobs"]), "jobs": content["jobs"], "user": payload["sub"]})
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

@app.route('/skills/<skill_id>/frequency', methods = ['GET'])
def get_skill_frequency(skill_id):

    payload = verify_jwt(request)
    skill_key = client.key(SKILLS, int(skill_id))
    skill = client.get(key=skill_key)

    if skill["user"] != payload["sub"]:
        return {"Error": "This skill belongs to another user"}, 403
    
    if request.method == 'GET':
        query = client.query(kind=JOBS)
        query = query.add_filter('user', '=', payload["sub"])
        results = list(query.fetch())
        total_jobs = len(results)
        frequency = skill["skill_frequency"]
        percentage = 0
        if frequency > 0:
            percentage = (frequency / total_jobs) * 100
        
        output = {
            "frequency": frequency,
            "percentage": percentage
            }

        return Response(json.dumps(output), 200)
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)

@app.route('/skills/topfive', methods = ['GET'])
def get_top_five_skills():

    payload = verify_jwt(request)

    if request.method == 'GET':
        query = client.query(kind=SKILLS)
        query = query.add_filter('user', '=', payload["sub"])
        results = list(query.fetch())
        results = sorted(results, key=lambda result: result['skill_frequency'], reverse=True)

        end = 5 if len(results) >= 5 else len(results)
        output = results[:end]
        return Response(json.dumps(output), 200)
        
    else:
        return Response({'Error': 'Method not recogonized or permitted'}, 405)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)

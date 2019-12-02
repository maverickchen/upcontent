import datetime
from time import mktime

from flask import Flask, request
import jwt
import requests

from secrets import api_auth_token, jwt_secret_key
from utils import parse_date_time
from business import get_user_by_email

app = Flask(__name__)


def decode_auth_token(auth_token):
    # use jwt, jwt_secret_key
    # should be a one liner, but we want you to see how JWTs work
    return jwt.decode(auth_token, jwt_secret_key)


def encode_auth_token(user_id, name, email, scopes):
    # use jwt and jwt_secret_key imported above, and the payload defined below
    # should be a one liner, but we want you to see how JWTs work
    # remember to convert the result of jwt.encode to a string
    # make sure to use .decode("utf-8") rather than str() for this
    payload = {
        'sub': user_id,
        'name': name,
        'email': email,
        'scope': scopes,
        'exp': mktime((datetime.datetime.now() + datetime.timedelta(days=1)).timetuple())
    }
    return jwt.encode(payload, jwt_secret_key).decode("utf-8")


def get_user_from_token():
    # use decode_auth_token above and flask.request imported above
    # should pull token from the Authorization header
    # Authorization: Bearer {token}
    # Where {token} is the token created by the login route
    token = request.headers.get('Authorization').split('Bearer ')[1]
    return decode_auth_token(token)


@app.route('/')
def status():
    return 'API Is Up'


@app.route('/user', methods=['GET'])
def user():
    # get the user data from the auth/header/jwt
    user_data = get_user_from_token()
    return {
        'user_id': user_data['sub'],
        'name': user_data['name'],
        'email': user_data['email']
    }


@app.route('/login', methods=['POST'])
def login():
    # use use flask.request to get the json body and get the email and scopes property
    # use the get_user_by_email function to get the user data
    # return a the encoded json web token as a token property on the json response as in the format below
    # we're not actually validitating a password or anything because that would add unneeded complexity
    email = request.args.get('email')
    scopes = request.args.get('scopes')
    if email and scopes:
        user = get_user_by_email(email)
        return {
            'token': encode_auth_token(user['id'], user['name'], email, scopes)
        }
    else:
        return {
            'error': 'No "email" or "scopes" query params provided'
        }

def satisfies(widget, filters):
    for (field, val) in filters.items():
        if widget[field] != val:
            return False
    return True


def labelify(s):
    # turn hyphens to spaces and capitalize words of a string s
    words = s.replace('-', ' ').split()
    capitalized = [word.capitalize() for word in words]
    return ' '.join(capitalized)
    

@app.route('/widgets', methods=['GET'])
def widgets():
    # accept the following optional query parameters (using the the flask.request object to get the query params)
    # type, created_start, created_end
    # dates will be in iso format (2019-01-04T16:41:24+0200)
    # dates can be parsed using the parse_date_time function written and imported for you above
    # get the user ID from the auth/header
    # verify that the token has the widgets scope in the list of scopes

    # Using the requests library imported above send the following the following request,

    # GET https://us-central1-interview-d93bf.cloudfunctions.net/widgets?user_id={user_id}
    # HEADERS
    # Authorization: apiKey {api_auth_token}

    # the api will return the data in the following format

    # [ { "id": 1, "type": "floogle", "created": "2019-01-04T16:41:24+0200" } ]
    # dates can again be parsed using the parse_date_time function

    # filter the results by the query parameters
    # return the data in the format below
    user_data = get_user_from_token()
    if 'widgets' not in user_data['scope']:
        return {
            'error': 'User is not authorized to GET widgets'
        }

    filters = request.args
    url_path = 'https://us-central1-interview-d93bf.cloudfunctions.net/widgets'
    resp = requests.get(
        url=url_path,
        headers={
            'Authorization': f'apiKey {api_auth_token}'
        },
        params={
            'user_id': user_data['sub']
        }
    )
    widgets = resp.json()
    matches = [widg for widg in widgets if satisfies(widg, filters)]
    for match in matches:
        print(match)
        match.update({
            'type_label': labelify(match['type']),
            'created': parse_date_time(match['created']),
        })
    return {
        'total_widgets_own_by_user': len(widgets),
        'matching_items': matches
    }


if __name__ == '__main__':
    app.run()

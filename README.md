# Docs

Read the [official documentation](https://flask-oauthlib.readthedocs.io/en/latest/oauth2.html#example-for-oauth-2)

1. Install dependencies $ pip install -r requirements.txt
1. Start the server by executing $ python server.py
1. Database will be created and populates with dummy data

## Authorize

First authorize by passing the client_id, client_secret, username and password and grab the CODE from the response

```curl -vvv -X GET "http://localhost:8080/oauth/authorize?response_type=code&client_id=confidential&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized&scope=email+address&username=admin&password=112"```

## Token

Get the access token using the code from the previous call

```curl -X POST --data "code=<CODE>&grant_type=authorization_code&client_id=confidential&redirect_uri=http://localhost:8000/authorized&client_secret=confidential" "http://localhost:8080/oauth/token?response_type=code"```

## Test

Test calling the email endpoint

```curl -vvv -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8080/api/email```

## ToDo

1. Encrypt password
1. Add permissions and roles per user
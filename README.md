# Docs
https://flask-oauthlib.readthedocs.io/en/latest/oauth2.html#example-for-oauth-2

## First authorize the oauth, and grab <CODE>
curl -vvv -X GET "http://localhost:8080/oauth/authorize?response_type=code&client_id=confidential&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fauthorized&scope=email+address&username=admin&password=112"

## get token and save <ACCESS_TOKEN>
curl -X POST --data "code=<CODE>&grant_type=authorization_code&client_id=confidential&redirect_uri=http://localhost:8000/authorized&client_secret=confidential" "http://localhost:8080/oauth/token?response_type=code"

# test email
curl -vvv -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:8080/api/email

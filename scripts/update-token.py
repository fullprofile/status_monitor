import requests
import json
from base64 import b64encode
from nacl import encoding, public
import os

base_github_url = 'https://api.github.com/repos/fullprofile/status_monitor/actions/secrets'
auth_url = 'https://api.waypath.io/auth/login'
user = {
    "username": "support@waypath.io",
    "password": os.environ['SUPPORT_USER_PASSWORD']
}
authToken = os.environ['AUTH_TOKEN']

def encrypt(public_key: str, secret_value: str) -> str:
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")

if __name__ == '__main__':
    # Make request to auth endpoint to get access token
    authResponse = requests.post(auth_url, user)
    
    responseJSON = json.loads(authResponse.text)
    # Add "Bearer" to token
    token = 'Bearer ' + responseJSON['accessToken']

    # Get public key and id from Github
    headers = {'Authorization': authToken}
    publicKeyResponse = requests.get(f'{base_github_url}/public-key', headers=headers)
    publicKeyJSON = json.loads(publicKeyResponse.text)
    print(publicKeyJSON)
    keyId = publicKeyJSON['key_id']
    publicKey = publicKeyJSON['key']

    # Encrypt access token
    encryptedToken = encrypt(publicKey, token)

    # Update secret in Github
    body = {
        'key_id': keyId,
        'encrypted_value': encryptedToken
    }
    updateResponse = requests.put(f'{base_github_url}/SECRET_SITE_2', json.dumps(body), headers=headers)
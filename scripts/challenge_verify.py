import json, time, urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sk = Ed25519PrivateKey.generate()
pub = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

def post(path, body):
    req = urllib.request.Request('http://127.0.0.1:8700'+path, json.dumps(body).encode(), {'Content-Type':'application/json'})
    return json.loads(urllib.request.urlopen(req).read())

def get(path):
    return json.loads(urllib.request.urlopen('http://127.0.0.1:8700'+path).read())

print('pubkey:', pub)
print('register:', post('/api/devices/register', {'public_key': pub, 'device_info': {'name': 'm2-test'}}))
print('waiting for approval (approve in http://127.0.0.1:8701)...')
print('status:', get('/api/devices/status?public_key='+pub))

nonce = post('/api/auth/challenge', {'public_key': pub})['challenge']
sig = sk.sign((nonce + pub + str(int(time.time()))).encode()).hex()

print('verify:', post('/api/auth/verify', {'public_key': pub, 'signature': sig, 'timestamp': int(time.time())}))
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .utils import base64url_encode

class Key():
    def __init__(self, alg, pk):
        self.alg = alg
        self.pk = pk

    def sign(msg):
        raise NotImplementedError

    @classmethod
    def create(cls):
        raise NotImplementedError

    def jwk(self):
        raise NotImplementedError


class ES256Key(Key):
    def __init__(self, pk):
        super().__init__('ES256', pk)
        self.key_length = 32

    @classmethod
    def create(cls):
        pk = ec.generate_private_key(ec.SECP256R1(), default_backend())
        return cls(pk)

    def sign(self, msg):
        signature = self.pk.sign(msg, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(signature)
        return r.to_bytes(byteorder='big', length=self.key_length) + s.to_bytes(byteorder='big', length=self.key_length)

    def jwk(self):
        public_numbers = self.pk.public_key().public_numbers()
        return {
            'kty': 'EC',
            'crv': 'P-256',
            'x': self._encode_public(public_numbers.x),
            'y': self._encode_public(public_numbers.y)
        }

    def _encode_public(self, val):
        return base64url_encode(val.to_bytes(byteorder='big', length=self.key_length)).decode('utf-8')

class JWS:
    def __init__(self, key, alg='ES256'):
        self.alg = alg
        key_class = resolve_alg(alg)
        if isinstance(key, key_class):
            self.key = key
        else:
            raise AttributeError('invalid key for algorithm')

    def create_jws(self, payload, **kwargs):
        header = kwargs
        header['alg'] = self.alg

        if not header.get('kid'):
            header['jwk'] = self.key.jwk()

        header_encoded = self._encode_header(header)
        payload_encoded = self._encode_payload(payload)
        signature_encoded = base64url_encode(self._sign(header_encoded, payload_encoded))

        return json.dumps({
            'protected': header_encoded.decode('utf-8'), 
            'payload': payload_encoded.decode('utf-8'), 
            'signature': signature_encoded.decode('utf-8')
        })

    def _encode_header(self, header):
        header_formatted = json.dumps(header, sort_keys=True).encode('utf-8')

        return base64url_encode(header_formatted)

    def _encode_payload(self, payload):
        if isinstance(payload, str):
            payload = payload.encode('utf-8')

        return base64url_encode(payload)

    def _sign(self, header_encoded, payload_encoded):
        return self.key.sign(b'.'.join([header_encoded, payload_encoded]))

def resolve_alg(alg):
    alg_map = {'ES256': ES256Key}
    try:
        return alg_map[alg]
    except:
        raise AttributeError('unsupported algorithm')






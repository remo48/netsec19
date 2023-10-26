import base64

def base64url_encode(val):
    if not isinstance(val, bytes):
        raise AttributeError('value must be of type bytes')
    return base64.urlsafe_b64encode(val).rstrip(b'=')

def base64url_decode(val):
    if not isinstance(val, bytes):
        raise AttributeError('value must be of type bytes')
    return base64.urlsafe_b64decode(val + b'=' * (4 - (len(val) % 4)))
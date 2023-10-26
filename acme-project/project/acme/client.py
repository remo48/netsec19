import hashlib
import json
import logging
import time
from typing import Any, Dict, List

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from requests import Session
from requests.models import Response
from requests.exceptions import SSLError, ConnectionError, Timeout

from .jws import JWS, ES256Key, resolve_alg
from .utils import base64url_encode


class AcmeError(Exception):
    pass


class Resource:
    def update(self, newdata):
        for key, value in newdata.items():
            setattr(self, key, value)


class Account(Resource):
    def __init__(self, key: ES256Key) -> None:
        self.key = key
        self.kid = None
        self.orders_url = None

    def get_jwk(self):
        return self.key.jwk()


class Order(Resource):
    def __init__(
        self,
        url: str,
        status: str,
        identifiers: List[Dict],
        authorizations: List[Dict],
        finalize: str,
        expires: str = None,
        notBefore: str = None,
        notAfter: str = None,
        error: str = None,
        certificate: str = None,
    ) -> None:
        self.url = url
        self.status = status
        self.identifiers = identifiers
        self.finalize = finalize
        self.expires = expires
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.error = error
        self.certificate = certificate

        self.authorizations = []
        for url in authorizations:
            self.update_authorization(url)

    def update_authorization(self, url: str, authz: Dict = {}) -> None:
        for a in self.authorizations:
            if a["url"] == url:
                a.update(authz)
                return
        self.authorizations.append({"url": url, **authz})

    def get_challenges(self, preferred_type):
        challenges = []
        for a in self.authorizations:
            identifier = a["identifier"]["value"]
            challenge = next(
                (c for c in a["challenges"] if c["type"] == preferred_type), None
            )
            if not challenge:
                raise AcmeError("challenge type not supported by server")
            challenges.append((identifier, challenge))
        return challenges

    def from_json(self, order_json: Dict):
        self.status = order_json["status"]
        self.error = order_json.get("error")
        self.certificate = order_json.get("certificate")

    def __str__(self) -> str:
        return str(self.__dict__)


class Client:
    """
    This is a simple ACME client
    """

    def __init__(self, dir_url: str, root_cert_path: str = None) -> None:
        s = Session()
        if root_cert_path:
            s.verify = root_cert_path
        self.s = s

        self.dir = self.get_directory(dir_url)
        self.nonces = []
        self.jws_alg = "ES256"

        key = resolve_alg(self.jws_alg).create()
        self.account = Account(key)

        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)

    def get_directory(self, dir_url: str) -> Dict:
        """Gets the JSON dir object containing the url information of the
        ACME server

        Args:
            dir_url: The url for the directory request

        Returns:
            dir: A directory object containing the url's of the ACME server
        """
        res = self._get(dir_url)
        return res.json()

    def get_nonce(self) -> str:
        """Gets a fresh anti-replay nonce Value.

        Returns
            nonce: a fresh nonce provided by the server
        """
        if self.nonces:
            return self.nonces.pop()
        else:
            res = self.s.head(self.dir["newNonce"])
            return res.headers["Replay-Nonce"]

    def create_account(self) -> None:
        """Creates a new account"""
        payload = json.dumps({"termsOfServiceAgreed": True}).encode("utf-8")
        res = self._make_jws_request(payload, self.dir["newAccount"])
        self.account.kid = res.headers["Location"]
        self.account.orders_url = res.json()["orders"]

    def submit_order(self, identifiers: List[Dict]):
        """Request a new order from the server

        Args:
            identifiers: A list of identifier (type, value) objects
        """
        payload = json.dumps({"identifiers": identifiers}).encode("utf-8")
        res = self._make_jws_request(payload, self.dir["newOrder"])
        url = res.headers.get("Location")
        res_json = res.json()
        return Order(url=url, **res_json)

    def fetch_challenges(self, order: Order):
        """Request the authorization object

        Args:
            auth_url: The url of the authorization

        Returns:
            authorization: An authorization object
        """
        for authz in order.authorizations:
            url = authz["url"]
            res = self._make_jws_request(b"", url)
            res_json = res.json()
            authz.update({"url": url, **res_json})

    def respond_to_challenge(self, challenge_url: str) -> None:
        """Inform the acme server that the corresponding challenge is ready for validation

        Args:
            authorization: An authorization object
        """
        res = self._make_jws_request(b"{}", challenge_url)

    def get_key_authorization(self, token):
        jwk = json.dumps(
            self.account.get_jwk(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

        thumbprint = base64url_encode(hashlib.sha256(jwk).digest()).decode("utf-8")
        return ".".join([token, thumbprint])

    def _fetch_authorization(self, url: str) -> str:
        """Fetch the status of the authorization

        Args:
            authorization: An authorization object

        Returns:
            status, expires: The status and expiration timestamp of the authorization object
        """
        res = self._make_jws_request(b"", url)
        return res.json()

    def poll_order(self, order: Order, timeout=60) -> None:
        """Periodically checks the status of the authorization objects

        Args:
            order: The order object to poll the status
            timeout: timeout in seconds
        """
        max_time = time.time() + timeout
        for authz in order.authorizations:
            url = authz["url"]
            while True:
                authorization = self._fetch_authorization(url)

                if authorization["status"] != "pending":
                    order.update_authorization(url, authorization)
                    break

                if time.time() >= max_time:
                    raise TimeoutError()

                time.sleep(1)

    def finalize_order(self, order: Order, cert_key, timeout=60) -> None:
        """Finalize the order by sending a CSR"""
        csr = self._create_csr(order.identifiers, cert_key)
        payload = json.dumps({"csr": base64url_encode(csr).decode("utf-8")}).encode(
            "utf-8"
        )
        self._make_jws_request(payload, order.finalize)

        max_time = time.time() + timeout
        while True:
            res_json = self._make_jws_request(b"", order.url).json()
            if (
                res_json.get("error")
                or res_json.get("certificate")
                or res_json["status"] != "processing"
            ):
                order.from_json(res_json)
                return

            if time.time() >= max_time:
                raise TimeoutError()

            time.sleep(1)

    def download_certificate(self, certificate_url: str) -> str:
        headers = {"Accept": "application/pem-certificate-chain"}
        res = self._make_jws_request(b"", certificate_url, headers)
        certificate = res.content
        return certificate

    def revoke_certificate(self, pem_certificate, cert_key=None):
        if not self.account.kid and not cert_key:
            raise AttributeError("No account key id or certificate key provided")

        der_certificate = x509.load_pem_x509_certificate(
            pem_certificate, default_backend()
        ).public_bytes(serialization.Encoding.DER)

        payload = json.dumps(
            {"certificate": base64url_encode(der_certificate).decode("utf-8")}
        ).encode("utf-8")

        self._make_jws_request(payload, self.dir["revokeCert"], key=cert_key)

    def _create_csr(self, identifiers, cert_key):
        alternativeNames = [x509.DNSName(val["value"]) for val in identifiers]
        commonName = identifiers[0]["value"]
        # TODO csr contains a public key from a known account
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, commonName)])
            )
            .add_extension(
                x509.SubjectAlternativeName(alternativeNames), critical=False
            )
            .sign(cert_key, hashes.SHA256(), default_backend())
        )

        return csr.public_bytes(serialization.Encoding.DER)

    def _make_jws_request(
        self, payload: bytes, url: str, headers: Dict = {}, key=None
    ) -> Response:
        """Helper function to wrap the request in a JWS

        Args:
            payload: the body of the request
            url: the url of the endpoint

        Returns:
            response: the server response
        """
        if not key:
            key = self.account.key
        jws = JWS(key)
        params = {"nonce": self.get_nonce(), "url": url}
        if self.account.kid:
            params["kid"] = self.account.kid

        headers.update({"Content-Type": "application/jose+json"})

        return self._post(url, data=jws.create_jws(payload, **params), headers=headers)

    def _post(self, url, data, headers=None):
        """Helper function to perform a request. Extracts the Replay-Nonce from the response header

        Args:
            url (str): The url of the endpoint
            data: The body of the request
            headers: The request headers
        """
        try:
            res = self.s.post(url, data=data, headers=headers)
        except (ConnectionError, Timeout, SSLError) as e:
            raise AcmeError(type(e), e)

        nonce = res.headers.get("Replay-Nonce")
        if nonce:
            self.nonces.append(nonce)
        return res

    def _get(self, url, headers=None):
        try:
            res = self.s.get(url, headers=headers)
        except (ConnectionError, Timeout, SSLError) as e:
            raise AcmeError(type(e), e)
        return res

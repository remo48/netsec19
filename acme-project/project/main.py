import argparse
import hashlib
import os
import pathlib
import socketserver
import ssl
import threading
from functools import partial
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from dnslib.server import DNSHandler, DNSLogger

from acme.client import AcmeError, Client
from acme.utils import base64url_encode
from dns import Resolver

ROOT_CERT_PATH = "pebble.minica.pem"
CHALL_TYPE_MAP = {"dns01": "dns-01", "http01": "http-01"}


class ShutdownHandler(BaseHTTPRequestHandler):
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        if self.path == "/shutdown":
            self.server.keep_running = False
        return


class HTTPSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        return


def main(args):
    out_dir = "temp"
    web_dir = os.path.join(out_dir, "web/")
    challenge_dir = os.path.join(web_dir, ".well-known/acme-challenge/")
    setup([out_dir, web_dir, challenge_dir])

    common_name = "example"

    keyfile_path = os.path.join(out_dir, ".".join([common_name, "key"]))
    certfile_path = os.path.join(out_dir, ".".join([common_name, "crt"]))

    dir_url = args.dir
    challenge_type = CHALL_TYPE_MAP[args.challenge_type]
    identifiers = get_identifiers(args.domain)
    default_ip = args.record
    revoke = args.revoke

    cert_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    dns_server = get_dns_server(default_ip)
    start_server(dns_server)
    challenge_server = get_http_challenge_server(web_dir)
    start_server(challenge_server)
    shutdown_server = get_http_shutdown_server()
    t1 = threading.Thread(target=run_shutdown_server, args=(shutdown_server,))
    t1.start()

    try:
        client = Client(dir_url, ROOT_CERT_PATH)

        client.create_account()

        order = client.submit_order(identifiers)
        client.fetch_challenges(order)
        challenges = order.get_challenges(challenge_type)

        for identifier, challenge in challenges:
            token = challenge["token"]
            key_auth = client.get_key_authorization(token).encode("utf-8")
            challenge_type = challenge["type"]
            if challenge_type == "dns-01":
                txt_entry = base64url_encode(hashlib.sha256(key_auth).digest()).decode(
                    "utf-8"
                )
                rname = ".".join(["_acme-challenge", identifier])
                dns_server.resolver.add_record(
                    rname=rname, rtype="TXT", rdata=txt_entry
                )
            elif challenge_type == "http-01":
                write_challenge(challenge_dir, token, key_auth)

            client.respond_to_challenge(challenge["url"])

        client.poll_order(order, timeout=60)
        client.finalize_order(order, cert_key)
        certificate = client.download_certificate(order.certificate)
        write_certificate(certificate, certfile_path)
        write_key(cert_key, keyfile_path)

        https_server = get_https_server(certfile_path, keyfile_path)
        start_server(https_server)

        if revoke:
            client.revoke_certificate(certificate)
    except AcmeError as e:
        print("Error occured during protocol execution:", e)
        print("shutting down servers")
        dns_server.shutdown()
        challenge_server.shutdown()

    t1.join()


def setup(directories):
    for directory in directories:
        pathlib.Path(directory).mkdir(parents=True, exist_ok=True)


def start_server(server):
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()


def write_key(pk, filename):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(filename, "wb") as pem_out:
        pem_out.write(pem)


def write_certificate(certificate, filename):
    with open(filename, "wb") as cert_out:
        cert_out.write(certificate)


def write_challenge(challenge_dir, token, key_auth):
    filename = os.path.join(challenge_dir, token)
    with open(filename, "wb") as out:
        out.write(key_auth)


def get_identifiers(domains):
    return list(map(lambda d: {"type": "dns", "value": d}, domains))


def get_https_server(certfile_path, keyfile_path):
    https_server = socketserver.TCPServer(("", 5001), HTTPSHandler)
    https_server.socket = ssl.wrap_socket(
        https_server.socket, certfile=certfile_path, keyfile=keyfile_path
    )
    return https_server


def get_dns_server(default_ip):
    dns_server = socketserver.UDPServer(("", 10053), DNSHandler)
    dns_server.resolver = Resolver(default_ip)
    dns_server.logger = DNSLogger()
    return dns_server


def get_http_challenge_server(web_directory):
    ChallengeHandler = partial(SimpleHTTPRequestHandler, directory=web_directory)
    challenge_server = socketserver.TCPServer(("", 5002), ChallengeHandler)
    return challenge_server


def get_http_shutdown_server():
    shutdown_server = socketserver.TCPServer(("", 5003), ShutdownHandler)
    shutdown_server.keep_running = True
    return shutdown_server


def run_shutdown_server(server):
    while server.keep_running:
        server.handle_request()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "challenge_type",
        help="indicates which ACME challenge type the client should perform",
    )
    parser.add_argument(
        "--dir", required=True, help="is the directory URL of the ACME server"
    )
    parser.add_argument(
        "--record",
        required=True,
        help="is the IPv4 address which must be returned by the DNS server",
    )
    parser.add_argument(
        "--domain",
        required=True,
        action="append",
        help="is the domain for which to request the certificate",
    )
    parser.add_argument(
        "--revoke",
        action="store_true",
        help="If present, your application should immediately revoke the certificate after obtaining it.",
    )

    args = parser.parse_args()
    main(args)

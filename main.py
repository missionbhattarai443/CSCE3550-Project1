from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
import datetime
import json
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


HOST = "localhost"
PORT = 8080


# Generate two RSA key pairs:
# one valid key and one expired key
valid_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

expired_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)


# Give each key a unique Key ID (kid)
valid_kid = str(uuid.uuid4())
expired_kid = str(uuid.uuid4())


# Store expiration times for both keys
now = datetime.datetime.now(datetime.timezone.utc)

valid_key_expiry = now + datetime.timedelta(hours=1)
expired_key_expiry = now - datetime.timedelta(hours=1)


def int_to_base64(value):
    """Convert an integer to Base64URL format used by JWK."""
    byte_length = (value.bit_length() + 7) // 8
    value_bytes = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")


def public_key_to_jwk(private_key, kid):
    """Convert an RSA public key into JWK format."""
    public_numbers = private_key.public_key().public_numbers()

    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }


class JWKSHandler(BaseHTTPRequestHandler):
    """Handle requests for the JWKS server."""

    def do_GET(self):
        parsed_path = urlparse(self.path)

        if parsed_path.path == "/.well-known/jwks.json":
            # JWKS should contain only keys that have not expired.
            keys = []

            current_time = datetime.datetime.now(datetime.timezone.utc)

            if valid_key_expiry > current_time:
                keys.append(
                    public_key_to_jwk(valid_private_key, valid_kid)
                )

            response = {"keys": keys}

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))
            return

        if parsed_path.path == "/auth":
            self.send_response(405)
            self.end_headers()
            return

        self.send_response(405)
        self.end_headers()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            current_time = datetime.datetime.now(datetime.timezone.utc)

            # Normal request: use the valid key and future expiration.
            signing_key = valid_private_key
            signing_kid = valid_kid
            token_expiry = current_time + datetime.timedelta(hours=1)

            # Expired request: use the expired RSA key and
            # give the JWT an expiration time in the past.
            if "expired" in params:
                signing_key = expired_private_key
                signing_kid = expired_kid
                token_expiry = current_time - datetime.timedelta(hours=1)

            payload = {
                "user": "fake_user",
                "exp": token_expiry,
            }

            headers = {
                "kid": signing_kid,
            }

            token = jwt.encode(
                payload,
                signing_key,
                algorithm="RS256",
                headers=headers,
            )

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(token.encode("utf-8"))
            return

        if parsed_path.path == "/.well-known/jwks.json":
            self.send_response(405)
            self.end_headers()
            return

        self.send_response(404)
        self.end_headers()

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), JWKSHandler)

    print(f"JWKS server running at http://{HOST}:{PORT}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

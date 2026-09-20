import datetime
import threading
import time

import jwt
import pytest
import requests
from http.server import HTTPServer

from main import (
    HOST,
    PORT,
    JWKSHandler,
    expired_kid,
    expired_private_key,
)


BASE_URL = f"http://{HOST}:{PORT}"


@pytest.fixture(scope="module")
def server():
    """Start the JWKS server for the test suite."""
    httpd = HTTPServer((HOST, PORT), JWKSHandler)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.daemon = True
    thread.start()

    time.sleep(0.2)

    yield httpd

    httpd.shutdown()
    thread.join()


def test_jwks_endpoint(server):
    """JWKS endpoint should return the valid public key."""
    response = requests.get(
        f"{BASE_URL}/.well-known/jwks.json",
        timeout=5,
    )

    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json"

    data = response.json()

    assert "keys" in data
    assert len(data["keys"]) == 1

    key = data["keys"][0]

    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert "kid" in key
    assert "n" in key
    assert "e" in key


def test_valid_authentication(server):
    """Normal /auth request should return a valid JWT."""
    response = requests.post(
        f"{BASE_URL}/auth",
        timeout=5,
    )

    assert response.status_code == 200

    token = response.text
    assert len(token.split(".")) == 3

    header = jwt.get_unverified_header(token)
    jwks = requests.get(
        f"{BASE_URL}/.well-known/jwks.json",
        timeout=5,
    ).json()

    valid_jwk = jwks["keys"][0]

    assert header["kid"] == valid_jwk["kid"]

    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(valid_jwk)

    payload = jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
    )

    assert payload["user"] == "fake_user"
    assert payload["exp"] > datetime.datetime.now(
        datetime.timezone.utc
    ).timestamp()


def test_expired_authentication(server):
    """Expired request should use the expired key and expiration."""
    response = requests.post(
        f"{BASE_URL}/auth?expired=true",
        timeout=5,
    )

    assert response.status_code == 200

    token = response.text
    header = jwt.get_unverified_header(token)

    assert header["kid"] == expired_kid

    expired_public_key = expired_private_key.public_key()

    payload = jwt.decode(
        token,
        expired_public_key,
        algorithms=["RS256"],
        options={"verify_exp": False},
    )

    assert payload["exp"] < datetime.datetime.now(
        datetime.timezone.utc
    ).timestamp()


def test_expired_key_not_in_jwks(server):
    """Expired key must not be returned by JWKS."""
    response = requests.get(
        f"{BASE_URL}/.well-known/jwks.json",
        timeout=5,
    )

    kids = [key["kid"] for key in response.json()["keys"]]

    assert expired_kid not in kids


def test_get_auth_not_allowed(server):
    """GET is not allowed on /auth."""
    response = requests.get(
        f"{BASE_URL}/auth",
        timeout=5,
    )

    assert response.status_code == 405


def test_post_jwks_not_allowed(server):
    """POST is not allowed on the JWKS endpoint."""
    response = requests.post(
        f"{BASE_URL}/.well-known/jwks.json",
        timeout=5,
    )

    assert response.status_code == 405


def test_invalid_endpoint(server):
    """Unknown endpoints should not be accepted."""
    response = requests.get(
        f"{BASE_URL}/not-a-real-endpoint",
        timeout=5,
    )

    assert response.status_code == 405

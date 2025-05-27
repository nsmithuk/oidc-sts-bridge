import base64
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict

import pytest
from botocore.exceptions import ClientError
from joserfc.jwt import Token
from mypy_boto3_sts.type_defs import CredentialsTypeDef
from urllib3.exceptions import HTTPError
from urllib3.response import HTTPResponse

from oidc_sts_bridge.main import ALLOWED_ALGORITHMS, KeyStore

mock_n = base64.urlsafe_b64encode(os.urandom(256)).rstrip(b"=").decode()

# Mock JWKS for testing
MOCK_JWKS = {
    "keys": [
        {"kid": "key1", "alg": "RS256", "kty": "RSA", "n": mock_n, "e": "AQAB"},
        {"kid": "key2", "alg": "RS256", "kty": "RSA", "n": mock_n, "e": "AQAB"},
    ]
}

# Mock JWT token and claims
MOCK_JWT = "mock.jwt.token"
MOCK_CLAIMS = {
    "iss": "test-issuer",
    "sub": "user123",
    "aud": "audience",
    "exp": int((datetime.now() + timedelta(hours=1)).timestamp()),  # Valid 1 hour from now
    "nbf": int((datetime.now() - timedelta(hours=1)).timestamp()),  # Valid from 1 hour ago
    "iat": int(datetime.now().timestamp()),  # Issued now
    "jti": "unique-id",
    "custom": "value",
}
MOCK_TOKEN = Token(header={"kid": "key1", "alg": "RS256"}, claims=MOCK_CLAIMS)

# Mock AWS credentials
MOCK_CREDENTIALS: CredentialsTypeDef = {
    "AccessKeyId": "mock-access-key",
    "SecretAccessKey": "mock-secret-key",
    "SessionToken": "mock-session-token",
    "Expiration": datetime.now() + timedelta(hours=1),  # Expires 1 hour from now
}


@pytest.fixture
def mock_pool_manager():
    """Mock PoolManager for HTTP requests."""

    class MockPoolManager:
        def __init__(self):
            self.responses: Dict[str, HTTPResponse] = {}

        def request(self, method: str, url: str, **kwargs: Any) -> HTTPResponse:
            if url in self.responses:
                return self.responses[url]
            raise HTTPError(f"No response configured for {url}")

    return MockPoolManager()


@pytest.fixture
def mock_sts_client():
    """Mock STSClient for AWS role assumption."""

    class MockSTSClient:
        def __init__(self):
            self.responses: Dict[str, Any] = {}
            self.calls: list[dict] = []

        def assume_role(self, **kwargs: Any) -> dict:
            self.calls.append(kwargs)
            role_arn = kwargs.get("RoleArn", "")
            if role_arn in self.responses:
                return self.responses[role_arn]
            raise ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "Mock error"}}, "AssumeRole"
            )

    return MockSTSClient()


@pytest.fixture
def mock_key_store(mock_pool_manager, request):
    """Mock KeyStore with pre-configured JWKS response and configurable jwks_cache_ttl."""
    jwks_cache_ttl = getattr(request, "param", None)
    key_store = KeyStore("https://example.com/jwks", jwks_cache_ttl)
    key_store._http = mock_pool_manager
    mock_pool_manager.responses["https://example.com/jwks"] = HTTPResponse(
        body=json.dumps(MOCK_JWKS).encode("utf-8"), status=200
    )
    return key_store


@pytest.fixture
def mock_jwt_decode(monkeypatch):
    """Mock joserfc.jwt.decode to return a predefined token."""

    def mock_decode(value: str, key: Any, algorithms: list[str]) -> Token:
        if value == MOCK_JWT and algorithms == ALLOWED_ALGORITHMS:
            return MOCK_TOKEN
        raise ValueError("Invalid token or algorithms")

    monkeypatch.setattr("joserfc.jwt.decode", mock_decode)

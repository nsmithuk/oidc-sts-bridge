from joserfc.errors import MissingClaimError

from oidc_sts_bridge.main import CORE_CLAIMS, Exchanger

from .test_mocks import *


def test_exchanger_init_valid(mock_key_store, mock_sts_client):
    """Test Exchanger initialization with valid inputs."""
    exchanger = Exchanger(
        jwks_uri="https://example.com/jwks",
        issuer="test-issuer",
        sts_client=mock_sts_client,
        additional_claims=["custom"],
    )
    assert exchanger._jwt._issuer == "test-issuer"
    assert exchanger._aws._sts_client == mock_sts_client
    assert exchanger._expected_claims == CORE_CLAIMS + ["custom"]


def test_exchanger_exchange_success(mock_key_store, mock_sts_client, mock_jwt_decode):
    """Test Exchanger exchanging a JWT for credentials."""
    exchanger = Exchanger(
        jwks_uri="https://example.com/jwks",
        issuer="test-issuer",
        sts_client=mock_sts_client,
        additional_claims=["custom"],
    )
    role_arn = "arn:aws:iam::123456789012:role/MyRole"
    mock_sts_client.responses[role_arn] = {"Credentials": MOCK_CREDENTIALS}
    tags = {"tag1": "val1"}
    result = exchanger.exchange(MOCK_JWT, role_arn, tags)
    assert result["Header"] == {"kid": "key1", "alg": "RS256"}
    assert result["Claims"]["All"] == MOCK_CLAIMS
    assert result["Claims"]["Passed"] == {
        "iss": "test-issuer",
        "sub": "user123",
        "aud": "audience",
        "exp": MOCK_CLAIMS["exp"],
        "nbf": MOCK_CLAIMS["nbf"],
        "iat": MOCK_CLAIMS["iat"],
        "jti": "unique-id",
        "custom": "value",
    }
    assert result["Credentials"]["AccessKeyId"] == "mock-access-key"
    assert result["Credentials"]["Expiration"] == MOCK_CREDENTIALS["Expiration"].isoformat()
    assert len(mock_sts_client.calls) == 1
    call = mock_sts_client.calls[0]
    assert call["Tags"] == [
        {"Key": "claim.iss", "Value": "test-issuer"},
        {"Key": "claim.sub", "Value": "user123"},
        {"Key": "claim.aud", "Value": "audience"},
        {"Key": "claim.exp", "Value": str(MOCK_CLAIMS["exp"])},
        {"Key": "claim.nbf", "Value": str(MOCK_CLAIMS["nbf"])},
        {"Key": "claim.iat", "Value": str(MOCK_CLAIMS["iat"])},
        {"Key": "claim.jti", "Value": "unique-id"},
        {"Key": "claim.custom", "Value": "value"},
        {"Key": "tag1", "Value": "val1"},
    ]


def test_exchanger_exchange_invalid_arn(mock_key_store, mock_sts_client, mock_jwt_decode):
    """Test Exchanger rejecting invalid role ARN."""
    exchanger = Exchanger(
        jwks_uri="https://example.com/jwks", issuer="test-issuer", sts_client=mock_sts_client
    )
    with pytest.raises(ValueError, match="Passed role ARN does not look valid"):
        exchanger.exchange(MOCK_JWT, "invalid-arn", {})


def test_exchanger_exchange_jwt_validation_failure(mock_key_store, mock_sts_client, monkeypatch):
    """Test Exchanger handling JWT validation failure."""

    def mock_decode(value: str, key: Any, algorithms: list[str]) -> Token:
        if value == MOCK_JWT and algorithms == ALLOWED_ALGORITHMS:
            claims = MOCK_CLAIMS.copy()
            del claims["jti"]  # Missing core claim
            return Token(header={"kid": "key1", "alg": "RS256"}, claims=claims)
        raise ValueError("Invalid token")

    monkeypatch.setattr("joserfc.jwt.decode", mock_decode)
    exchanger = Exchanger(
        jwks_uri="https://example.com/jwks", issuer="test-issuer", sts_client=mock_sts_client
    )
    role_arn = "arn:aws:iam::123456789012:role/MyRole"
    with pytest.raises(MissingClaimError, match="jti"):
        exchanger.exchange(MOCK_JWT, role_arn, {})


def test_exchanger_exchange_aws_failure(mock_key_store, mock_sts_client, mock_jwt_decode):
    """Test Exchanger handling AWS role assumption failure."""
    exchanger = Exchanger(
        jwks_uri="https://example.com/jwks", issuer="test-issuer", sts_client=mock_sts_client
    )
    role_arn = "arn:aws:iam::123456789012:role/MyRole"
    with pytest.raises(RuntimeError, match="Failed to assume role"):
        exchanger.exchange(MOCK_JWT, role_arn, {})

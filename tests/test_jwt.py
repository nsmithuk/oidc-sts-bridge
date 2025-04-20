from joserfc.errors import BadSignatureError, InvalidClaimError, MissingClaimError

from oidc_sts_bridge.main import JWT

from .test_mocks import *


def test_jwt_init_valid_issuer(mock_key_store):
    """Test JWT initialisation with a valid issuer."""
    jwt = JWT(issuer="test-issuer", key_store=mock_key_store, additional_claims=["custom"])
    assert jwt._issuer == "test-issuer"
    assert jwt._key_store == mock_key_store
    assert jwt._additional_claims == ["custom"]


def test_jwt_init_invalid_issuer(mock_key_store):
    """Test JWT initialisation with invalid issuers."""
    with pytest.raises(ValueError, match="issuer must be a non-empty string"):
        JWT(issuer="", key_store=mock_key_store)
    with pytest.raises(ValueError, match="issuer must be a non-empty string"):
        JWT(issuer=123, key_store=mock_key_store)


def test_jwt_get_validated_token_success(mock_key_store, mock_jwt_decode):
    """Test JWT validating a token with all required claims."""
    jwt = JWT(issuer="test-issuer", key_store=mock_key_store, additional_claims=["custom"])
    token = jwt.get_validated_token(MOCK_JWT)
    assert token == MOCK_TOKEN
    assert token.claims["iss"] == "test-issuer"
    assert token.claims["custom"] == "value"


def test_jwt_get_validated_token_missing_core_claim(mock_key_store, monkeypatch):
    """Test JWT rejecting a token missing a core claim."""

    def mock_decode(value: str, key: Any, algorithms: list[str]) -> Token:
        if value == MOCK_JWT and algorithms == ALLOWED_ALGORITHMS:
            claims = MOCK_CLAIMS.copy()
            del claims["sub"]  # Missing core claim
            return Token(header={"kid": "key1", "alg": "RS256"}, claims=claims)
        raise ValueError("Invalid token")

    monkeypatch.setattr("joserfc.jwt.decode", mock_decode)
    jwt = JWT(issuer="test-issuer", key_store=mock_key_store)
    with pytest.raises(MissingClaimError, match="sub"):
        jwt.get_validated_token(MOCK_JWT)


def test_jwt_get_validated_token_incorrect_issuer(mock_key_store, monkeypatch):
    """Test JWT rejecting a token with incorrect issuer."""

    def mock_decode(value: str, key: Any, algorithms: list[str]) -> Token:
        if value == MOCK_JWT and algorithms == ALLOWED_ALGORITHMS:
            claims = MOCK_CLAIMS.copy()
            claims["iss"] = "wrong-issuer"
            return Token(header={"kid": "key1", "alg": "RS256"}, claims=claims)
        raise ValueError("Invalid token")

    monkeypatch.setattr("joserfc.jwt.decode", mock_decode)
    jwt = JWT(issuer="test-issuer", key_store=mock_key_store)
    with pytest.raises(InvalidClaimError, match="iss"):
        jwt.get_validated_token(MOCK_JWT)


def test_jwt_get_validated_token_missing_additional_claim(mock_key_store, monkeypatch):
    """Test JWT rejecting a token missing an additional claim."""

    def mock_decode(value: str, key: Any, algorithms: list[str]) -> Token:
        if value == MOCK_JWT and algorithms == ALLOWED_ALGORITHMS:
            claims = MOCK_CLAIMS.copy()
            del claims["custom"]  # Missing additional claim
            return Token(header={"kid": "key1", "alg": "RS256"}, claims=claims)
        raise ValueError("Invalid token")

    monkeypatch.setattr("joserfc.jwt.decode", mock_decode)
    jwt = JWT(issuer="test-issuer", key_store=mock_key_store, additional_claims=["custom"])
    with pytest.raises(MissingClaimError, match="custom"):
        jwt.get_validated_token(MOCK_JWT)


def test_jwt_get_validated_token_invalid_token(mock_key_store, monkeypatch):
    """Test JWT handling invalid token decoding."""

    def mock_decode(value: str, key: Any, algorithms: list[str]) -> Token:
        raise BadSignatureError("Invalid token")

    monkeypatch.setattr("joserfc.jwt.decode", mock_decode)
    jwt = JWT(issuer="test-issuer", key_store=mock_key_store)
    with pytest.raises(BadSignatureError, match="Invalid token"):
        jwt.get_validated_token("invalid.jwt")

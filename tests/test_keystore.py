from unittest.mock import patch

from joserfc.jwk import Key, KeySet
from urllib3 import PoolManager

from .test_mocks import *


def test_key_store_init_valid_jwks_uri():
    """Test KeyStore initialisation with a valid HTTPS JWKS URI and jwks_cache_ttl."""
    key_store = KeyStore("https://example.com/jwks", jwks_cache_ttl=None)
    assert key_store._jwks_uri == "https://example.com/jwks"
    assert isinstance(key_store._http, PoolManager)
    assert key_store._jwks_cache_ttl is None
    assert key_store._cached_key_set is None
    assert key_store._cached_at is None

    ttl = timedelta(hours=1)
    key_store = KeyStore("https://example.com/jwks", jwks_cache_ttl=ttl)
    assert key_store._jwks_cache_ttl == ttl


def test_key_store_init_invalid_jwks_uri():
    """Test KeyStore initialisation with invalid JWKS URIs."""
    with pytest.raises(ValueError, match="jwks_uri must be a valid HTTPS URL"):
        KeyStore("http://example.com/jwks", jwks_cache_ttl=None)  # Non-HTTPS
    with pytest.raises(ValueError, match="jwks_uri must be a valid HTTPS URL"):
        KeyStore("", jwks_cache_ttl=None)  # Empty
    with pytest.raises(ValueError, match="jwks_uri must be a valid HTTPS URL"):
        KeyStore(123, jwks_cache_ttl=None)  # Non-string


def test_key_store_init_invalid_jwks_cache_ttl():
    """Test KeyStore initialisation with invalid jwks_cache_ttl values."""
    with pytest.raises(ValueError, match="jwks_cache_ttl must be a timedelta or None"):
        KeyStore("https://example.com/jwks", jwks_cache_ttl=123)  # Non-timedelta
    with pytest.raises(ValueError, match="jwks_cache_ttl must be a timedelta or None"):
        KeyStore("https://example.com/jwks", jwks_cache_ttl="1h")  # String


def test_key_store_download_keyset_success(mock_pool_manager, caplog):
    """Test KeyStore downloading a JWKS successfully."""
    key_store = KeyStore("https://example.com/jwks", jwks_cache_ttl=None)
    key_store._http = mock_pool_manager
    mock_pool_manager.responses["https://example.com/jwks"] = HTTPResponse(
        body=json.dumps(MOCK_JWKS).encode("utf-8"), status=200
    )
    key_set = key_store._download_keyset()
    assert isinstance(key_set, KeySet)
    assert len(key_set.keys) == 2
    assert key_store._cached_key_set == key_set


def test_key_store_download_keyset_http_error(mock_pool_manager):
    """Test KeyStore handling HTTP errors during JWKS download."""
    key_store = KeyStore("https://example.com/jwks", jwks_cache_ttl=None)
    key_store._http = mock_pool_manager
    mock_pool_manager.responses["https://example.com/jwks"] = HTTPResponse(body=b"", status=500)
    with pytest.raises(HTTPError, match="Unexpected HTTP status code 500"):
        key_store._download_keyset()


def test_key_store_download_keyset_invalid_json(mock_pool_manager):
    """Test KeyStore handling invalid JSON in JWKS response."""
    key_store = KeyStore("https://example.com/jwks", jwks_cache_ttl=None)
    key_store._http = mock_pool_manager
    mock_pool_manager.responses["https://example.com/jwks"] = HTTPResponse(
        body=b"invalid json", status=200
    )
    with pytest.raises(ValueError, match="Invalid JWKS \\(JSON\\) format"):
        key_store._download_keyset()


@pytest.mark.parametrize("mock_key_store", [timedelta(hours=1)], indirect=True)
def test_key_store_call_cached_key(mock_key_store, mock_pool_manager):
    """Test KeyStore returning a cached key for a known kid within TTL."""

    class MockGuest:
        def headers(self):
            return {"kid": "key1", "alg": "RS256"}

    guest = MockGuest()
    with patch.object(mock_pool_manager, "request") as mock_request:
        mock_request.return_value = HTTPResponse(
            body=json.dumps(MOCK_JWKS).encode("utf-8"), status=200
        )
        mock_key_store._download_keyset()  # Cache the key set
        key = mock_key_store(guest)
        assert isinstance(key, Key)
        assert mock_request.call_count == 1  # Only one download


@pytest.mark.parametrize("mock_key_store", [timedelta(hours=1)], indirect=True)
def test_key_store_call_cache_miss(mock_key_store, mock_pool_manager):
    """Test KeyStore downloading JWKS on cache miss for unknown kid."""

    class MockGuest:
        def headers(self):
            return {"kid": "key3", "alg": "RS256"}

    guest = MockGuest()
    with patch.object(mock_pool_manager, "request") as mock_request:
        mock_request.return_value = HTTPResponse(
            body=json.dumps(MOCK_JWKS).encode("utf-8"), status=200
        )
        mock_key_store._download_keyset()  # Cache the key set
        key_set = mock_key_store(guest)
        assert isinstance(key_set, KeySet)
        assert len(key_set.keys) == 2
        assert mock_request.call_count == 2  # Second download for miss


@pytest.mark.parametrize("mock_key_store", [None], indirect=True)
def test_key_store_call_cache_disabled(mock_key_store, mock_pool_manager):
    """Test KeyStore downloading JWKS for every call when caching is disabled."""

    class MockGuest:
        def headers(self):
            return {"kid": "key1", "alg": "RS256"}

    guest = MockGuest()
    with patch.object(mock_pool_manager, "request") as mock_request:
        mock_request.return_value = HTTPResponse(
            body=json.dumps(MOCK_JWKS).encode("utf-8"), status=200
        )
        mock_key_store._download_keyset()  # Initial download
        key_set = mock_key_store(guest)
        assert isinstance(key_set, KeySet)
        assert len(key_set.keys) == 2
        key_set_again = mock_key_store(guest)
        assert isinstance(key_set_again, KeySet)
        assert mock_request.call_count == 3  # Downloads for each call


@pytest.mark.parametrize("mock_key_store", [timedelta(seconds=1)], indirect=True)
def test_key_store_call_cache_expired(mock_key_store, mock_pool_manager):
    """Test KeyStore downloading JWKS when cache expires."""

    class MockGuest:
        def headers(self):
            return {"kid": "key1", "alg": "RS256"}

    guest = MockGuest()
    with patch.object(mock_pool_manager, "request") as mock_request:
        mock_request.return_value = HTTPResponse(
            body=json.dumps(MOCK_JWKS).encode("utf-8"), status=200
        )
        mock_key_store._download_keyset()  # Cache the key set
        # Set cache time to ensure expiration
        mock_key_store._cached_at = datetime.now() - timedelta(seconds=2)
        key = mock_key_store(guest)
        assert isinstance(key, KeySet)
        assert mock_request.call_count == 2  # Second download after expiration


def test_key_store_call_missing_headers():
    """Test KeyStore rejecting JWTs with missing kid or alg headers."""
    key_store = KeyStore("https://example.com/jwks", jwks_cache_ttl=None)

    class MockGuest:
        def headers(self):
            return {"kid": "key1"}  # Missing alg

    guest = MockGuest()
    with pytest.raises(ValueError, match="JWT header missing required fields: kid or alg"):
        key_store(guest)

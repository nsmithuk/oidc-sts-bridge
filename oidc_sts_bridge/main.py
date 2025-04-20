import json
import logging
from datetime import datetime, timedelta
from re import match as rematch

from botocore.exceptions import BotoCoreError, ClientError
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import GuestProtocol, KeyBase, KeySet
from joserfc.jwt import JWTClaimsRegistry, Token
from mypy_boto3_sts import STSClient
from mypy_boto3_sts.type_defs import CredentialsTypeDef
from urllib3 import PoolManager
from urllib3.exceptions import HTTPError

from .utils import is_stringable

# Allowed JWT algorithms for signature verification, using standard asymmetric algorithms supported by joserfc.
ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"]

# Core JWT claims required for validation, per RFC 7519.
CORE_CLAIMS = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

# Logging configuration with a default warning level to minimise performance overhead.
# Structured 'extra' data in logs aids debugging and monitoring.
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)


class KeyStore:
    """Manages JWKS retrieval and caching for JWT key resolution.

    Args:
        jwks_uri: HTTPS URI of the JWKS endpoint.
        jwks_cache_ttl: Cache TTL as a timedelta, or None to disable caching.

    Raises:
        ValueError: If jwks_uri is not a valid HTTPS URL or jwks_cache_ttl is neither a timedelta nor None.

    Notes:
        - Caches JWKS for the specified jwks_cache_ttl duration to optimise performance, as private IDP keys are typically long-lived. You can set a long TTL for stable keys.
        - Disables caching if jwks_cache_ttl is None, downloading JWKS for each request.
        - Refreshes the cache on cache miss (unknown kid) or TTL expiration to minimise HTTP requests.
        - Returns a Key for cached kid or the full KeySet on miss, letting joserfc select the key.
        - Enforces HTTPS for jwks_uri to ensure secure key retrieval for private IDPs.
        - Callers handle retries for failed downloads to keep this class lightweight.
        - PoolManager cleanup is managed externally to avoid context manager overhead.
    """

    def __init__(self, jwks_uri: str, jwks_cache_ttl: timedelta | None):
        """Initializes the KeyStore with JWKS URI and cache TTL.

        Validates inputs for security and correctness.
        """
        # Validate jwks_uri to ensure it is a secure HTTPS URL.
        if not isinstance(jwks_uri, str) or not jwks_uri.lower().startswith("https://"):
            raise ValueError("jwks_uri must be a valid HTTPS URL")

        # Validate jwks_cache_ttl to ensure it is a timedelta or None.
        if jwks_cache_ttl is not None and not isinstance(jwks_cache_ttl, timedelta):
            raise ValueError("jwks_cache_ttl must be a timedelta or None")

        self._jwks_uri = jwks_uri
        self._http = PoolManager()

        self._jwks_cache_ttl = jwks_cache_ttl

        self._cached_at: datetime | None = None
        self._cached_key_set: KeySet | None = None

    def _download_keyset(self) -> KeySet:
        """Downloads and parses the JWKS, caching the result.

        Returns:
            KeySet: The parsed JWKS as a joserfc KeySet.

        Raises:
            HTTPError: If the HTTP request fails or returns a non-200 status.
            ValueError: If the JWKS JSON is invalid.

        Notes:
            - Propagates errors to callers for retry handling.
            - Logs the number of keys and JWKS data for debugging and monitoring.
        """
        try:
            resp = self._http.request("GET", self._jwks_uri)
            if resp.status != 200:
                raise HTTPError(f"Unexpected HTTP status code {resp.status} during JWK lookup")
        except HTTPError as e:
            raise HTTPError(f"Failed to download JWKS from {self._jwks_uri}: {str(e)}") from e

        try:
            keys = json.loads(resp.data.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JWKS (JSON) format from {self._jwks_uri}: {str(e)}") from e

        self._cached_key_set = KeySet.import_key_set(keys)
        self._cached_at = datetime.now()

        # Logs the public keys for debugging.
        logger.info(
            f"Loaded {len(self._cached_key_set.keys)} keys from {self._jwks_uri}",
            extra=self._cached_key_set.as_dict(private=False),
        )

        return self._cached_key_set

    def __call__(self, obj: GuestProtocol) -> KeyBase:
        """Resolves a key for JWT verification based on the token's headers.

        Args:
            obj: GuestProtocol object with JWT headers.

        Returns:
            KeyBase: A Key (if cached and valid) or KeySet (on cache miss, expiration, or no caching) for joserfc to use.

        Raises:
            ValueError: If kid or alg headers are missing.

        Notes:
            - Validates kid and alg headers to catch malformed JWTs early.
            - Uses cached Key for known kid if caching is enabled and the cache is valid to optimise performance.
            - Downloads and returns KeySet if caching is disabled (jwks_cache_ttl is None), on cache miss (unknown kid), or on TTL expiration, letting joserfc resolve the key.
            - Logs cache hits, misses, and downloads for debugging with structured extra data.
        """
        headers = obj.headers()
        kid = headers.get("kid")
        alg = headers.get("alg")
        if not kid or not alg:
            raise ValueError("JWT header missing required fields: kid or alg")

        if (
            self._jwks_cache_ttl is not None
            and self._cached_key_set is not None
            and self._cached_at is not None
        ):
            expires_at = self._cached_at + self._jwks_cache_ttl
            if expires_at > datetime.now():
                try:
                    key = self._cached_key_set.get_by_kid(kid)
                    logger.debug(f"Using cached key for kid: {kid}", extra={"kid": kid, "alg": alg})
                    return key
                except InvalidKeyIdError:
                    # Downloads a fresh KeySet if the key is not found.
                    logger.debug(
                        f"Key not found in cache for kid: {kid}", extra={"kid": kid, "alg": alg}
                    )
                    pass

        logger.debug(f"Downloading JWKS to resolve kid: {kid}", extra={"kid": kid, "alg": alg})
        return self._download_keyset()


class JWT:
    """Validates JWTs using joserfc with separate claim registries for core and additional claims.

    Args:
        issuer: Expected issuer of the JWT (non-empty string).
        key_store: KeyStore for JWKS retrieval.
        additional_claims: Optional list of additional claim names to validate.

    Raises:
        ValueError: If issuer is not a non-empty string.

    Notes:
        - Uses two JWTClaimsRegistry instances for defensive coding: one for core claims (iss, sub, aud, exp, nbf, iat, jti) and one for additional claims.
        - Relies on joserfc for security-critical validation (signatures, claims, timing).
        - Validates issuer to prevent misconfigurations.
    """

    def __init__(
        self, issuer: str, key_store: KeyStore, additional_claims: list[str] | None = None
    ):
        """Initializes the JWT validator with issuer and key store.

        Validates issuer to ensure correct configuration.
        """
        # Validate issuer to catch misconfigurations early.
        if not isinstance(issuer, str) or not issuer.strip():
            raise ValueError("issuer must be a non-empty string")

        self._issuer = issuer
        self._key_store = key_store
        self._additional_claims = additional_claims

    def get_validated_token(self, token: str) -> Token:
        """Validates a JWT token using joserfc.

        Args:
            token: The JWT string to validate.

        Returns:
            Token: The decoded and validated JWT.

        Raises:
            joserfc.errors.JWTError: If decoding or claims validation fails (e.g., invalid signature, expired token).

        Notes:
            - Delegates signature verification and key selection to joserfc via key_store.
            - Uses separate JWTClaimsRegistry for core claims to ensure static, critical validations.
            - Validates additional claims separately to isolate user-defined claim risks.
        """
        # Decodes the token, raising an exception on invalid signature or format.
        decoded_token = jwt.decode(
            value=token,
            key=self._key_store,
            algorithms=ALLOWED_ALGORITHMS,
        )

        # Validates core claims, including timing fields (exp, nbf, iat).
        claims_requests = JWTClaimsRegistry(
            exp={"essential": True},
            nbf={"essential": True},
            iat={"essential": True},
            sub={"essential": True},
            aud={"essential": True},
            jti={"essential": True},
            iss={"essential": True, "value": self._issuer},
        )

        # Raises an exception if core claims are invalid (e.g., expired, wrong issuer).
        claims_requests.validate(decoded_token.claims)

        if self._additional_claims is not None:
            # Validates additional claims separately to keep core claims static.
            claims_requests = JWTClaimsRegistry(
                **{claim: {"essential": True} for claim in self._additional_claims}
            )
            claims_requests.validate(decoded_token.claims)

        return decoded_token


class AWS:
    """Handles AWS role assumption with validated claims and tags.

    Args:
        sts_client: Boto3 STS client for assuming roles.

    References:
        https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html
    """

    def __init__(self, sts_client: STSClient):
        """Initializes the AWS role assumption handler with an STS client."""
        self._sts_client = sts_client

    def assume_role(self, role_arn: str, claims: dict, tags: dict) -> CredentialsTypeDef:
        """Assumes an IAM role using validated claims and tags as session tags.

        Args:
            role_arn: The ARN of the IAM role to assume.
            claims: Validated JWT claims to include as session tags.
            tags: Additional session tags to include.

        Returns:
            CredentialsTypeDef: AWS credentials for the assumed role.

        Raises:
            RuntimeError: If role assumption fails, with a generic message to avoid leaking details.
            ValueError: If claims or tags are invalid.

        Notes:
            - Merges claims and tags with strict validation to meet AWS STS limits (50 tags, 128-char keys, 256-char values).
            - Uses jti as RoleSessionName and iss as ExternalId for traceability.
            - Logs the request and errors for debugging, using a generic exception to protect sensitive role details.
        """
        claims_and_tags = self.map_validate_merge_claims_and_tags(claims, tags)
        formatted_claims_and_tags = [
            {"Key": k, "Value": str(v)} for k, v in claims_and_tags.items()
        ]

        external_id = claims["iss"]
        role_session_name = claims["jti"]

        request = {
            "RoleArn": role_arn,
            "RoleSessionName": role_session_name,
            "ExternalId": external_id,
            "Tags": formatted_claims_and_tags,
        }

        logger.info(
            f"Assuming role {role_arn} with session name {role_session_name}",
            extra={"request": request},
        )

        try:
            response = self._sts_client.assume_role(**request)
        except (BotoCoreError, ClientError) as e:
            logger.error(e)
            # Uses a generic exception to avoid leaking role details.
            raise RuntimeError(
                f"Failed to assume role '{role_arn}' with ExternalId '{external_id}' and tags: {claims_and_tags}"
            )

        return response["Credentials"]

    @classmethod
    def does_role_arn_look_sensible(cls, role_arn: str) -> bool:
        """Validates the format of an IAM role ARN.

        Args:
            role_arn: The ARN to validate.

        Returns:
            bool: True if the ARN matches the expected pattern, False otherwise.

        Notes:
            - Uses a regex to enforce AWS ARN format (12-digit account ID, role path, valid characters).
            - Supports role paths and names up to 128 characters, per AWS IAM limits.
        """
        pattern = r"^arn:aws:iam::\d{12}:role(/[A-Za-z0-9+=,.@_-]+)*[A-Za-z0-9+=,.@_-]{1,128}$"
        return bool(rematch(pattern, role_arn))

    @classmethod
    def map_validate_merge_claims_and_tags(cls, claims: dict, tags: dict) -> dict:
        """Validates and merges JWT claims and additional tags for AWS session tags.

        Args:
            claims: JWT claims to include as session tags.
            tags: Additional session tags to include.

        Returns:
            dict: Merged claims (prefixed with 'claim.') and tags.

        Raises:
            ValueError: If claims or tags violate AWS limits or contain invalid values.

        Notes:
            - Enforces AWS STS limits: 50 tags total, 128-char keys, 256-char values.
            - Prevents 'claim.' prefixes in keys to avoid collisions with prefixed claims.
            - Ensures values are stringable to meet AWS requirements.
            - Prefixes claim keys with 'claim.' to distinguish them from tags.
        """
        if (len(claims) + len(tags)) > 50:
            raise ValueError(
                f"STS supports maximum of 50 session tags. {len(claims)} claims and {len(tags)} tags passed."
            )

        for k in claims.keys() | tags.keys():
            if k.lower().startswith("claim."):
                raise ValueError(
                    f"Claim and tag names that are prefixed with 'claim.' are not allowed: {k}"
                )

        # Map all claim key names to be prefixed with 'claim.'
        claims = {f"claim.{k}": v for k, v in claims.items()}

        # Merges claims and tags, ensuring no key collisions.
        for k, v in (claims | tags).items():
            if not is_stringable(v):
                raise ValueError(
                    f"Claim and tag values must be strings, or be castable to a string. {v} is not."
                )

            v_str = str(v)

            if len(k) > 128:
                raise ValueError(
                    f"Claim and tag names can’t exceed 128 characters. Key {k} contains {len(k)} characters."
                )

            if len(v_str) > 256:
                raise ValueError(
                    f"Claim and tag values can’t exceed 256 characters. Value {v_str} contains {len(v_str)} characters, for key {k}."
                )

        return claims | tags


class Exchanger:
    """Orchestrates JWT token exchange for AWS credentials by validating tokens and assuming IAM roles.

    Args:
        jwks_uri: HTTPS URI of the JWKS endpoint.
        issuer: Expected issuer of the JWT (non-empty string).
        sts_client: Boto3 STS client for assuming roles.
        additional_claims: Optional list of additional claim names to validate.
        jwks_cache_ttl: Cache TTL for JWKS as a timedelta, or None to disable caching.

    Notes:
        - Validates inputs (jwks_uri, issuer) to prevent misuse.
        - Uses joserfc for security-critical JWT validation (signatures, claims, timing).
        - Caches JWKS for the specified jwks_cache_ttl duration, or downloads for each request if None, to optimise performance for private IDPs with long-lived keys.
        - Lowercases claim keys for consistency and to avoid case-sensitivity issues in AWS session tags.
        - Logs errors and validation results for debugging with structured extra data.
        - Propagates errors to callers after logging for robust error handling.
    """

    def __init__(
        self,
        jwks_uri: str,
        issuer: str,
        sts_client: STSClient,
        additional_claims: list[str] | None = None,
        jwks_cache_ttl: timedelta | None = None,
    ):
        """Initializes the Exchanger with OIDC and AWS configurations.

        Creates KeyStore and JWT instances for token validation and AWS for role assumption.
        """
        key_store = KeyStore(jwks_uri=jwks_uri, jwks_cache_ttl=jwks_cache_ttl)
        self._jwt = JWT(issuer=issuer, key_store=key_store, additional_claims=additional_claims)
        self._aws = AWS(sts_client=sts_client)

        self._expected_claims = CORE_CLAIMS.copy()
        if additional_claims is not None:
            self._expected_claims.extend(additional_claims)

    def exchange(
        self, jwt_token: str, role_arn_to_assume: str, tags: dict[str, str] | None = None
    ) -> dict:
        """Exchanges a JWT token for AWS credentials, including optional session tags.

        Args:
            jwt_token: The JWT to validate and extract claims from.
            role_arn_to_assume: The ARN of the IAM role to assume.
            tags: Optional session tags to include with claims.

        Returns:
            dict: Token header, claims (all and passed), and AWS credentials.

        Raises:
            ValueError: If the role ARN is invalid.
            joserfc.errors.JWTError: If token validation fails.
            RuntimeError: If role assumption fails.

        Notes:
            - Wraps _exchange to log errors before propagation for debugging.
            - Uses _exchange for core logic to separate error handling.
        """
        try:
            return self._exchange(jwt_token, role_arn_to_assume, tags)
        except Exception as e:
            logger.error(e)
            raise

    def _exchange(
        self, jwt_token: str, role_arn_to_assume: str, tags: dict[str, str] | None = None
    ) -> dict:
        """Implements JWT token exchange and role assumption.

        Args:
            jwt_token: The JWT to validate.
            role_arn_to_assume: The IAM role ARN.
            tags: Optional session tags.

        Returns:
            dict: Token header, claims, and AWS credentials.

        Raises:
            ValueError: If the role ARN is invalid.
            joserfc.errors.JWTError: If token validation fails.
            RuntimeError: If role assumption fails.

        Notes:
            - Validates ARN to catch invalid inputs early.
            - Filters and lowercases claims for consistency in AWS session tags.
            - Logs validated JWT details for debugging and auditing.
            - Copies CredentialsTypeDef to allow modification of Expiration for JSON serialisation.
            - Converts Expiration to ISO string for JSON compatibility.
        """
        if not self._aws.does_role_arn_look_sensible(role_arn_to_assume):
            raise ValueError(f"Passed role ARN does not look valid: {role_arn_to_assume}")

        # Validates the token, raising an exception if invalid.
        token = self._jwt.get_validated_token(token=jwt_token)

        # Enforces lowercase claim keys for consistency.
        filtered_claims = {
            k.lower(): v for k, v in token.claims.items() if k in self._expected_claims
        }

        logger.info(
            f"JWT validated",
            extra={
                "header": token.header,
                "claims": token.claims,
                "expected_claims": self._expected_claims,
            },
        )

        tags = tags or {}
        creds = self._aws.assume_role(
            role_arn=role_arn_to_assume, claims=filtered_claims, tags=tags
        )

        # Copies CredentialsTypeDef to a standard dict to allow modifying Expiration.
        creds = creds.copy()

        # Converts Expiration to ISO string for JSON compatibility.
        creds["Expiration"] = creds["Expiration"].isoformat()

        return {
            "header": token.header,
            "claims": {"all": token.claims, "passed": filtered_claims},
            "credentials": creds,
        }

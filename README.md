# oidc-sts-bridge

Validates OpenID Connect (OIDC) JSON Web Tokens (JWTs) from private Identity Providers (IDPs) and exchanges them for AWS temporary credentials, mapping claims to session tags with security and performance optimisations.

## Purpose

The `oidc-sts-bridge` project enables OIDC-based authentication for AWS when the OIDC Identity Provider (IDP) is not publicly accessible. AWS’s `AssumeRoleWithWebIdentity` is the standard method for exchanging OIDC JWTs for temporary AWS credentials, but it requires the OIDC IDP’s JWKS endpoint to be available on the internet for AWS to fetch public keys. For private IDPs (e.g., on internal networks), this is not possible.

This library validates OIDC JWTs and fetches JWKS from private IDPs, then exchanges the validated tokens for AWS credentials via STS. It must run in an environment with access to both the private OIDC IDP (e.g., a local network) and AWS STS (e.g., via the internet). It is designed for this specific use case, mapping JWT claims and additional tags to AWS session tags for role-based access control.

Use this library if:

- Your OIDC IDP is on a private network and not accessible to AWS.
- You need to authenticate users or services via OIDC for temporary AWS access.
- You want to propagate OIDC claims (e.g., user ID, roles) as AWS session tags for IAM policies.

**Note**: If your OIDC IDP is publicly accessible, use `AssumeRoleWithWebIdentity` directly, as it is the simpler option.

## Features

- **JWT Validation**: Uses `joserfc` for JWT signature verification and claim validation, delegating security-critical operations to a trusted library.
- **Private JWKS Retrieval**: Fetches JSON Web Key Sets (JWKS) from HTTPS endpoints on private networks, with caching for performance.
- **AWS STS Integration**: Assumes IAM roles via AWS STS, mapping OIDC claims and custom tags to session tags, adhering to AWS limits (50 tags, 128-char keys, 256-char values).
- **Custom Claim Support**: Validates core JWT claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) and user-defined claims for flexibility.
- **Defensive Coding**: Validates inputs (e.g., HTTPS-only JWKS URIs, IAM role ARNs) and handles edge cases to prevent errors.
- **Performance Optimisations**: Minimises HTTP requests with JWKS caching and avoids retry logic for efficiency.
- **Error Handling**: Logs structured errors (e.g., token validation, STS failures) and uses generic exceptions to avoid leaking sensitive details.
- **Case Normalisation**: Lowercases claim keys to ensure consistency in AWS session tags.

## Design Philosophies

The project is built with principles to ensure security, reliability, and maintainability for private IDP integration:

- **Security**:

  - Delegates JWT validation (signatures, claims, timing) to `joserfc`, minimising custom security logic. The `JWT` class enforces core claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`) and optional custom claims using separate registries to isolate risks.
  - Enforces HTTPS-only JWKS URIs in `KeyStore` to prevent insecure key retrieval on private networks.
  - Uses generic exceptions (e.g., `RuntimeError` in `AWS.assume_role`) to avoid leaking role or configuration details.
  - Sets `iss` as `ExternalId` and `jti` as `RoleSessionName` in STS calls for traceability without exposing sensitive data.

- **Defensive Coding**:

  - Validates all inputs, such as JWKS URIs (HTTPS-only in `KeyStore`), issuer strings, IAM role ARNs (via `AWS.does_role_arn_look_sensible`), and session tag values (via `is_stringable`), to catch misconfigurations early.
  - Handles edge cases, such as non-stringable values, missing JWT headers (`kid`, `alg`), or invalid JWKS JSON, ensuring robustness.
  - Uses separate claim validation in `JWT` for core and user-defined claims to maintain strict checks on critical fields.

- **Performance Optimisations**:

  - Caches JWKS indefinitely in `KeyStore` to minimise HTTP requests, refreshing only on cache miss (unknown `kid`), as private IDP keys are long-lived.
  - Avoids retry logic in JWKS downloads, keeping `KeyStore` lean and delegating retries to callers.
  - Uses efficient type checks and string conversions in `is_stringable` and `AWS.map_validate_merge_claims_and_tags` to reduce overhead for session tag validation.

- **Error Handling**:

  - Logs structured errors with context (e.g., JWT headers, claims, STS request details) via `logging` in `Exchanger.exchange` and other components for debugging.
  - Propagates generic exceptions to avoid leaking sensitive information, such as role ARNs or STS details.
  - Converts credentials to JSON-serializable formats (e.g., ISO string for `Expiration` in `Exchanger._exchange`) to ensure compatibility.
  - Handles edge cases like invalid JWKS JSON or non-stringable tag values gracefully.

- **Modularity and Maintainability**:

  - Organises logic into classes: `KeyStore` (JWKS retrieval), `JWT` (validation), `AWS` (STS integration), and `Exchanger` (orchestration) for clear separation of concerns.
  - Uses type hints and docstrings to support clarity and static analysis (e.g., `mypy`), aligning with private IDP deployment needs.
  - Supports extensibility for custom claims within the private IDP use case, though designed specifically for this scenario.

## Installation

### Prerequisites

- Python 3.10+
- Dependencies: `joserfc`, `boto3`, `urllib3`, `mypy-boto3-sts`

### Steps

1. Install the package:

   ```bash
   git clone https://github.com/your-repo/oidc-sts-bridge.git
   cd oidc-sts-bridge
   pip install .
   ```

2. Configure AWS credentials and OIDC IDP details (JWKS URI, issuer).

## Usage

### Example

```python
import boto3
from oidc_sts_bridge import Exchanger

# Initialise the exchanger with private OIDC and AWS configuration
exchanger = Exchanger(
    jwks_uri="https://oidc.private.local/.well-known/jwks.json",
    issuer="https://oidc.private.local",
    sts_client=boto3.client("sts"),
    additional_claims=["actor"] # Provider specific claims
)

# Exchange a JWT for AWS credentials
result = exchanger.exchange(
    jwt_token="your.jwt.token",  # Must include claim.actor=nsmithuk
    role_arn_to_assume="arn:aws:iam::123456789012:role/OidcBridgeRole",
    tags={"env": "prod"}
)

# Access the result
print(result["credentials"])  # AWS credentials
print(result["claims"]["passed"])  # Validated claims that were passed to STS
```

### Output

The `exchange` method returns a dictionary with:

- `header`: JWT header (e.g., `kid`, `alg`).
- `claims`: All claims and those passed to AWS (lowercased, filtered).
- `credentials`: AWS temporary credentials (`AccessKeyId`, `SecretAccessKey`, `SessionToken`, `Expiration`).

### Deployment Notes

Run `oidc-sts-bridge` in an environment (e.g., a private network server) with:

- Access to the private OIDC IDP’s JWKS endpoint (e.g., `https://oidc.private.local/.well-known/jwks.json`).
- Connectivity to AWS STS (e.g., via the internet or VPC endpoints).
- A `boto3` STS client configured with an IAM user or role that has permissions to assume the target IAM role (e.g., `arn:aws:iam::123456789012:role/OidcBridgeRole`).
- Note: Use the `SSL_CERT_FILE` environment variable to specify a `.pem` file for the trusted certificate for your local OIDC provider, if required.

Ensure the target IAM role has a Trust Policy allowing the STS client’s principal to assume the role and tag the session. Example Trust Policy for the role `OidcBridgeRole`:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowAssumeRole",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/oidc-bridge-user"
            },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {
                    "aws:RequestTag/claim.actor": "nsmithuk",
                    "sts:ExternalId": "https://oidc.private.local"
                }
            }
        },
        {
            "Sid": "AllowTagSession",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/oidc-bridge-user"
            },
            "Action": "sts:TagSession"
        }
    ]
}
```

This policy:

- Allows the IAM user `oidc-bridge-user` to assume the role if the session tag `claim.actor` is `nsmithuk` and the `ExternalId` matches the OIDC issuer (`https://oidc.private.local`).
- Permits session tagging, enabling `oidc-sts-bridge` to map JWT claims (e.g., `actor`) and custom tags (e.g., `env`) to AWS session tags.

## Testing

Unit tests cover all functionality, including edge cases and error handling, using dynamic mock data for robustness across dates.

### Setup

```bash
pip install pytest pytest-cov
```

### Run Tests

```bash
pytest tests/ -v --cov=oidc_sts_bridge
```

Tests cover:

- JWKS retrieval and caching (`KeyStore`).
- JWT validation, including core and custom claims (`JWT`).
- AWS role assumption and session tag mapping (`AWS`).
- Token exchange orchestration (`Exchanger`).
- Utility functions (`is_stringable`).

## Licence

This project is licensed under the MIT Licence. See the `LICENCE` file for details.

---

*Python written by humans. English written by AI.*

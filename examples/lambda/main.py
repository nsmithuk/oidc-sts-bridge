import logging
import os
from datetime import timedelta
from typing import Any, List, Optional

import boto3
from joserfc.errors import ExpiredTokenError

from oidc_sts_bridge import Exchanger

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)


# Initialise the Exchanger outside the handler for reuse across invocations
# This improves performance as the Exchanger is only initialised once when the Lambda container starts
def initialise_exchanger():
    """
    Initialise the Exchanger with environment variables.

    Returns:
        Exchanger: Initialised Exchanger instance or None if initialisation fails
    """
    try:
        # Extract required parameters from environment variables
        jwks_uri = os.environ.get("JWKS_URI")
        if not jwks_uri:
            logger.error("Missing required environment variable: JWKS_URI")
            return None

        issuer = os.environ.get("ISSUER")
        if not issuer:
            logger.error("Missing required environment variable: ISSUER")
            return None

        # Extract optional parameters from environment variables
        additional_claims_str = os.environ.get("ADDITIONAL_CLAIMS")
        additional_claims = additional_claims_str.split(",") if additional_claims_str else None

        jwks_cache_ttl_seconds_str = os.environ.get("JWKS_CACHE_TTL_SECONDS")
        jwks_cache_ttl = None
        if jwks_cache_ttl_seconds_str:
            try:
                jwks_cache_ttl_seconds = int(jwks_cache_ttl_seconds_str)
                jwks_cache_ttl = timedelta(seconds=jwks_cache_ttl_seconds)
            except ValueError:
                logger.error(
                    f"Invalid environment variable: JWKS_CACHE_TTL_SECONDS must be an integer, got: {jwks_cache_ttl_seconds_str}"
                )
                return None

        # Initialise the Exchanger
        return Exchanger(
            jwks_uri=jwks_uri,
            issuer=issuer,
            sts_client=boto3.client("sts"),
            additional_claims=additional_claims,
            jwks_cache_ttl=jwks_cache_ttl,
        )
    except Exception as e:
        logger.error(f"Error initializing Exchanger: {str(e)}", exc_info=True)
        return None


# Initialise the exchanger at module load time
EXCHANGER = initialise_exchanger()


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """
    AWS Lambda handler that uses oidc_sts_bridge to validate OIDC tokens and exchange them for AWS credentials.
    
    Args:
        event: Lambda event containing:
            - jwt_token: The OIDC JWT token to validate and exchange
            - role_arn: The AWS IAM role ARN to assume
            - tags: Optional dictionary of tags to include with the role assumption
        context: Lambda context object (not used)
        
    Environment Variables:
        - JWKS_URI: The JWKS URI for the OIDC provider
        - ISSUER: The expected issuer of the JWT
        - ADDITIONAL_CLAIMS: Optional comma-separated list of additional claims to validate
        - JWKS_CACHE_TTL_SECONDS: Optional cache TTL in seconds for JWKS caching
        
    Returns:
        Dictionary containing:
            - header: JWT header (e.g., kid, alg)
            - claims: All claims and those passed to AWS (lowercased, filtered)
            - credentials: AWS temporary credentials (AccessKeyId, SecretAccessKey, SessionToken, Expiration)
            
    Raises:
        Exception: If any validation or exchange step fails
        
    Example AWS CLI v2 invocation:
        ```
        aws lambda invoke \\
          --function-name oidc-sts-bridge \\
          --payload '{"jwt_token": "eyJ0eXAi...", "role_arn": "arn:aws:iam::123456789012:role/my-role", "tags": {"env": "prod"}}' \\
          --cli-binary-format raw-in-base64-out \\
          response.json
        
        # View the response
        cat response.json
        ```
    """
    try:
        # Check if Exchanger was initialised successfully
        if EXCHANGER is None:
            return {"error": "Lambda initialisation failed. Check environment variables and logs."}

        # Extract required parameters from the event
        jwt_token = event.get("jwt_token")
        role_arn = event.get("role_arn")
        tags = event.get("tags", {})

        # Validate required parameters from event
        if not jwt_token:
            return {"error": "Missing required parameter: jwt_token"}

        if not role_arn:
            return {"error": "Missing required parameter: role_arn"}

        # Exchange the JWT token for AWS credentials
        result = EXCHANGER.exchange(jwt_token=jwt_token, role_arn_to_assume=role_arn, tags=tags)

        # We'll always return the error key. Simplifies client logic.
        result.update({"Error": None})

        # Return the result directly (already JSON-serializable)
        return result

    except ExpiredTokenError as e:
        logger.warning(f"Issue exchanging token: {str(e)}")
        return {"Error": str(e)}

    except Exception as e:
        logger.error(f"Error in lambda_handler: {str(e)}", exc_info=True)
        return {"Error": str(e)}

from oidc_sts_bridge.main import AWS

from .test_mocks import *


def test_aws_does_role_arn_look_sensible():
    """Test AWS role ARN validation."""
    assert AWS.does_role_arn_look_sensible("arn:aws:iam::123456789012:role/MyRole")
    assert AWS.does_role_arn_look_sensible("arn:aws:iam::123456789012:role/path/to/MyRole")
    assert not AWS.does_role_arn_look_sensible("arn:aws:iam::123456789012:role/Invalid#Role")
    assert not AWS.does_role_arn_look_sensible(
        "arn:aws:iam::12345678901:role/MyRole"
    )  # Invalid account ID
    assert not AWS.does_role_arn_look_sensible("")


def test_aws_map_validate_merge_claims_and_tags():
    """Test AWS claim and tag validation and merging."""
    claims = {"sub": "user123", "custom": "value"}
    tags = {"tag1": "val1", "tag2": "val2"}
    result = AWS.map_validate_merge_claims_and_tags(claims, tags)
    assert result == {
        "claim.sub": "user123",
        "claim.custom": "value",
        "tag1": "val1",
        "tag2": "val2",
    }


def test_aws_map_validate_merge_claims_and_tags_too_many():
    """Test AWS rejecting too many claims and tags."""
    claims = {f"claim{i}": "value" for i in range(40)}
    tags = {f"tag{i}": "value" for i in range(20)}
    with pytest.raises(ValueError, match="STS supports maximum of 50 session tags"):
        AWS.map_validate_merge_claims_and_tags(claims, tags)


def test_aws_map_validate_merge_claims_and_tags_invalid_prefix():
    """Test AWS rejecting claim. prefixes in keys."""
    claims = {"claim.sub": "value"}
    tags = {"claim.tag": "value"}
    with pytest.raises(
        ValueError, match="Claim and tag names that are prefixed with 'claim.' are not allowed"
    ):
        AWS.map_validate_merge_claims_and_tags(claims, {})
    with pytest.raises(
        ValueError, match="Claim and tag names that are prefixed with 'claim.' are not allowed"
    ):
        AWS.map_validate_merge_claims_and_tags({}, tags)


def test_aws_map_validate_merge_claims_and_tags_non_stringable():
    """Test AWS rejecting non-stringable values."""
    claims = {"sub": {"key": "value"}}  # Non-stringable
    with pytest.raises(
        ValueError, match="Claim and tag values must be strings, or be castable to a string"
    ):
        AWS.map_validate_merge_claims_and_tags(claims, {})


def test_aws_map_validate_merge_claims_and_tags_key_too_long():
    """Test AWS rejecting keys exceeding 128 characters."""
    long_key = "x" * 129
    claims = {long_key: "value"}
    with pytest.raises(ValueError, match="Claim and tag names can’t exceed 128 characters"):
        AWS.map_validate_merge_claims_and_tags(claims, {})


def test_aws_map_validate_merge_claims_and_tags_value_too_long():
    """Test AWS rejecting values exceeding 256 characters."""
    long_value = "x" * 257
    claims = {"sub": long_value}
    with pytest.raises(ValueError, match="Claim and tag values can’t exceed 256 characters"):
        AWS.map_validate_merge_claims_and_tags(claims, {})


def test_aws_assume_role_success(mock_sts_client):
    """Test AWS role assumption success."""
    aws = AWS(mock_sts_client)
    role_arn = "arn:aws:iam::123456789012:role/MyRole"
    claims = {"iss": "test-issuer", "jti": "unique-id", "sub": "user123"}
    tags = {"tag1": "val1"}
    mock_sts_client.responses[role_arn] = {"Credentials": MOCK_CREDENTIALS}
    creds = aws.assume_role(role_arn, claims, tags)
    assert creds == MOCK_CREDENTIALS
    assert len(mock_sts_client.calls) == 1
    call = mock_sts_client.calls[0]
    assert call["RoleArn"] == role_arn
    assert call["RoleSessionName"] == "unique-id"
    assert call["ExternalId"] == "test-issuer"
    assert call["Tags"] == [
        {"Key": "claim.iss", "Value": "test-issuer"},
        {"Key": "claim.jti", "Value": "unique-id"},
        {"Key": "claim.sub", "Value": "user123"},
        {"Key": "tag1", "Value": "val1"},
    ]


def test_aws_assume_role_failure(mock_sts_client):
    """Test AWS role assumption failure."""
    aws = AWS(mock_sts_client)
    role_arn = "arn:aws:iam::123456789012:role/MyRole"
    claims = {"iss": "test-issuer", "jti": "unique-id"}
    tags = {}
    with pytest.raises(RuntimeError, match="Failed to assume role"):
        aws.assume_role(role_arn, claims, tags)

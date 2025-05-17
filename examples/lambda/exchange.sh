#!/usr/bin/env bash

set_aws_creds() {
  local payload="$1"
  local response

  response=$(aws lambda invoke \
    --function-name oidc-sts-bridge \
    --payload "$payload" \
    --cli-binary-format raw-in-base64-out \
    /dev/stdout 2>/dev/null | jq -r '. | select(.Error != null or .Credentials != null) // empty')

  if [ -z "$response" ]; then
    echo "Error: No valid response from Lambda"
    return 1
  fi

  if echo "$response" | jq -e '.Credentials' >/dev/null; then
    export AWS_ACCESS_KEY_ID=$(echo "$response" | jq -r '.Credentials.AccessKeyId')
    export AWS_SECRET_ACCESS_KEY=$(echo "$response" | jq -r '.Credentials.SecretAccessKey')
    export AWS_SESSION_TOKEN=$(echo "$response" | jq -r '.Credentials.SessionToken')
    echo "Credentials Set"
  else
    local error_message
    error_message=$(echo "$response" | jq -r '.Error // "Unknown error"')
    echo "Error: $error_message"
    return 1
  fi
}


JWT_TOKEN="eyJ0eX..."
ROLE_ARN="arn:aws:iam::123456789123:role/oidc-access-via-lambda"
TAGS='{"env":"dev"}'

# We'll use jq to build the JSON payload - it deals with escaping.
PAYLOAD=$(jq -c --null-input \
      --arg jwt_token "$JWT_TOKEN" \
      --arg role_arn "$ROLE_ARN" \
      --argjson tags "$TAGS" \
      '{jwt_token: $jwt_token, role_arn: $role_arn, tags: $tags}')


set_aws_creds "$PAYLOAD"

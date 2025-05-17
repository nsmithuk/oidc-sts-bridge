# Example: Credential Exchange via AWS Lambda

This example demonstrates a simple approach to exchanging credentials using an AWS Lambda function.

* `main.py` – An example AWS Lambda handler that performs credential exchange logic based on a provided JWT token and role ARN.
* `exchange.sh` – A sample Bash script showing how the Lambda function could be invoked and its output used.

These files are for guidance only and are intended to illustrate a lightweight pattern for delegated credential retrieval, such as in short-lived access scenarios.

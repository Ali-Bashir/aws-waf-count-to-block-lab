# Echo target behind the ALB. Returns 200 "ok" for any request, so any 403
# you see in the lab comes from AWS WAF, not from the application.


def handler(event, context):
    return {
        "statusCode": 200,
        "statusDescription": "200 OK",
        "isBase64Encoded": False,
        "headers": {"Content-Type": "text/plain"},
        "body": "ok",
    }

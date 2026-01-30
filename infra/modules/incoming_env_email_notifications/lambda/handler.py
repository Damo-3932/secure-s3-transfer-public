import os
import urllib.parse
import boto3


def lambda_handler(event, context):
    suffix = os.environ.get("NOTIFICATION_SUFFIX", ".env")
    message = os.environ.get(
        "NOTIFICATION_MESSAGE",
        "You have a new file to download from the bucket.",
    )
    topic_arn = os.environ.get("SNS_TOPIC_ARN", "")

    if not topic_arn:
        raise ValueError("SNS_TOPIC_ARN is not set")

    keys = []
    for record in event.get("Records", []):
        key = record.get("s3", {}).get("object", {}).get("key")
        if not key:
            continue
        key = urllib.parse.unquote_plus(key)
        if key.endswith(suffix):
            keys.append(key)

    if not keys:
        return {"status": "no-match"}

    sns = boto3.client("sns")
    sns.publish(
        TopicArn=topic_arn,
        Message=message,
        Subject="Secure S3 Transfer"
    )

    return {"status": "sent", "matched": keys}

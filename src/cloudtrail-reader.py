#!/bin/python
import gzip
import json
import os

import boto3
import slackweb

from formatters import *


botosession = boto3.session.Session(
    aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
    aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    region_name=os.environ["AWS_REGION"]
)

s3 = botosession.resource("s3")
sqs = botosession.resource("sqs")
queue = sqs.get_queue_by_name(QueueName=os.environ['SQS_QUEUE'])
classes = globals()
slack = slackweb.Slack(url=os.environ['SLACK_URL'])
inventory = Inventory(botosession)

while True:
    for message in queue.receive_messages():
        msg = json.loads(message.body)
        msg = json.loads(msg["Message"])
        for key in msg["s3ObjectKey"]:
            s3.Bucket(msg["s3Bucket"]).download_file(key, "/tmp/data.json.gz")
        try:
            gz = gzip.GzipFile('/tmp/data.json.gz')
            data = json.loads(gz.read())
        except Exception as e:
            print("Failed to read file ")
            continue
        for record in data["Records"]:
            name = record["eventName"]
            if name.startswith(('List', 'Describe', 'Get', 'Lookup')):
                continue
            if name+"Formatter" in classes:
                clazz = classes[name+"Formatter"]
                try:
                    formatter = clazz(record, inventory)
                    slackmsg = formatter.format()
                except Exception as e:
                    print(e)
                    pp.pprint(record)
                    continue
                if slackmsg:
                    pass
                    pp.pprint(slackmsg)
                    slack.notify(attachments=[slackmsg])
            else:
                print("need formatter for "+name)
                pp.pprint(record)
        message.delete()

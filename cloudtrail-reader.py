import gzip
import json
import boto3

from steps import *



s3 = boto3.resource("s3")
sqs = boto3.resource("sqs")
queue = sqs.get_queue_by_name(QueueName="ops-announce")
classes = globals()
slack = slackweb.Slack(url="https://hooks.slack.com/services/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")

while True:
    for message in queue.receive_messages():
        msg = json.loads(message.body)
        msg = json.loads(msg["Message"])
        for key in msg["s3ObjectKey"]:
            s3.Bucket(msg["s3Bucket"]).download_file(key, "/tmp/data.json.gz")
        try:
            gz = gzip.GzipFile('/tmp/data.json.gz')
            data = json.loads(gz.read())
            print(data)
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
                    formatter = clazz(record)
                    slackmsg = formatter.format()
                except Exception as e:
                    print(e)
                    pp.pprint(record)
                    raise
                    continue
                if slackmsg:
                    pass
                    pp.pprint(slackmsg)
                    slack.notify(attachments=[slackmsg])
            else:
                print("need formatter for "+name)
                pp.pprint(record)
        message.delete()

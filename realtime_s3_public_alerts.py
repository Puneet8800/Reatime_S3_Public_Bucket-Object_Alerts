import json
import boto3
import os
from botocore.vendored import requests



def lambda_handler(event, context):
    if event["detail"]['eventSource'] == 's3.amazonaws.com' and 'requestParameters' in event["detail"]:
        event_name = event["detail"]['eventName']
        if event_name == 'CreateBucket' or event_name == 'PutObject':
            creation(event, event_name)
        elif event_name == 'PutBucketAcl' or event_name == 'PutObjectAcl':
            changed(event, event_name)
        elif event_name == "PutBucketPolicy":
            policy_creation(event,event_name)

# below Policy function check wheather any s3 bucket policy contains s3* in it.
def policy_creation(event,event_name):
    print(event)
    if 'bucketPolicy' in event["detail"]["requestParameters"]:
        policy = event["detail"]["requestParameters"]["bucketPolicy"]["Statement"]
        if not isinstance(policy, list):
            policy = [policy]
        print(policy)
        for i in policy:
            if i["Effect"] == "Allow":
                if i["Principal"] == "*" or i["Principal"]["AWS"] == "*":
                    publish_policy_alert(event, event_name)

# After detecting the Alert it will realtime alert us about the policy
def publish_policy_alert(event, event_name):
    user_name = event["detail"]['userIdentity']['principalId']
    agent = user_agent(event)
    bucket_name = event["detail"]['requestParameters']['bucketName']
    for i in event["detail"]["requestParameters"]["bucketPolicy"]["Statement"]:
        per = i["Action"]

    template = {}
    template['attachments'] = [{}]
    template['attachments'][0]['fallback'] = 'unable to display this message !'
    template['attachments'][0]['color'] = '#F75D59'
    template['attachments'][0]['pretext'] = "List of Public S3 bucket "
    template['attachments'][0]['title'] = "List of Public S3 bucket to review"
    template['attachments'][0]['fields'] = [{"title": "Public S3 Bucket "}]
    template['attachments'][0]['fields'].append({"title": "Username"})
    template['attachments'][0]['fields'].append({"value": user_name})
    template['attachments'][0]['fields'].append({"title": "Useragent"})
    template['attachments'][0]['fields'].append({"value": agent})
    template['attachments'][0]['fields'].append({"title": "Public Bucket Name"})
    template['attachments'][0]['fields'].append({"value": bucket_name})
    template['attachments'][0]['fields'].append({"title": "Policy Permission"})
    template['attachments'][0]['fields'].append({"value": per})

    json_template = json.dumps(template)
    print(json_template)
    requests.post(url='Slack incoming webhook url', data=json_template)
    


def creation(event, event_name):
    public_read = False
    public_write = False

    if 'x-amz-acl' in event["detail"]['requestParameters']:
        acl_headers = event["detail"]['requestParameters']['x-amz-acl']
        if not isinstance(acl_headers, list):
            acl_headers = [acl_headers]

        for acl_header in acl_headers:
            if acl_header == 'public-read' or acl_header == 'public-read-write':
                public_read = True
            if acl_header == 'public-read-write':
                public_write = True

    if 'accessControlList' in event["detail"]['requestParameters']:
        if 'x-amz-grant-read' in event["detail"]['requestParameters']['accessControlList'] \
                and '/global/AllUsers' in event["detail"]['requestParameters']['accessControlList']['x-amz-grant-read']:
            public_read = True
        if 'x-amz-grant-read-acp' in event["detail"]['requestParameters']['accessControlList'] \
                and '/global/AllUsers' in event["detail"]['requestParameters']['accessControlList']['x-amz-grant-read-acp']:
            public_read = True
        if 'x-amz-grant-write' in event["detail"]['requestParameters']['accessControlList'] \
                and '/global/AllUsers' in event["detail"]['requestParameters']['accessControlList']['x-amz-grant-write']:
            public_write = True
        if 'x-amz-grant-write-acp' in event["detail"]['requestParameters']['accessControlList'] \
                and '/global/AllUsers' in event["detail"]['requestParameters']['accessControlList']['x-amz-grant-write-acp']:
            public_write = True

    if public_read == True or public_write == True:
        publish_alert(event, event_name, public_write, public_read)


def changed(event, event_name):
    public_read = False
    public_write = False

    if 'AccessControlPolicy' in event["detail"]['requestParameters']:
        grant_list = event["detail"]['requestParameters']['AccessControlPolicy']['AccessControlList']['Grant']
        if not isinstance(grant_list, list):
            grant_list = [grant_list]

        for grantee in grant_list:
            if 'Grantee' in grantee:
                if 'URI' in grantee['Grantee'] and '/global/AllUsers' in grantee['Grantee']['URI']:
                    if grantee['Permission'] == 'READ' or grantee['Permission'] == 'READ_ACP':
                        public_read = True
                    elif grantee['Permission'] == 'WRITE' or grantee['Permission'] == 'WRITE_ACP':
                        public_write = True
                    elif grantee['Permission'] == 'FULL_CONTROL':
                        public_read= True
                        public_write = True

    if public_read == True or public_write == True:
        publish_alert(event, event_name, public_write, public_read)
    elif public_read == True and public_write == True:
        publish_alert(event, event_name, public_write, public_read)
        


def publish_alert(event, event_name, public_write, public_read):
    user_name = event["detail"]['userIdentity']['principalId']
    agent = user_agent(event)
    bucket_name = event["detail"]['requestParameters']['bucketName']
    object_arn = get_object_arn(event)
    template = {}
    template['attachments'] = [{}]
    template['attachments'][0]['fallback'] = 'unable to display this message !'
    template['attachments'][0]['color'] = '#F70D1A'
    template['attachments'][0]['pretext'] = "List of Public S3 bucket"
    template['attachments'][0]['title'] = "List of Public S3 bucket to review"
    template['attachments'][0]['fields'] = [{"title": "Public S3 Bucket "}]
    template['attachments'][0]['fields'].append({"title": "Username"})
    template['attachments'][0]['fields'].append({"value": user_name})
    template['attachments'][0]['fields'].append({"title": "Useragent"})
    template['attachments'][0]['fields'].append({"value": agent})
    template['attachments'][0]['fields'].append({"title": "Bucket Name"})
    template['attachments'][0]['fields'].append({"value": bucket_name})
    template['attachments'][0]['fields'].append({"title": "Object ARN"})
    template['attachments'][0]['fields'].append({"value": object_arn})
    template['attachments'][0]['fields'].append({"title": "Resource Access"})
    template['attachments'][0]['fields'].append({"value": get_resource_access(event_name, bucket_name, object_arn)})
    template['attachments'][0]['fields'].append({"title": "Access Level"})
    template['attachments'][0]['fields'].append({"value": get_public_access(public_write, public_read)})

    json_template = json.dumps(template)
    requests.post(url='enter incoming webhook url of slack', data=json_template)
    



def get_object_arn(event):
    if 'resources' in event["detail"]:
        for resource in event["detail"]['resources']:
            if resource['type'] == 'AWS::S3::Object':
                return resource['ARN']
    return None


def user_agent(event):
    if event["detail"]['userAgent'] == 'signin.amazonaws.com' or event["detail"]['userAgent'] == 'console.amazonaws.com':
        return 'Console'
    elif event["detail"]['userAgent'] == 'lambda.amazonaws.com':
        return 'Lambda'
    else:
        return 'API'


def get_public_access(public_write, public_read):
    messages = []
    if public_read:
        messages.append('READ')
    if public_write:
            messages.append('WRITE')
    return(' , '.join(messages))


def get_resource_access(event_name, bucket_name, object_arn):
    messages = []
    if event_name == 'CreateBucket' or event_name == 'PutObject':
        messages.append('created')
    else:
        messages.append('changed')

    if object_arn is not None:
        messages.append(object_arn)
        messages.append('at bucket')
        messages.append(bucket_name)
    else:
        messages.append('bucket')
        messages.append(bucket_name)

    return(' '.join(messages))

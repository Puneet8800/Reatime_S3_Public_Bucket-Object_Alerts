## Reatime S3 Public Bucket/Object Alerts on Slack
### Purpose
 The purpose of this automation is to trigger an alert whenever a public access policy is applied to an object/bucket in an AWS account.

### Deployment Options
AWS Lambda

### Prerequisites
1. Cloudwatch Events.
2. Cloudtrail events( logging should be enabled).
3. S3 object logging should be enabled.

### Configuration Steps
1. Enable s3 object logging on all buckets.
2. Configure cloudtrail on the account with logging enabled.
3. Configure cloudwatch event rule using the json mention below.
4. Lambda deployement.
5. Enable lambda trigger for the cloudwatch event rule.



### References
1. Enable S3 Object Logging: https://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-cloudtrail-events.html
2. Cloudtrail Multi Region Configuration: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html
3. Cloudwatch Event Rule: https://github.com/Puneet8800/Cloud_Security_Automations/blob/master/s3_public_access_alerting/Cloudwatch_eventrule.json
4. Creating Cloudwatch Rule using JSON: https://aws.amazon.com/premiumsupport/knowledge-center/cloudwatch-create-custom-event-pattern/
5. Enabling Cloudwatch trigger on Lambda: https://docs.aws.amazon.com/lambda/latest/dg/services-cloudwatchevents.html

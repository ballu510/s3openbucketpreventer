import boto3
from botocore.exceptions import ClientError
import json
import os

def checkBucketAcl(bucketAcl):
    openAcl = False
    for key, value in bucketAcl.items():
        if(key == 'Grants'):
            for i in range(0, len(value)):
                if((value[i]['Grantee']['Type'] == 'Group') and (value[i]['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers') and (value[i]['Permission'] is not None)):
                    openAcl = True
    return openAcl

def lambda_handler(event, context):
    # instantiate Amazon S3 client
    s3 = boto3.client('s3')
    #print('event is: ', event)
    resource = list(event['detail']['requestParameters']['evaluations'])[0]
    bucketName = resource['complianceResourceId']
    if ((event['detail']['additionalEventData']['managedRuleIdentifier'] == 'S3_BUCKET_PUBLIC_READ_PROHIBITED')or(event['detail']['additionalEventData']['managedRuleIdentifier'] == 'S3_BUCKET_PUBLIC_write_PROHIBITED')):
        if ((resource['complianceResourceType'] == 'AWS::S3::Bucket') and (resource['complianceType'] == 'NON_COMPLIANT')):

            # check for offending Amazon S3 bucket ACL by getting the bucket ACL for the offending bucket
            bucketAcl = s3.get_bucket_acl(Bucket=bucketName)
            if(checkBucketAcl(bucketAcl)):
                s3.put_bucket_acl(Bucket=bucketName, ACL='private')

            # check if a policy exists for the bucket; if so, notify that it may be a concern
            try:
                bucketPolicy = s3.get_bucket_policy(Bucket=bucketName)
                # notify that the bucket policy may need to be reviewed due to security concerns
                sns = boto3.client('sns')
                subject = "Potential compliance violation in " + bucketName + " bucket policy"
                message = "Potential bucket policy compliance violation. Please review: " + json.dumps(bucketPolicy['Policy'])
                # send SNS message with warning and bucket policy
                response = sns.publish(
                    TopicArn = os.environ['TOPIC_ARN'],
                    Subject = subject,
                    Message = message
                )
            except ClientError as e:
                # error caught due to no bucket policy
                return 0
                # print(e)
                # print("No bucket policy found; no alert sent.")
    return 0  # done
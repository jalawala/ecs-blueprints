
# Import modules
import boto3
import os
from pprint import pprint
import logging
from botocore.exceptions import ClientError
from botocore.config import Config
from datetime import datetime
from datetime import timedelta
from datetime import timezone

# Create logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

# Define config
config=Config(
   retries = {
      'max_attempts': 10,
      'mode': 'standard'
   }
)

# Define session and resources
session=boto3.Session()
# sqs:session.resource('sqs', config=config)
cloudwatch=session.client('cloudwatch', config=config)
appautoscaling=boto3.client('application-autoscaling', config=config)

# Read environment variables
ecs_sqs_app_scaling_policy_name=os.environ['ecs_sqs_app_scaling_policy_name']
desiredLatency=int(os.environ['desiredLatency'])
defaultMsgProcDuration=int(os.environ['defaultMsgProcDuration'])

queueName=os.environ['ProcessingQueueName']
appMetricName = os.environ['appMetricName']
bpiMetricName=os.environ['bpiMetricName']
metricType=os.environ['metricType']
metricNamespace=os.environ['metricNamespace']


def publishMetricValue(metricValue):

    response = cloudwatch.put_metric_data(
        Namespace = metricNamespace,
        MetricData = [
            {
                'MetricName': bpiMetricName,
                'Value': metricValue,
                'Dimensions': [
                    {
                        'Name': 'Type',
                        'Value': metricType
                    },
                    {
                        'Name': 'QueueName',
                        'Value': queueName
                    }                    
                ],
                'StorageResolution': 1
            }
        ]
    )

def getMetricValue(metricNamespace, metricName):

    # Define query
    query={
        'Id': 'query_123',
        'MetricStat': {
            'Metric': {
                'Namespace': metricNamespace,
                'MetricName': appMetricName,
                    'Dimensions': [
                        {
                            'Name': 'Type',
                            'Value': metricType
                        },
                        {
                            'Name': 'QueueName',
                            'Value': queueName
                        },                        
                    ]                
            },
            'Period': 1,
            'Stat': 'Average',
        }
    }

    response = cloudwatch.get_metric_data(
        MetricDataQueries=[query],
        StartTime=datetime.now(timezone.utc) - timedelta(seconds=86400),
        EndTime=datetime.now(timezone.utc),
    )
    
    #print(response)
    
    if not response.get('MetricDataResults')[0].get('Values'): 
        msgProcessingDuration=defaultMsgProcDuration
    else: 
        values = response.get('MetricDataResults')[0].get('Values')
        total = sum(values)
        count = len(values)
        msgProcessingDuration =  total / count
        print("count={} total={} msgProcessingDuration={}".format(count, total, msgProcessingDuration))
        msgProcessingDuration=response.get('MetricDataResults')[0].get('Values')[0]
        
    # Return 
    return msgProcessingDuration
    


def lambda_handler(event, context):

    # Get cloudwatch metric for msg processing duration
    msgProcessingDuration=getMetricValue(metricNamespace, appMetricName)
    print('Most recent message processing duration is {}'.format(msgProcessingDuration))

    # Calculate new target BPI (assuming latency of 5mins)
    newTargetBPI =int(desiredLatency / msgProcessingDuration)
    print('New Target BPI is {}'.format(newTargetBPI))

    # Get scaling policy of ASG
    
    response =appautoscaling.describe_scaling_policies(PolicyNames=[ecs_sqs_app_scaling_policy_name], ServiceNamespace='ecs')
    policies =response.get('ScalingPolicies')  
    #pprint(policies)
    policy=policies[0]
    print(policy)

    # Get target tracking config and update target value
    TargetTrackingConfig=policy.get('TargetTrackingScalingPolicyConfiguration')
    #print(TargetTrackingConfig)
    TargetTrackingConfig['TargetValue'] = newTargetBPI
    TargetTrackingConfig['CustomizedMetricSpecification']['MetricName'] = bpiMetricName
    TargetTrackingConfig['CustomizedMetricSpecification']['Namespace'] = metricNamespace
    TargetTrackingConfig['CustomizedMetricSpecification']['Statistic'] = 'Average'

    # Update scaling policy of ASG
    appautoscaling.put_scaling_policy(
        ServiceNamespace='ecs', 
        ResourceId=policy.get('ResourceId'),
        ScalableDimension=policy.get('ScalableDimension'),
        PolicyName=policy.get('PolicyName'),
        PolicyType=policy.get('PolicyType'),
        TargetTrackingScalingPolicyConfiguration=TargetTrackingConfig        
    )    
    print('Scaling policy of ECS has been successfully updated!')

    # Publish new target BPI
    publishMetricValue(newTargetBPI)


# if __name__=="__main__":

#     logger.info('Calling lambda_handler...')
#     lambda_handler("", "")
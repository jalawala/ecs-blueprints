
# Import modules
import boto3
import os
from pprint import pprint
import logging
from botocore.exceptions import ClientError
from botocore.config import Config

# Create logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

# Define config
config = Config(
   retries = {
      'max_attempts': 10,
      'mode': 'standard'
   }
)

# Define session and resources
session = boto3.Session()
sqs = session.resource('sqs', config=config)
cloudwatch = session.client('cloudwatch', config=config)
autoscaling = session.client('autoscaling', config=config)

# Read  environment variables
queueName = os.environ['queueName']
ecsClusterName = os.environ['ecsClusterName']
ecsServiceName = os.environ['ecsServiceName']



def publishMetricValue(namespace, metricName, value, metricType):

    response = cloudwatch.put_metric_data(
        Namespace = namespace,
        MetricData = [
            {
                'MetricName': metricName,
                'Value': value,
                'Dimensions': [
                    {
                        'Name': 'Type',
                        'Value': metricType
                    }
                ],
                'StorageResolution': 1
            }
        ]
    )

def getNumberOfTasks(ecsClusterName, ecsServiceName): 
    
    # Describe ASG
    ecs = boto3.client('ecs')
    response = ecs.describe_services(cluster=ecsClusterName, services=[ecsServiceName])
    
    service_info = response['services'][0]
    
    # Get the number of tasks running
    running_task_count = service_info['runningCount']
    
    return running_task_count



def lambda_handler(event, context):


    # Get number of messages in queue
    processingQueue = sqs.get_queue_by_name(QueueName=queueName)
    nMessagesVisible = int(processingQueue.attributes.get('ApproximateNumberOfMessages'))
    print('There is a total of {} messages in the processing queue(s)'.format(nMessagesVisible))

    # Get number of instances in ASG
    nTasks = getNumberOfTasks(ecsClusterName, ecsServiceName)
    print('Total nTasks in ECS Service {} : {}'.format(ecsServiceName, nTasks))

    # Publish metric data to cloudwatch
    BPI = nMessagesVisible / nTasks
    publishMetricValue('ECS-SQS-Metrics', 'BPI', BPI, 'Single Queue')
    print('A Backlog per instance (BPI) of {} was published to CloudWatch'.format(BPI))


if __name__=="__main__":

    logger.info('Calling lambda_handler...')
    lambda_handler("", "")
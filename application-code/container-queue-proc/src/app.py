
# Import modules
import boto3
import os
import json
import time
from pprint import pprint
import logging
from botocore.exceptions import ClientError
from botocore.config import Config
import datetime

# Create logger
#logging.basicConfig(filename='consumer.log', level=logging.INFO)
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

queueName = os.environ['ProcessingQueueName']
appMetricName = os.environ['appMetricName']
metricType = os.environ['metricType']
metricNamespace = os.environ['metricNamespace']


def publishMetricValue(metricValue):

    now = datetime.datetime.now()
    logger.info('Time {} publishMetricValue with metricNamespace {} appMetricName {} metricValue {} metricType {} queueName {}'.format(now, metricNamespace, appMetricName, metricValue,metricType, queueName))
    response = cloudwatch.put_metric_data(
        Namespace = metricNamespace,
        MetricData = [
            {
                'MetricName': appMetricName,
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

if __name__=="__main__":

    # Initialize variables
    logger.info('Environment queueName {} appMetricName {} metricType {} metricNamespace {}'.format(queueName, appMetricName, metricType, metricNamespace))
    logger.info('Calling get_queue_by_name....')
    queue = sqs.get_queue_by_name(QueueName=queueName)
    batchSize = 1
    queueWaitTime= 5

    # start continuous loop
    logger.info('Starting queue consumer process...')
    while True: 

        try:
            
            # Read messages from queue
            logger.info('Polling messages from the   processing queue')
            messages = queue.receive_messages(AttributeNames=['All'], MaxNumberOfMessages=batchSize, WaitTimeSeconds=queueWaitTime) 
            if not messages: continue
            logger.info('-- Received {} messages'.format(len(messages)))
            
            # Process messages
            for message in messages:
                
                # Process message
                logger.info('---- Processing message {}...'.format(message.message_id))
                messageBody = json.loads(message.body)
                processingDuration = messageBody.get('duration')
                time.sleep(processingDuration)
                #time.sleep(2)
                
                # Delete the message
                message.delete()
                logger.info('---- Message processed and deleted')
                
                # Report message duration to cloudwatch
                publishMetricValue(processingDuration)

        except ClientError as error: 
            logger.error('SQS Service Exception - Code: {}, Message: {}'.format(error.response['Error']['Code'],error.response['Error']['Message']))
            continue   

        except Exception as e: 
            logger.error('Unexpected error - {}'.format(e))



#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from health_client import HealthClient, ActiveRegionHasChangedError
import datetime
import logging
import boto3

logging.basicConfig(level=logging.INFO)

def event_details(event, session):
    health_client = session.client('health')
    event_details_response = health_client.describe_event_details(eventArns=[event['arn']])
    for event_details in event_details_response['successfulSet']:
        logging.info('Details: %s, description: %s', event_details['event'], event_details['eventDescription'])

def describe_events(session):
    health_client = session.client('health')
    events_paginator = health_client.get_paginator('describe_events')
    events_pages = events_paginator.paginate(filter={
        'startTimes': [
            {
                'from': datetime.datetime.now() - datetime.timedelta(days=7)
            }
        ],
        'eventStatusCodes': ['upcoming']
    })

    number_of_matching_events = 0
    for events_page in events_pages:
        for event in events_page['events']:
            number_of_matching_events += 1
            event_details(event, session)

    if number_of_matching_events == 0:
        logging.info('There are no AWS Health events that match the given filters')

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
        RoleSessionName='HealthDemoSession'
    )
    return response['Credentials']

def run_for_account(account_id, role_name):
    credentials = assume_role(account_id, role_name)
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    restart_workflow = True
    while restart_workflow:
        try:
            describe_events(session)
            restart_workflow = False
        except ActiveRegionHasChangedError as are:
            logging.info("The AWS Health API active region has changed. Restarting the workflow using the new active region!, %s", are)

if __name__ == "__main__":
    accounts = [
        {'account_id': '211125535116', 'role_name': 'cross-account-war-role'},
        {'account_id': '590183713919', 'role_name': 'cross-account-war-role'}
        
    ]

    for account in accounts:
        run_for_account(account['account_id'], account['role_name'])

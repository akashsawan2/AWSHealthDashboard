#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from health_client import HealthClient, ActiveRegionHasChangedError
import datetime
import logging
import boto3
import csv
import os

logging.basicConfig(level=logging.INFO)

def event_details(event, session, csv_writer, account_id):
    health_client = session.client('health')
    event_details_response = health_client.describe_event_details(eventArns=[event['arn']])
    for event_details in event_details_response['successfulSet']:
        event_info = {
            "AccountID": account_id,
            "ARN": event_details['event']['arn'],
            "Service": event_details['event']['service'],
            "EventTypeCode": event_details['event']['eventTypeCode'],
            "EventTypeCategory": event_details['event']['eventTypeCategory'],
            "Region": event_details['event']['region'],
            "StartTime": event_details['event']['startTime'].isoformat(),
            "LastUpdatedTime": event_details['event']['lastUpdatedTime'].isoformat(),
            "StatusCode": event_details['event']['statusCode'],
            "EventScopeCode": event_details['event']['eventScopeCode'],
            "Description": event_details['eventDescription']['latestDescription'],
            "AffectedEntities": ""
        }

        affected_entities = get_affected_entities(event, session)
        event_info["AffectedEntities"] = ", ".join(affected_entities)
        
        csv_writer.writerow(event_info)

def get_affected_entities(event, session):
    health_client = session.client('health')
    events_paginator_affectedResource = health_client.get_paginator('describe_affected_entities')
    events_pages_affected = events_paginator_affectedResource.paginate(filter={
        'eventArns': [event['arn']],
        'lastUpdatedTimes': [
            {
                'from': datetime.datetime.now() - datetime.timedelta(days=180)
            }
        ]
    })

    affected_entities = []
    for page in events_pages_affected:
        for entity in page['entities']:
            affected_entities.append(entity['entityValue'])
    
    return affected_entities

def describe_events(session, csv_writer, account_id):
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
            event_details(event, session, csv_writer, account_id)

    if number_of_matching_events == 0:
        logging.info('There are no AWS Health events that match the given filters for account %s', account_id)

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    response = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
        RoleSessionName='HealthDemoSession'
    )
    return response['Credentials']

def run_for_account(account_id, role_name, csv_writer):
    credentials = assume_role(account_id, role_name)
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    restart_workflow = True
    while restart_workflow:
        try:
            describe_events(session, csv_writer, account_id)
            restart_workflow = False
        except ActiveRegionHasChangedError as are:
            logging.info("The AWS Health API active region has changed. Restarting the workflow using the new active region!, %s", are)

if __name__ == "__main__":
    accounts = [
        {'account_id': '998604591968', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '323529618611', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '350027074327', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '914066148492', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '998604591968', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '578845538067', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '327798492615', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '471726860506', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '338897596704', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '078331826294', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '260126818574', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '143948849258', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '470064715030', 'role_name': 'TTN_ReadOnly'},
        {'account_id': '924456361876', 'role_name': 'TTN_ReadOnly'}
    ]

    output_file = 'aws_health_events.csv'

    if os.path.isfile(output_file):
        os.remove(output_file)

    with open(output_file, mode='w', newline='') as csv_file:
        fieldnames = ["AccountID", "ARN", "Service", "EventTypeCode", "EventTypeCategory", "Region", "StartTime", "LastUpdatedTime", "StatusCode", "EventScopeCode", "Description", "AffectedEntities"]
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        
        csv_writer.writeheader()

        for account in accounts:
            run_for_account(account['account_id'], account['role_name'], csv_writer)

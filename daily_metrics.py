#!/usr/bin/env python3

import argparse
import http.client
import json
import logging
import os
import requests
import sys
import time

from datadog import initialize, api
from dotenv import load_dotenv


API_TOKEN_ENVVAR = 'METERIAN_API_TOKEN'

class HelpingParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.stderr.write('\n')
        sys.exit(-1)


def _logHttpRequests():
    http.client.HTTPConnection.debuglevel = 1

    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

    logging.debug('Full debug log for HTTP requests enabled')

def _parseArgs():
    parser = HelpingParser()

    # all other arguments
    parser.add_argument(
        '-p',
        '--prefix',
        default='.meterian',
        metavar='PREFIX',
        help='The prefix to use for the metrics (default: "meterian.")'
    )

    parser.add_argument(
        '--meterian-token',
        metavar='TOKEN',
        default=os.getenv('METERIAN_API_TOKEN', None),
        help=(
            'Allows you to specify the API token to use directly on the command line (although discouraged) '
            'You can create your token with a bootstrap+ plan at https://meterian.com/account/#tokens'
        )
    )
    
    val = os.getenv('DATADOG_API_KEY', None)
    parser.add_argument(
        '--dd-apikey',
        metavar='KEY',
        default=val,
        help=(
            'Allows you to specify the Datadog API key directly on the command line (although discouraged) '
            'You should use the standard environment variable DATADOG_API_KEY instead'
        )
    )
    
    parser.add_argument(
        '--dd-appkey',
        metavar='KEY',
        default=os.getenv('DATADOG_APP_KEY', None),
        help=(
            'Allows you to specify the Datadog application key directly on the command line (although discouraged) '
            'You should use the standard environment variable DATADOG_APP_KEY instead'
        )
    )
    
    parser.add_argument(
        '--dd-host',
        metavar='HOST',
        default=os.getenv('DATADOG_HOST', None),
        help=(
            'Allows you to specify the API host to use directly on the command line (although discouraged) '
            'You should use the standard environment variable DATADOG_HOST instead'
        )
    )

    parser.add_argument(
        '--branches',
        metavar='BRANCHES',
        default=os.getenv('BRANCHES', None),
        help=(
            'Allows you to specify a comma separated list of branches to be taken in account'
            'You can use the standard environment variable BRANCHES instead'
        )
    )

    parser.add_argument(
        '-l',
        '--log',
        default='warning',
        metavar='LEVEL',
        help='Sets the logging level (default is "warning")'
    )

    parser.add_argument('--recompute', action='store_true')
    
    args = parser.parse_args()

    args.meterian_env = os.getenv('METERIAN_ENV', 'www')
    args.branches =  [x.strip() for x in args.branches.split(',')]
    return args


def _initLogging(args):
    levels = {
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warn': logging.WARNING,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG
    }
    level = levels.get(args.log.lower())
    if level is None:
        raise ValueError('Invalid log level requested - must be in '+levels.keys());

    logging.basicConfig(level=level)
    logging.basicConfig(format='%(time)s-%(levelname)s-%(message)s')

    if level == logging.DEBUG:
        _logHttpRequests()
    else:
        logging.getLogger('requests').setLevel(logging.WARNING)

    logging.debug('Logging initiated')


def _get_account_uuid(args):
    logging.debug("Loading account information...")

    where = "https://" + args.meterian_env + ".meterian.com/api/v1/accounts/me"
    headers = {
        'content-type':'application/json', 
        'Authorization':'token ' + args.meterian_token
    }
    
    response = requests.get(where, headers=headers, timeout=10)
    if response.status_code != 200:
        print ("Unable to collect account information:", response)
        sys.exit(-1)
    
    value = json.loads(response.text)
    account_uuid = value['uuid']

    print("Account:", value['name'])
    print("Email:", value['email'])
    print();
    
    return account_uuid


def collect_projects_data():

    account_uuid = _get_account_uuid(args)
    
    logging.debug("Loading projects information...")    
    where = "https://"+args.meterian_env+".meterian.com/api/v1/accounts/"+account_uuid+"/projects"
    headers={
        'content-type':'application/json',
        'Authorization':'token '+args.meterian_token
    }
    
    response = requests.get(where, headers=headers, timeout=10)
    all_projects = json.loads(response.text)
    
    projects = []
    for p in all_projects:
        branches = []
        for b in p['branches']:
            if b in args.branches:
                logging.debug("Selected branch %s of project %s", p['name'], b)
                branches.append(b)

        if len(branches) > 0:            
            logging.debug("Selected %s project", p['name'])
            p['branches'] = branches
            projects.append(p)
        else:
            logging.debug("Project %s not selected - no matching branches", p['name'])
            
    print("Collected", str(len(projects)), "projects out of", str(len(all_projects)))
    return projects


def _load_or_recompute_project_report(name, uuid, branch):
    
    headers={
        'content-type':'application/json',
        'Authorization':'token '+args.meterian_token
    }

    if args.recompute:
        print("Recomputing project", name, "branch", branch)    
        where = "https://"+args.meterian_env+".meterian.com/api/v1/reports/"+uuid+"/full?branch="+branch
        response = requests.post(where, headers=headers, timeout=180)
    else:
        logging.debug("Loading report for project %s, branch %s", uuid, branch)    
        where = "https://"+args.meterian_env+".meterian.com/api/v1/reports/"+uuid+"/json?branch="+branch
        response = requests.get(where, headers=headers, timeout=10)
        
    report = json.loads(response.text)
    logging.debug("Report for project %s, branch %s: %s", uuid, branch, json.dumps(report))
    return report
    

def _send_score_to_dd(name, branch, stype, project_report):
    if stype in project_report:
        report = project_report[stype]
        if 'score' in report:
            score = report['score']
            metric_name = args.prefix + '.projects.scores.' + stype
            logging.debug("- updating metric %s for project %s/%s", metric_name, name, branch)
            api.Metric.send(metric=metric_name, 
                points=[(int(time.time()), score)], 
                tags=['project:' + name, 'branch:' + branch], 
                type='gauge')


def _send_vulns_to_dd(name, branch, project_report):
    excl_count = 0
    crit_count = 0
    high_count = 0
    med_count  = 0
    low_count  = 0
    
    if 'security' in project_report:
        security_report = project_report['security']
        for assessment in security_report['assessments']:
            for report in assessment['reports']:
                for advice in report['advices']:
                    if 'exclusions' in advice:
                        excl_count = excl_count +1
                    else:
                        severity = advice['severity']
                        if severity == 'CRITICAL':
                            crit_count+=1
                        elif severity == 'HIGH':
                            high_count+=1
                        elif severity == 'MEDIUM':
                            med_count+=1
                        elif severity == 'LOW':
                            low_count+=1
                                
    when = int(time.time())
    metric_name = args.prefix + '.projects.vulns'
    logging.debug("- updating metric %s for project %s/%s - C/H/M/L: %d/%d/%d/%d (%d exclusions)", metric_name, name, branch, crit_count, high_count, med_count, low_count, excl_count)

    api.Metric.send(metric=metric_name, 
        points=[(when, crit_count)], 
        tags=['project:' + name, 'branch:' + branch, 'severity:CRITICAL'], 
        type='gauge')
    api.Metric.send(metric=metric_name, 
        points=[(when, high_count)], 
        tags=['project:' + name, 'branch:' + branch, 'severity:HIGH'], 
        type='gauge')
    api.Metric.send(metric=metric_name, 
        points=[(when, med_count)], 
        tags=['project:' + name, 'branch:' + branch, 'severity:MEDIUM'], 
        type='gauge')
    api.Metric.send(metric=metric_name, 
        points=[(when, low_count)], 
        tags=['project:' + name, 'branch:' + branch, 'severity:LOW'], 
        type='gauge')


def send_statistics(projects):
    for p in projects:
        name = p['name']
        for branch in p['branches']:
            project_report = _load_or_recompute_project_report(name, p['uuid'], branch)
            
            print("Uploading data for project", p['name'], "branch", branch)
            _send_score_to_dd(name, branch, 'security',  project_report)
            _send_score_to_dd(name, branch, 'stability', project_report)
            _send_score_to_dd(name, branch, 'licensing', project_report)
            _send_vulns_to_dd(name, branch, project_report)


def recompute_projects(projects):
    for p in projects:
        name = p['name']
        for branch in p['branches']:
            print("Uploading data for project", p['name'], "branch", branch)
            project_report = _load_or_recompute_project_report(p['uuid'], branch)
            
            _send_score_to_dd(name, branch, 'security',  project_report)
            _send_score_to_dd(name, branch, 'stability', project_report)
            _send_score_to_dd(name, branch, 'licensing', project_report)
            _send_vulns_to_dd(name, branch, project_report)



#
# CLI entry point
#

if __name__ == '__main__':

    load_dotenv()

    args = _parseArgs()
    _initLogging(args)

    logging.info('Initializing DD apis...')
    initialize()

    print('Collecting information from Meterian...')
    projects = collect_projects_data()

    if len(projects) > 0:
        print('\nUploading project statistics to DataDog...')
        send_statistics(projects)
    else:
        print('No projects were selected!')

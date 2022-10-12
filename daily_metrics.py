#!/usr/bin/env python3

import argparse
import http.client
import json
import logging
import math
import os
from _socket import gaierror

import datadog_api_client.exceptions
import requests
import sys
import time

from datadog import initialize, api
from datadog_api_client.v1.api.authentication_api import AuthenticationApi
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta
from datetime import datetime
from datadog_api_client import ApiClient, Configuration
from datadog_api_client.v1.api.metrics_api import MetricsApi
from datadog_api_client.v1.model.metric_metadata import MetricMetadata
from datadog_api_client.v1.model.distribution_point import DistributionPoint
from datadog_api_client.v1.model.distribution_points_content_encoding import DistributionPointsContentEncoding
from datadog_api_client.v1.model.distribution_points_payload import DistributionPointsPayload
from datadog_api_client.v1.model.distribution_points_series import DistributionPointsSeries
from urllib3.exceptions import MaxRetryError

API_TOKEN_ENVVAR = 'METERIAN_API_TOKEN'

class HelpingParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.stderr.write('\n')
        sys.exit(-1)

class AgeMetric():
    def __init__(self, advice_id, library, age=timedelta(0), cve=None,severity=None):
        self.advice_id = advice_id
        self.age = age
        self.library = library
        self.cve = cve
        self.severity = severity

    def to_arr(self):
        arr = []

        arr.append("library:" + self.library)
        if self.cve is not None:
            arr.append("cve:" + self.cve)

        if self.severity is not None:
            arr.append("severity:"+self.severity)

        return arr

    def get_age(self):
        return math.floor(self.age.days)

    def get_hours(self):
        return self.age.days * 24

    def get_mins(self):
        return math.floor(self.age.seconds / 60)

def exit_with_err_msg(msg):
    print("FAILURE: " + msg)
    exit(1)


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
        '--metrics',
        metavar='METRICS',
        default='project_scores,vulns_age,vulns_count_by_severity',
        help=(
            'Allows you to specify a comma separated list of metrics to send to datadog'
            'Supported values: project_scores, vulns_age, vulns_count_by_severity'
            'If omitted all metrics will be sent.'
        )
    )

    parser.add_argument(
        '--projects',
        metavar='PROJECTS',
        default=os.getenv('PROJECTS', None),
        help=(
            'Allows you to specify a comma separated list of projects to be taken in account'
            'You can use the standard environment variable PROJECTS instead'
        )
    )
    parser.add_argument(
        '--tags',
        metavar='TAGS',
        default=os.getenv('TAGS', None),
        help=(
            'Allows you to specify a comma separated list of tags to be taken in account'
            'You can use the standard environment variable TAGS instead'
        )
    )

    parser.add_argument(
        '--vuln-age-start-date',
        metavar='START_DATE',
        default=None,
        help=(
            'Ensures that only the data which comes from reports after the given date is used to calculate vulnerability age.\n'
            'Should be formatted as YYYY/MM/DD e.g 2020/05/01'
        )
    )

    parser.add_argument(
        '--vuln-age-end-date',
        metavar='END_DATE',
        default=None,
        help=(
            'Ensures that only the data which comes from reports before the given date is used to calculate vulnerability age.\n'
            'Should be formatted as YYYY/MM/DD e.g 2020/05/08'
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
    parser.add_argument(
        '--validate',
        action='store_true',
        help=(
            'check connection to datadog endpoints.'
            'checks connection to datadog host, validates the datadog API key and validates the datadog APP key'
        )
    )

    args = parser.parse_args()

    args.meterian_env = os.getenv('METERIAN_ENV', 'www')

    args.tags     = _split_by_comma(args.tags)
    args.branches = _split_by_comma(args.branches)
    args.projects = _split_by_comma(args.projects)
    args.metrics  = _split_by_comma(args.metrics)
    _enable_metrics(args,args.metrics)
    if args.vuln_age_start_date is not None:
        args.vuln_age_time_period_start = _parse_date_str_as_utc(args.vuln_age_start_date)
    else:
        args.vuln_age_time_period_start = None

    if args.vuln_age_end_date is not None:
        args.vuln_age_time_period_end = _parse_date_str_as_utc(args.vuln_age_end_date)
    else:
        args.vuln_age_time_period_end = None

    return args

def _split_by_comma(text):
    if text:
        return [x.strip() for x in text.split(',')]
    else:
        return None

def _enable_metrics(args, metrics):

    if 'project_scores' in metrics:
        args.send_project_scores = True
    else:
        args.send_project_scores = False

    if 'vulns_age' in metrics:
        args.send_vulns_age = True
    else:
        args.send_vulns_age = False

    if 'vulns_count_by_severity' in metrics:
        args.send_vulns_count_by_severity = True
    else:
        args.send_vulns_count_by_severity = False


def _parse_date_str_as_utc(str):
    return datetime.strptime(str,"%Y/%m/%d").replace(tzinfo=timezone.utc)


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
    where = "https://" + args.meterian_env + ".meterian.com/api/v1/accounts/me"
    try:
        logging.debug("Loading account information...")
        headers = {
            'content-type':'application/json',
            'Authorization':'token ' + args.meterian_token
        }

        response = requests.get(where, headers=headers, timeout=10)
        if response.status_code != 200:
            if response.status_code == 401:
                exit_with_err_msg("Unable to collect account information at" + where + " incorrect credentials")

            if response.status_code == 403:
                exit_with_err_msg("Unable to collect account information at " + where + " you are not authorized to view this account")

            if response.status_code == 404:
                exit_with_err_msg("Unable to collect account information at " + where + " account does not exist")

            exit_with_err_msg(str(response) + " Unable to collect account information at " + where)

        value = json.loads(response.text)
        account_uuid = value['uuid']

        print("Account:", value['name'])
        print("Email:", value['email'])
        print()
        logging.debug("collected account information")
        return account_uuid

    except requests.exceptions.ConnectionError as e:
        exit_with_err_msg('Could not collect account information. Could not connect to ' + where)


def collect_projects_data():

    account_uuid = _get_account_uuid(args)
    try:
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
            project_name = p['name']
            if args.projects:
                if not project_name in args.projects:
                    logging.debug("Project %s not selected - name not matching", project_name)
                    continue

            if args.tags:
                accepted = False
                for t in p['tags']:
                    if t in args.tags:
                        accepted = True

                if not accepted:
                    logging.debug("Project %s not selected - tags %s not matching", project_name, str(p['tags']))
                    continue

            if args.branches:
                branches = []
                for b in p['branches']:
                    if b in args.branches:
                        logging.debug("Selected branch %s of project %s", project_name, b)
                        branches.append(b)
            else:
                branches = p['branches']

            if len(branches) > 0:
                logging.debug("Selected %s project", p['name'])
                p['branches'] = branches
                projects.append(p)
            else:
                logging.debug("Project %s not selected - no matching branches", project_name)

        print("Collected", str(len(projects)), "projects out of", str(len(all_projects)))
        return projects

    except requests.exceptions.ConnectionError as e:
        exit_with_err_msg("could not collect project information, failed to establish a connection")



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
    try:
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

    except Exception as e:
        exit_with_err_msg(str(e))

def _send_vulns_to_dd(name, branch, project_report):
    excl_count = 0
    crit_count = 0
    high_count = 0
    med_count  = 0
    low_count  = 0
    try:
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
    except Exception as e:
        exit_with_err_msg(str(e))


def _validate_dd_connection():
    where = args.dd_host
    if args.validate:
        try:
            print("checking connection to datadog")
            res = requests.get(where)
            if res.status_code == 200 or res.status_code == 202:
                print("connection to [" + where + "]" + " is working")
            else:
                exit_with_err_msg("could not establish connection to datadog host: [" + where + "]" "status: " + str(res.status_code))

        except requests.exceptions.ConnectionError:
            exit_with_err_msg("could not establish connection to datadog host: [" + where + "]")


        try:
            config = Configuration(host=args.dd_host, api_key={'apiKeyAuth': args.dd_apikey})
            with ApiClient(config) as api_client:
                instance = AuthenticationApi(api_client)
                instance.validate()
                print("API key is valid")

        except datadog_api_client.exceptions.ForbiddenException:
            print("could not validate api key")
            exit_with_err_msg("API key is invalid")

        try:
            config = Configuration(host=args.dd_host, api_key={'apiKeyAuth': args.dd_apikey, 'appKeyAuth': args.dd_appkey})
            with ApiClient(config) as api_client:
                metric_name = args.prefix + "projects.vulns"
                api_instance = MetricsApi(api_client)
                api_instance.list_metrics(metric_name)
                print("APP key is valid")

        except datadog_api_client.exceptions.ForbiddenException:
            print("could not get retrieve metric information")
            exit_with_err_msg("APP key is invalid")

        print("OK")
        exit(0)


def _get_project_history(project_uuid, branch):
    where = "https://" + args.meterian_env + ".meterian.com/api/v1/reports/" + project_uuid + "/history"
    headers = {
        'content-type': 'application/json',
        'Authorization': 'token ' + args.meterian_token
    }
    params = {
        'project': project_uuid,
        'branch': branch,
        'limit': 100
    }
    response = requests.get(where, params=params, headers=headers, timeout=10)
    res = json.loads(response.text)
    return res

def _get_adv_history(project_uuid, branch, pid_list):

    adv_history = []
    adv_metric_map = {}
    for pid in pid_list:
        where = "https://" + args.meterian_env + ".meterian.com/api/v1/reports/" + project_uuid + "/full/" + pid
        params = {'branch': branch}
        headers = {
            'content-type': 'application/json',
            'Authorization': 'token ' + args.meterian_token
        }

        response = requests.get(where, params=params, headers=headers, timeout=10)
        res_obj = json.loads(response.text)
        security = res_obj['security']['assessments']
        tmp_advices = []
        for assessment in security:
            for report in assessment['reports']:
                for adv in report['advices']:
                    if 'exclusions' not in adv:
                        tmp_advices.append(adv['id'])
                        if adv['id'] not in adv_metric_map:
                            adv_metric_map[adv['id']] = AgeMetric(
                                advice_id=adv['id'],
                                library=adv['library']['name'],
                                cve=adv['cve'] if adv['cve'] else None,
                                severity=adv['severity']
                            )

        adv_history.append(tmp_advices)

    return (adv_history, adv_metric_map)


def tally_time_delta(adv_id, adv_history, times):
    tally = timedelta(0)
    latest_time = times[0]
    for i in range(len(adv_history)):
        if adv_id in adv_history[i]:
            tally += times[i] - latest_time
            latest_time = times[i]
        else:
            if i + 1 < len(adv_history):
                latest_time = times[i + 1]


    return tally


def append_date_to_project_history(times, adv_history, new_time):
    if(times[-1] > new_time):
        logging.warning("attempted to add an entry in non-chronological order, it will be ignored")
        return

    times.append(new_time)
    if adv_history is not None:
        last_adv = adv_history[-1]
        adv_history.append(last_adv)


def filter_project_history_by_date(pid_and_time,start_date,end_date):
    filtered = pid_and_time
    if start_date is not None:
        logging.info('start date: %s',start_date)
        filtered = list(filter(lambda entry:  entry[1] >= start_date, filtered))

    if end_date is not None:
        logging.info('end date: %s',end_date)

        filtered = list(filter(lambda entry: entry[1] <= end_date,filtered))

    return filtered


def _find_age(project_uuid,branch,start_date,end_date):
    res = _get_project_history(project_uuid, branch)
    pid_and_time = []
    pid_and_time = list(map(lambda p_id: (p_id['uuid'],p_id['timestamp']),res))
    pid_and_time = sorted(pid_and_time, key=lambda t: t[1])
    pid_and_time = list(map(lambda history: (history[0],datetime.fromtimestamp(history[1]/1000, tz=timezone.utc)),pid_and_time))
    logging.debug("start: %s, end %s",start_date,end_date)
    pid_and_time = filter_project_history_by_date(pid_and_time, start_date, end_date)
    logging.debug("filtered history<<%s>>",pid_and_time)

    if not pid_and_time:
        logging.warning("empty history after filtered by date, will be skipped")
        return None

    adv_history,adv_metric_map = _get_adv_history(project_uuid, branch, list(map(lambda p_id: p_id[0], pid_and_time)))
    times = list(map(lambda t: t[1], pid_and_time))

    if end_date is None:
        append_date_to_project_history(times, adv_history,datetime.now(tz=timezone.utc))
    else:
        append_date_to_project_history(times, adv_history, end_date)

    print("most recent report summary " + str(adv_history[-1]))
    for advisories in adv_history:
        for adv_id in advisories:
            if adv_id in adv_history[-1]:
                adv_metric_map[adv_id].age = tally_time_delta(adv_id, adv_history, times)
            else:
                logging.debug('ignoring datapoint for ' + adv_id + ' its not present in the most recent report')
                adv_metric_map[adv_id] = None

    logging.debug("final map " + str(adv_metric_map))
    return adv_metric_map


def _send_vuln_age_to_dd(name,project_uuid, branch,start_date,end_date):
    vuln_ages = _find_age(project_uuid, branch,start_date,end_date)
    if not vuln_ages:
        logging.warning('could not calculate any ages for ' + name)
        return

    metric_name = args.prefix + ".vulns.age.distribution"
    try:
        for adv_id, age_metric in vuln_ages.items():
            if age_metric:
                logging.debug("--vuln: %s, lib: %s, mins_open: %d",age_metric.advice_id,age_metric.library,age_metric.get_mins())
                metric_tags = ['project:' + name, 'branch:' + branch]
                for tag in age_metric.to_arr():
                    metric_tags.append(tag)

                logging.debug(metric_tags)
                _send_distribution_to_metric_endpoint(metric_name,age_metric.get_mins(),tags=metric_tags)
            else:
                logging.debug("no age metric submitted for vuln %s",adv_id)

    except Exception as e:
        exit_with_err_msg(str(e))


def _configure_distribution_metric(metric_name):
    try:
        body = MetricMetadata(
            unit="day"
        )
        config = Configuration(host=args.dd_host, api_key={'apiKeyAuth': args.dd_apikey, 'appKeyAuth': args.dd_appkey})
        with ApiClient(config) as api_client:
            logging.info("configuring %s metric",metric_name)
            api_instance = MetricsApi(api_client)
            response = api_instance.update_metric_metadata(metric_name=metric_name, body=body)
            logging.info("SUCCESS %s",response)

    except datadog_api_client.exceptions.ForbiddenException as e:
        exit_with_err_msg('could not configure distribution metric, incorrect credentials')
    except MaxRetryError as e:
        exit_with_err_msg('could not connect to host')


def _send_distribution_to_metric_endpoint(metric_name,value,tags):
    try:
        body = DistributionPointsPayload(
            series=[
                DistributionPointsSeries(
                    metric=metric_name,
                    points=[
                        DistributionPoint(
                            [
                                datetime.now().timestamp(),
                                [value],
                            ]
                        ),
                    ],
                    tags=tags
                ),
            ],
        )
        config = Configuration(host=args.dd_host,api_key={'apiKeyAuth': args.dd_apikey})

        with ApiClient(config) as api_client:
            instance = MetricsApi(api_client)
            instance.submit_distribution_points(
                content_encoding=DistributionPointsContentEncoding("deflate"), body=body
            )

    except datadog_api_client.exceptions.ForbiddenException as e:
        exit_with_err_msg('could not send distribution metric, incorrect credentials')


def send_statistics(projects,vuln_age_time_period_start,vuln_age_time_period_end):
    dist_metric_name = args.prefix + ".vulns.age.distribution"
    _configure_distribution_metric(dist_metric_name)
    for p in projects:
        name = p['name']
        for branch in p['branches']:
            project_report = _load_or_recompute_project_report(name, p['uuid'], branch)
            print("Uploading data for project", p['name'], "branch", branch)
            if args.send_project_scores:
                logging.info("sending scores for security section")
                _send_score_to_dd(name, branch, 'security',  project_report)

                logging.info("sending scores for stability section")
                _send_score_to_dd(name, branch, 'stability', project_report)

                logging.info("sending scores for licensing section")
                _send_score_to_dd(name, branch, 'licensing', project_report)

            if args.send_vulns_count_by_severity:
                logging.info("sending vulnerability counts information")
                _send_vulns_to_dd(name, branch, project_report)

            if args.send_vulns_age:
                logging.info("sending vulnerability age information")
                _send_vuln_age_to_dd(name, p['uuid'], branch,vuln_age_time_period_start,vuln_age_time_period_end)


def recompute_projects(projects):
    for p in projects:
        name = p['name']
        for branch in p['branches']:
            print("Uploading data for project", p['name'], "branch", branch)
            project_report = _load_or_recompute_project_report(p['uuid'], branch)
            if args.send_project_scores:
                _send_score_to_dd(name, branch, 'security',  project_report)
                _send_score_to_dd(name, branch, 'stability', project_report)
                _send_score_to_dd(name, branch, 'licensing', project_report)

            if args.send_vulns_age:
                _send_vulns_to_dd(name, branch, project_report)



#
# CLI entry point
#

if __name__ == '__main__':

    load_dotenv()

    args = _parseArgs()
    _initLogging(args)

    _validate_dd_connection()
    logging.info('Initializing DD apis...')
    initialize()

    print('Collecting information from Meterian... (%s)' % args.meterian_env)
    projects = collect_projects_data()
    if len(projects) > 0:
        print('\nUploading project statistics to DataDog...')

        send_statistics(projects,args.vuln_age_time_period_start, args.vuln_age_time_period_end)
        print('OK')
    else:
        print('No projects were selected!')
        print('OK')

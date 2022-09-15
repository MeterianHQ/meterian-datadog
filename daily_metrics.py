#!/usr/bin/env python3

import argparse
import http.client
import json
import logging
import os
import requests
import sys
import time

from datadog import initialize, api, statsd
from dotenv import load_dotenv
from datetime import datetime, timezone, timedelta

options = {
    'statsd_host':'127.0.0.1',
    'statsd_port':8125
}
initialize(**options)
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
        return self.age.days

    def get_hours(self):
        return self.age.days * 24

    def get_mins(self):
        return self.age.seconds / 60

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

    args = parser.parse_args()

    args.meterian_env = os.getenv('METERIAN_ENV', 'www')

    args.tags     = _split_by_comma(args.tags)
    args.branches = _split_by_comma(args.branches)
    args.projects = _split_by_comma(args.projects)

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
    logging.debug("Loading account information...")

    where = "https://" + args.meterian_env + ".meterian.com/api/v1/accounts/me"
    headers = {
        'content-type':'application/json',
        'Authorization':'token ' + args.meterian_token
    }

    response = requests.get(where, headers=headers, timeout=10)
    if response.status_code != 200:
        print ("Unable to collect account information at ", where, "\n", response)
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
    latest_time = timedelta(0)
    for i in range(len(adv_history)):
        if adv_id in adv_history[i]:
            if tally == timedelta(0) and latest_time == timedelta(0):
                latest_time = times[i]
            else:
                tally += times[i] - latest_time
                latest_time = times[i]
        else:
            tally = timedelta(0)
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

    for advisories in adv_history:
        for adv_id in advisories:
            adv_metric_map[adv_id].age = tally_time_delta(adv_id, adv_history, times)

    return adv_metric_map


def _send_vuln_age_to_dd(name,project_uuid, branch,start_date,end_date):
    vuln_ages = _find_age(project_uuid, branch,start_date,end_date)
    if not vuln_ages:
        logging.warning("could not calculate ages for %s",name)
        return

    metric_name = args.prefix + ".vulns.age.distribution"

    for adv_id,age_metric in vuln_ages.items():
        logging.debug("--vuln: %s, lib: %s, mins_open: %d",age_metric.advice_id,age_metric.library,age_metric.get_mins())
        metric_tags = ['project:' + name, 'branch:' + branch]
        for tag in age_metric.to_arr():
            metric_tags.append(tag)
        logging.debug(metric_tags)
        statsd.distribution(metric_name,age_metric.get_mins(),tags=metric_tags)

def send_statistics(projects,vuln_age_time_period_start,vuln_age_time_period_end):
    for p in projects:
        name = p['name']
        for branch in p['branches']:
            project_report = _load_or_recompute_project_report(name, p['uuid'], branch)

            print("Uploading data for project", p['name'], "branch", branch)
            _send_score_to_dd(name, branch, 'security',  project_report)
            _send_score_to_dd(name, branch, 'stability', project_report)
            _send_score_to_dd(name, branch, 'licensing', project_report)
            _send_vulns_to_dd(name, branch, project_report)
            _send_vuln_age_to_dd(name, p['uuid'], branch,vuln_age_time_period_start,vuln_age_time_period_end)

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

    print('Collecting information from Meterian... (%s)' % args.meterian_env)
    projects = collect_projects_data()
    if len(projects) > 0:
        print('\nUploading project statistics to DataDog...')

        send_statistics(projects, args.vuln_age_time_period_start, args.vuln_age_time_period_end)
    else:
        print('No projects were selected!')

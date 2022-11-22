# Meterian Datadog Sample Scripts

A repository that contains script that, using the Meterian API, allows to feed to a DataDog instance.

## You will need a token to use this tool!

This tool will require an API token from Meterian. This is available for any paid plan, and it can be generated from the "Tokens" tab at https://meterian.com/dashboard

Once you have the token, the best and secure way to use it is to put it into an environment variable, called METERIAN_API_TOKEN. In linux, for example, you can simply do something like this:

    export METERIAN_API_TOKEN=a902874d-50f2-464f-8707-780cd5f669a3
(no, this is not a real token eheh!)


## How to use

If you have python3, you can install the dependencies (see the Pipfile) and
run it manually as a normal python script
`python daily_metrics.py [Options]`

You can also use `pipenv`: first of all run `pipenv install` to setup the virtual environment.
**This script only works with python3**
Then launch the generator `pipenv run python daily_metrics.py [Options]`

You can use the "--help" option to show the parameters that can be passed.

We suggest you setup a `.env` file so that most parameters are loaded automatically:
```
DATADOG_API_KEY=...
DATADOG_APP_KEY=...
DATADOG_HOST="https://api.datadoghq.eu"
METERIAN_API_TOKEN=...
BRANCHES=master,develop
PROJECTS=project_foo,project_bar
```
You can use the `--metrics` flag to specify which types of metrics you want to send. This flag is optional and if omitted all available metrics will be sent.

For example if you only wanted to send the `vulns_age` metric and the `project_scores` metric you would run: `python daily_metrics.py --metrics=vulns_age,project_scores`

You can also use the `--vuln-age-tags` flag to control what tags you want to be associated to the 
datapoints sent by the `vulns_age` metric. For example if you wanted to send data without a specific value for the library tag you would run: 

`python daily_metrics.py --vuln-age-tags=project,branch,severity,cve`

by default the tags `project,branch,severity,cve,library` are enabled for the `vulns_age` metric
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
```

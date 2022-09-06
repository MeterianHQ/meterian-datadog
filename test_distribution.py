from datadog import initialize, statsd

options = {
    'statsd_host':'127.0.0.1',
    'statsd_port':8125
}

initialize(**options)

i = 0
while(i < 30):
    statsd.distribution("example.new.dist",float(i),["example"])
    i += 1

print("finished submitting test metrics")
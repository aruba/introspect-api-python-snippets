# introspect-api

## introspect_api.py

Python interface to the Aruba IntroSpect REST API

IntroSpect version support: 2.3.0.0-425 and above

Implements
	OAuth
	alerts
	conversations
API

See analyzer:
	https://<analyzer>/api-specs/

and pydocs in this module for full documentation

Sample test script in:

    test_introspect_api.py

### Usage

```
import json
import time

import introspect_api

host = 'seeladvanced.portal.niarasystems.com'
client_id = '<CLIENT_ID'
client_secret = '<CLIENT_SECRET>'
port = 443 # or 8443 for on-prem analyzer

api = IntroSpectRest(host, client_id, client_secret, port=port)

# Get an OAuth token from the Analyzer
api.refresh_token()

print (api.get_alert('ALERT-10'))

print (api.get_alerts())

params = {
	'operation': 'search',
	'query': '*.*',
	'limit': 10,
	'from': (ts - 10*24*60*60) * 1000,
	'to': millis
}

alerts = json.loads(api.get_alerts(params))
print(alerts)
print("Number of alerts: {}".format(len(alerts['data'])))
```





	


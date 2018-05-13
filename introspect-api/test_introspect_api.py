#!/usr/bin/env python

"""
Author: @alpaalpa, Aruba Security Group
Organization: Aruba, a Hewlett Packard Enterprise company

Version: 2018.01

The MIT License (MIT)
 
Copyright (c) Hewlett Packard Enterprise Development LP
 
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

from __future__ import print_function

import json
import logging
import platform
import requests
import socket
import time

from introspect_api import IntroSpectRest

# Disable SSL cert warning as we are using self-signed cert
requests.packages.urllib3.disable_warnings()

# set logging level
logging.basicConfig(level=logging.DEBUG)   

ts = int(round(time.time()))
millis = int(round(time.time() * 1000))


host = 'seeladvanced.portal.niarasystems.com'
client_id = '6WUHmGuTuW0ee8VvRLIeOw6XCsDtl833970nN9oy'
client_secret = 'Pu6hJbfLDbrRN1ef96HZA9sOQBhk7aHK6O4b1AZYPBrnDZbq1P'
port = 443

api = IntroSpectRest(host, client_id, client_secret, port=port)
api.refresh_token()

print (api.token)

params = {
	'operation': 'search',
	'query': '*.*',
	'limit': 10,
	'from': (ts - 10*24*60*60) * 1000,
	'to': millis
}


print (api.get_alert('ALERT-10'))

print (api.get_alerts())

alerts = json.loads(api.get_alerts(params))
print(alerts)
print("Number of alerts: {}".format(len(alerts['data'])))


print (api.get_conversation('5cc51841109000000000004000100008a992dd15761'))

print (api.get_conversations())

conversations = json.loads(api.get_conversations(params))
print(conversations)
print("Number of conversations: {}".format(len(conversations['data'])))






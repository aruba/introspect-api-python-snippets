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
_THE SOFTWARE.
"""

from __future__ import print_function
__version__ = "2018.01"
__author__ = "Albert Pang"

import json
import logging
import requests
import time

def param_encode(payload):
    """
    This is to get around the default url encode of requests.get(). We need
    *.* to be encoded as *%3A* but it's encoding it as %2A.%2
    IntroSpect doesn't like that
    """
    payload_str = "&".join("%s=%s" % (k,v) for k,v in payload.items())
    return payload_str.replace('.', '%3A')

class IntroSpectRest(object):
    """
    Python interface for Aruba IntroSpect's REST API

	Tested with IntroSpect version 2.3.0.0-425

    Full documentation can be found by accessing the swagger interface at:
    	https://<IntroSpectAN>:8443/api-spects/
    for on-prem analyzer or
    	https://<IntroSpectAN>/api-spects/
    for analyzer deployed in AWS
	"""
    def __init__(self, hostname, client_id, client_secret, port=443, verify=False):
    	"""
    	The client_id, client_secret can be optained from IntroSpect AN:
    		Menu -> Configuration -> API Clients

		port is 8443 for an on-prem analyzer, 443 for AWS deployment

    	"""
        super(IntroSpectRest, self).__init__()
        self.hostname = hostname
        self.client_id = client_id
        self.client_secret = client_secret
        self.port = port
        self.verify = verify # Whether to verify SSL cert

        self._token = None

    @property
    def _header(self):
        header = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }        

    @property
    def _token_header(self):
        if not self.token:
            self.refresh_token()

        token_header = {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer {}'.format(self.token)
        }

        return token_header

    def _get_url(self, endpoint):
        """
        Fortmat the URL based on the REST API endpoint
        """
        if self.port == 443 or self.port == None:
            url="https://{}/{}".format(self.hostname, endpoint)
        else:
            url="https://{}:{}/{}".format(self.hostname, self.port, endpoint)

        return url

    def _post(self, endpoint, data):
        url=self._get_url(endpoint)

        logging.debug(url)
        logging.debug(json.dumps(data, sort_keys=True, indent=2))

        return requests.post(url, headers=self._header, json=data, verify=self.verify)

    def _get(self, endpoint, params=None):
        if not self.token:
            self.refresh_token()

        if not self.token:
            logging.error("Cannot get access_token")
            return None

        url=self._get_url(endpoint)

        logging.debug("url: {}".format(url))
        logging.debug("token_header: {}".format(self._token_header))

        if params:
            payload_str = param_encode(params)
            r = requests.get(url, verify=self.verify, headers=self._token_header, params=payload_str)
        else:
            r = requests.get(url, verify=self.verify, headers=self._token_header)

        return r

    def get_oauth_token(self):
        endpoint = "api/oauth/token"

        token_request = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }

        r = self._post(endpoint, token_request)

        if r and r.status_code == requests.codes.ok:
            return json.loads(r.text)['access_token']
        else:
            logging.error("{}".format(r.text))
            return None

    def refresh_token(self):
        token = self.get_oauth_token()
        if token:
            self._token = token

    @property
    def token(self):
        return self._token

    def _get_items(self, attribute, params=None):
        """
        retrieve multiple alerts based on params
        
        parameters:
            operation: Valid values are 'search', 'aggregations'; Default: search
            query: Boolean query to be executed against the datastore; Default: *.*
            fields: Fields returned. Required if aggregations. Separated by ,
            filter: Comma separate key:value. Add - in front for exclusion (foo:bar,-baz:quz)
            sort: Field to sort on. -field if you want desc or field for ascending
            offset: Number of records to skip (default: 0)
            limit: Number of records to return (default: 10)
            from: Epoch time in milliseconds for start of search. (default: epoch of 24 hours earlier)
            to: Epoch time in milliseconds to search till. (default: epoch of now)

        """
        if not params:
            """
            Default to getting last 30 days of alerts, limit to 100
            """
            now = time.time()
            thirtydays_ago = now - 30*24*60*60
            oneday_ago = now - 24*60*60
            params = {
                'operation': 'search',
                'query': '*.*',
#                'from': int(round(thirtydays_ago * 1000)),
                'from': int(round(oneday_ago * 1000)),
                'to': int(round(now * 1000)),
                'limit': 1
            }

        endpoint = "api/v2/{}/".format(attribute)
        r = self._get(endpoint, params)
        logging.debug("Return from _get: {}".format(r))

        if not r:
            return None
        if r.status_code == requests.codes.ok:
            return r.text
        else: 
            logging.error("{}".format(r.text))
            return None

    def _get_item(self, attribute, id):
        endpoint = "api/v2/{}/{}".format(attribute, id)
        r = self._get(endpoint)
        logging.debug("Return from _get: {}".format(r))

        if not r:
            return None
        if r.status_code == requests.codes.ok:
            return r.text
        else: 
            logging.error("ERROR: get_alert({}): {}".format(id, r.text))
            return None


    # External interfaces:

    def get_alert(self, alert_id):
        return self._get_item('alerts', alert_id)

    def get_alerts(self, params=None):
        return self._get_items('alerts', params)

    def get_conversation(self, conversation_id):
        return self._get_item('conversations', conversation_id)

    def get_conversations(self, params=None):
        return self._get_items('conversations', params)

def main():
    pass

if __name__ == "__main__":
    main()

"""
This inline script can be used to dump flows as HAR files.
"""
import pprint
import json
import sys
import base64
import zlib
import os, sys

from datetime import datetime
import pytz

import mitmproxy
from netlib import version
from netlib import strutils
from netlib.http import cookies

import traceback
import logging
from urlparse import urlparse
import argparse
import re

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tools

LOG_FILENAME = os.path.dirname(os.path.realpath(__file__))+"/error.log"
logging.basicConfig(filename=LOG_FILENAME, level=logging.ERROR)
json_dump = {}
user_para = {}
parser = argparse.ArgumentParser(description='Initialisation for model testing.')
parser.add_argument('-f', action='store', dest='statefile', type=str, help='file to store state', required=True)
parser.add_argument('-u', action='store', dest='uisupport', type=str, help='indicate whether it uses ui to identify user', required=True)
parser.add_argument('-i', action='store', dest='idp', type=str, help='identity provider', required=True)
args = parser.parse_args()

def start():
    """
        Called once on script startup before any other events.
    """
    global args
    json_dump.update({
        "access_token": None,
        "idp_url": [],
        "status": 'normal'
        })
    if args.uisupport == 'False':
        url = ''
        user_para_path = []
        user_json = json.load(open('user_para', 'r'))['userIdentifier']
        for key in user_json.keys():
            if key != 'Alice' and key != 'Eve':
                url = key
                user_para_path = user_json[key]
        [refHash, refOrder, refURL] = tools.refineURL(url)
        user_para.update({'url': refURL, 'path': user_para_path, 'hash': refHash, 'order': refOrder})
        

def response(flow):
    global args
    ip_addr_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    request_headers = name_value(flow.request.headers)
    hostname = ''
    for item in request_headers:
        if item['name'] == 'Host':
            hostname = item['value']
            break
        if item['name'] == ':authority':
            hostname = item['value']
            break 
    if re.search(r':(\d+)', hostname):
        hostname = hostname[:hostname.find(':')]
    url = re.sub(ip_addr_regex, hostname, flow.request.pretty_url) if hostname != '' else flow.request.pretty_url
    try:
        if args.idp == 'sina':
            if 'api.weibo.com/oauth2/sso_authorize' in url:
                try:
                    data = json.loads(flow.response.content)
                    if 'access_token' in data:
                        json_dump['access_token'] = data['access_token']
                except:
                    logging.exception("Exception in getting access token")

            if 'weibo' in url:
                try:
                    data = json.loads(flow.response.get_text(strict=False))
                    if 'error_code' in data and str(data['error_code']) == '10023':
                        json_dump['status'] = 'rate_limit'
                        o = urlparse(url)
                        netpath = o.netloc+o.path
                        if netpath not in json_dump["idp_url"]:
                            json_dump["idp_url"].append(netpath)
                except:
                    logging.exception("Exception in loading response content of weibo api")

            if args.uisupport == 'False' and user_para['url'] in url and (user_para['hash'] == '' or tools.RequestIndex(flow, True) == user_para['hash']):
                if user_para['order'] == 0:
                    pass
                elif user_para['order'] > 1:
                    user_para['order'] = user_para['order'] - 1
                else:
                    user_json = json.load(open('user_para', 'r'))
                    user_para['order'] = user_para['order'] - 1
                    data = json.loads(flow.response.content)
                    observation = tools.extractValue(user_para['path'][1:], data)
                    user_json['userIdentifier']['Eve'] = observation
                    json.dump(user_json, open('user_para_bk', 'w'))
        elif args.idp == 'fb':
            if re.search('m.facebook.com/v(.*)/dialog/oauth/confirm', url) or re.search('m.facebook.com/v(.*)/dialog/oauth/read', url):
                json_dump['access_token'] = tools.getFBResponseValue(flow.response.content, 'access_token')
        elif args.idp == 'wechat':
            if 'api.weixin.qq.com/sns/oauth2/access_token' in url:
                try:
                    data = json.loads(flow.response.content)
                    if 'access_token' in data:
                        json_dump['access_token'] = data['access_token']
                except:
                    logging.exception("Exception in getting access token")
    except:
        logging.exception("Unexpected exception")

def done():
    global args
    json.dump(json_dump, open(args.statefile, "w"))

def name_value(obj):
    """
        Convert (key, value) pairs to HAR format.
    """
    return [{"name": k, "value": v} for k, v in obj.items()]
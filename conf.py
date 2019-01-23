#!/usr/bin/env python
# -*- coding: utf-8 -*-
import urllib
import json
import os
import sys
import logging
import logging.handlers
#load in configuration info
g_code_type='utf-8'
# debug or run
g_test_state = 'run'
g_config = json.load(open('config.json', 'r'))
# g_appinfo = json.load(open('appinfo.json'))

# if g_config['policy']['level'] == 0 and g_config['policy']['step'] < 10:
#     g_config['policy']['step'] = 10 
# elif g_config['policy']['level'] == 1 and g_config['policy']['step'] < 20:
#     g_config['policy']['step'] = 20
# elif g_config['policy']['level'] == 2 and g_config['policy']['step'] < 30:
#     g_config['policy']['step'] = 30

# remove this latter 
# g_config['policy']['cases'] = 10


# def init_logger(path='running.log', outcome='result.log'):
#     global g_logger
#     global g_result
#     handler = logging.handlers.RotatingFileHandler(path)
#     handler2 = logging.handlers.RotatingFileHandler(outcome)
#     fmt = '[%(levelname)s] ' + g_appinfo['appName'] + ' %(asctime)s %(filename)s:%(lineno)s : %(message)s'
#     formatter = logging.Formatter(fmt)
#     handler.setFormatter(formatter)
#     handler2.setFormatter(formatter)
#     g_logger = logging.getLogger('mylog')
#     g_logger.addHandler(handler)
#     g_logger.setLevel(logging.DEBUG)
#     g_result = logging.getLogger('myresult')
#     g_result.addHandler(handler2)
#     g_result.setLevel(logging.DEBUG)

# init_logger()



#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
MobileApplication Stepper
"""
#self-defined lib
import SSO #state machine, input to PyModel
import tools
import extractor
import conf
import rpActions
#official lib
import re
import os
import sys
import copy
import json
import time
import requests
import subprocess
import threading
import urllib
import psutil
from shutil import copyfile
import logging
from time import sleep
from mitmproxy import flow, controller, options
from mitmproxy.proxy import ProxyServer, ProxyConfig
import testing
import logging
import unicodedata
import pdb
from urlparse import *
from logger import MyLogger

reload(sys)
sys.setdefaultencoding('utf8')

running_logger = MyLogger('Stepper', level='INFO').get_logger()
result_logger = logging.getLogger('result')

g_conf = json.load(open('config.json', 'r'))
g_appinfo = json.load(open('appinfo.json'))

#Global varialbe, need to use lock to access
actionName = None
respParaPool = {}
requParaPool = {}
#Store current parameter changed
#Internal structure may changes for different action
paraPool = {}

appium_port = int(g_conf["appium_port"])
system_port = int(g_conf["system_port"])
proxy_port = int(g_conf["proxy_port"])
mainProcess = psutil.Process(os.getpid())

def error_exit():
	global mainProcess

	currentFuzzing = tools.getLast()
	if not os.path.exists('appiumError.log'):
		json.dump({}, open('appiumError.log', 'w'))	
	else:
		errorLog = json.load(open('appiumError.log', 'r+'))
		if str(currentFuzzing) in errorLog.keys():
			errorLog[str(currentFuzzing)] = errorLog[str(currentFuzzing)] + 1
		else:
			errorLog[str(currentFuzzing)] = 1
		json.dump(errorLog, open('appiumError.log', 'w'))	
	try:
		p = psutil.Process(testing.process.pid)
		p.terminate()
	except Exception:
		pass
	running_logger.info('process id :{}, call system exit'.format(os.getppid()))
	mainProcess.terminate()

def readState():
  import os
  import json
  from tools import getBooleanInJson
  if os.path.exists('state.json'):
	with open('state.json') as f:
		stateVariables = json.load(f)
		SSO.access_token = str(stateVariables['access_token'])		
		SSO.initialized = getBooleanInJson(stateVariables['initialized'])
		SSO.Eve_state = getBooleanInJson(stateVariables['Eve_state'])
		SSO.IdP_App_Installed = getBooleanInJson(stateVariables['IdP_App_Installed'])					
		SSO.IdP_Name = str(stateVariables['IdP_Name'])	
		SSO.Eve_Auth_RP = getBooleanInJson(stateVariables['Eve_Auth_RP'])		
		SSO.doubleRequests = getBooleanInJson(stateVariables['doubleRequests'])
		SSO.fuzzIdPAuthIdPApp = getBooleanInJson(stateVariables['fuzzIdPAuthIdPApp'])
		SSO.fuzzIdPShowRPAppInfo = getBooleanInJson(stateVariables['fuzzIdPShowRPAppInfo'])
		SSO.fuzzEveIdP_Auth = getBooleanInJson(stateVariables['fuzzEveIdP_Auth'])
		SSO.fuzzIdPAuthIdPApp1 = getBooleanInJson(stateVariables['fuzzIdPAuthIdPApp1'])
		SSO.fuzzIdPShowRPAppInfo1 = getBooleanInJson(stateVariables['fuzzIdPShowRPAppInfo1'])
		SSO.fuzzEveIdP_Auth1 = getBooleanInJson(stateVariables['fuzzEveIdP_Auth1'])
		SSO.fuzzRPAppHandshakeRPServ = getBooleanInJson(stateVariables['fuzzRPAppHandshakeRPServ'])	
		SSO.fuzzGetUid = getBooleanInJson(stateVariables['fuzzGetUid'])
		SSO.fuzzShowUserInfo = getBooleanInJson(stateVariables['fuzzShowUserInfo'])
		SSO.fuzzShowMoreUserInfo = getBooleanInJson(stateVariables['fuzzShowMoreUserInfo'])
		SSO.fuzzShowExtraUserInfo = getBooleanInJson(stateVariables['fuzzShowExtraUserInfo'])
		SSO.fuzzGetUid1 = getBooleanInJson(stateVariables['fuzzGetUid1'])		
		SSO.fuzzShowUserInfo1 = getBooleanInJson(stateVariables['fuzzShowUserInfo1'])
		SSO.fuzzShowMoreUserInfo1 = getBooleanInJson(stateVariables['fuzzShowMoreUserInfo1'])
		SSO.fuzzShowExtraUserInfo1 = getBooleanInJson(stateVariables['fuzzShowExtraUserInfo1'])
		SSO.fuzzGetAT = getBooleanInJson(stateVariables['fuzzGetAT'])
		SSO.fuzzRefreshAT = getBooleanInJson(stateVariables['fuzzRefreshAT'])			
		SSO.finishIdPAuthIdPApp = getBooleanInJson(stateVariables['finishIdPAuthIdPApp'])
		SSO.finishIdPShowRPAppInfo = getBooleanInJson(stateVariables['finishIdPShowRPAppInfo'])
		SSO.finishEveIdP_Auth = getBooleanInJson(stateVariables['finishEveIdP_Auth'])
		SSO.finishIdPAuthIdPApp1 = getBooleanInJson(stateVariables['finishIdPAuthIdPApp1'])
		SSO.finishIdPShowRPAppInfo1 = getBooleanInJson(stateVariables['finishIdPShowRPAppInfo1'])
		SSO.finishEveIdP_Auth1 = getBooleanInJson(stateVariables['finishEveIdP_Auth1'])
		SSO.finishRPAppHandshakeRPServ = getBooleanInJson(stateVariables['finishRPAppHandshakeRPServ'])	
		SSO.finishGetUid = getBooleanInJson(stateVariables['finishGetUid'])
		SSO.finishShowUserInfo = getBooleanInJson(stateVariables['finishShowUserInfo'])
		SSO.finishShowMoreUserInfo = getBooleanInJson(stateVariables['finishShowMoreUserInfo'])
		SSO.finishShowExtraUserInfo = getBooleanInJson(stateVariables['finishShowExtraUserInfo'])
		SSO.finishGetUid1 = getBooleanInJson(stateVariables['finishGetUid1'])	
		SSO.finishShowUserInfo1 = getBooleanInJson(stateVariables['finishShowUserInfo1'])	
		SSO.finishShowMoreUserInfo1 = getBooleanInJson(stateVariables['finishShowMoreUserInfo1'])	
		SSO.finishShowExtraUserInfo1 = getBooleanInJson(stateVariables['finishShowExtraUserInfo1'])
		SSO.finishGetAT = getBooleanInJson(stateVariables['finishGetAT'])
		SSO.finishRefreshAT = getBooleanInJson(stateVariables['finishRefreshAT'])
		SSO.traceOneFinished = getBooleanInJson(stateVariables['traceOneFinished'])		
		SSO.traceTwoFinished = getBooleanInJson(stateVariables['traceTwoFinished'])																																													
	os.remove('state.json')

def initializeState(IdP_Name):
	if IdP_Name == 'sina':
		SSO.initialized = False
		SSO.Eve_state = False
		SSO.IdP_App_Installed = True					
		SSO.IdP_Name = 'sina'	
		SSO.Eve_Auth_RP = False
		SSO.doubleRequests = False
		SSO.fuzzIdPAuthIdPApp = False
		SSO.fuzzIdPShowRPAppInfo = False
		SSO.fuzzEveIdP_Auth = True
		SSO.fuzzIdPAuthIdPApp1 = False
		SSO.fuzzIdPShowRPAppInfo1 = False
		SSO.fuzzEveIdP_Auth1 = False
		SSO.fuzzRPAppHandshakeRPServ = False
		SSO.fuzzGetUid = True
		SSO.fuzzShowUserInfo = True
		SSO.fuzzShowMoreUserInfo = False
		SSO.fuzzShowExtraUserInfo = False
		SSO.fuzzGetUid1 = False
		SSO.fuzzShowUserInfo1 = False
		SSO.fuzzShowMoreUserInfo1 = False
		SSO.fuzzShowExtraUserInfo1 = False
		SSO.fuzzGetAT = False
		SSO.fuzzRefreshAT = False
		SSO.finishIdPAuthIdPApp = False
		SSO.finishIdPShowRPAppInfo = False
		SSO.finishEveIdP_Auth = False
		SSO.finishIdPAuthIdPApp1 = False
		SSO.finishIdPShowRPAppInfo1 = False
		SSO.finishEveIdP_Auth1 = False
		SSO.finishRPAppHandshakeRPServ = False
		SSO.finishGetUid = False
		SSO.finishShowUserInfo = False
		SSO.finishShowMoreUserInfo = False
		SSO.finishShowExtraUserInfo = False
		SSO.finishGetUid1 = False
		SSO.finishShowUserInfo1 = False
		SSO.finishShowMoreUserInfo1 = False
		SSO.finishShowExtraUserInfo1 = False
		SSO.finishGetAT = False
		SSO.finishRefreshAT = False
		SSO.traceOneFinished = False
		SSO.traceTwoFinished = False
		if g_conf['policy']['level'] >= 1:
			SSO.fuzzIdPAuthIdPApp = True
			SSO.fuzzIdPShowRPAppInfo = True
			SSO.fuzzIdPAuthIdPApp1 = True
			SSO.fuzzIdPShowRPAppInfo1 = True
			SSO.fuzzEveIdP_Auth1 = True	
			SSO.fuzzShowUserInfo1 = True
			SSO.fuzzGetUid1 = True
		if g_conf['policy']['level'] >= 2:
			SSO.fuzzRPAppHandshakeRPServ = True
	elif IdP_Name == 'wechat':
		SSO.initialized = False
		SSO.Eve_state = False
		SSO.IdP_App_Installed = True					
		SSO.IdP_Name = 'wechat'	
		SSO.Eve_Auth_RP = False
		SSO.doubleRequests = False
		SSO.fuzzIdPAuthIdPApp = False
		SSO.fuzzIdPShowRPAppInfo = True
		SSO.fuzzEveIdP_Auth = True
		SSO.fuzzIdPAuthIdPApp1 = False
		SSO.fuzzIdPShowRPAppInfo1 = False
		SSO.fuzzEveIdP_Auth1 = False
		SSO.fuzzRPAppHandshakeRPServ = False
		SSO.fuzzGetUid = False
		SSO.fuzzShowUserInfo = True
		SSO.fuzzShowMoreUserInfo = False
		SSO.fuzzShowExtraUserInfo = False
		SSO.fuzzGetUid1 = False
		SSO.fuzzShowUserInfo1 = False
		SSO.fuzzShowMoreUserInfo1 = False
		SSO.fuzzShowExtraUserInfo1 = False
		SSO.fuzzGetAT = True
		SSO.fuzzRefreshAT = True
		SSO.finishIdPAuthIdPApp = False
		SSO.finishIdPShowRPAppInfo = False
		SSO.finishEveIdP_Auth = False
		SSO.finishIdPAuthIdPApp1 = False
		SSO.finishIdPShowRPAppInfo1 = False
		SSO.finishEveIdP_Auth1 = False
		SSO.finishRPAppHandshakeRPServ = False
		SSO.finishGetUid = False
		SSO.finishShowUserInfo = False
		SSO.finishShowMoreUserInfo = False
		SSO.finishShowExtraUserInfo = False
		SSO.finishGetUid1 = False
		SSO.finishShowUserInfo1 = False
		SSO.finishShowMoreUserInfo1 = False
		SSO.finishShowExtraUserInfo1 = False
		SSO.finishGetAT = False
		SSO.finishRefreshAT = False
		SSO.traceOneFinished = False
		SSO.traceTwoFinished = True	
		if g_conf['policy']['level'] >= 1:	
			SSO.fuzzRPAppHandshakeRPServ = True
	elif IdP_Name == 'fb':
		SSO.initialized = False
		SSO.Eve_state = False
		SSO.IdP_App_Installed = True					
		SSO.IdP_Name = 'fb'	
		SSO.Eve_Auth_RP = False
		SSO.doubleRequests = True
		SSO.fuzzIdPAuthIdPApp = True
		SSO.fuzzIdPShowRPAppInfo = True
		SSO.fuzzEveIdP_Auth = True
		SSO.fuzzIdPAuthIdPApp1 = False
		SSO.fuzzIdPShowRPAppInfo1 = False
		SSO.fuzzEveIdP_Auth1 = False
		SSO.fuzzRPAppHandshakeRPServ = False
		SSO.fuzzGetUid = False
		SSO.fuzzShowUserInfo = True
		SSO.fuzzShowMoreUserInfo = True
		SSO.fuzzShowExtraUserInfo = True
		SSO.fuzzGetUid1 = False
		SSO.fuzzShowUserInfo1 = False
		SSO.fuzzShowMoreUserInfo1 = False
		SSO.fuzzShowExtraUserInfo1 = False
		SSO.fuzzGetAT = False
		SSO.fuzzRefreshAT = False
		SSO.finishIdPAuthIdPApp = False
		SSO.finishIdPShowRPAppInfo = False
		SSO.finishEveIdP_Auth = False
		SSO.finishIdPAuthIdPApp1 = False
		SSO.finishIdPShowRPAppInfo1 = False
		SSO.finishEveIdP_Auth1 = False
		SSO.finishRPAppHandshakeRPServ = False
		SSO.finishGetUid = False
		SSO.finishShowUserInfo = False
		SSO.finishShowMoreUserInfo = False
		SSO.finishShowExtraUserInfo = False
		SSO.finishGetUid1 = False
		SSO.finishShowUserInfo1 = False
		SSO.finishShowMoreUserInfo1 = False
		SSO.finishShowExtraUserInfo1 = False
		SSO.finishGetAT = False
		SSO.finishRefreshAT = False
		SSO.traceOneFinished = False
		SSO.traceTwoFinished = False
		if g_conf['policy']['level'] >= 1:
			SSO.fuzzIdPAuthIdPApp1 = True
			SSO.fuzzIdPShowRPAppInfo1 = True
			SSO.fuzzEveIdP_Auth1 = True	
			SSO.fuzzShowUserInfo1 = True
			SSO.fuzzShowMoreUserInfo1 = True
			SSO.fuzzShowExtraUserInfo1 = True
		if g_conf['policy']['level'] >= 2:
			SSO.fuzzRPAppHandshakeRPServ = True		

#Setup Proxy
class proxyMaster(flow.FlowMaster):
	def run(self):
		try:
			flow.FlowMaster.run(self)
		except KeyboardInterrupt:
			self.shutdown()
	
	@controller.handler
	def request(self, f):
		global globalCond
		global actionName
		global paraPool
		global enter
		global Hash
		global rpLock
		global refHash
		global idp_name
		global query_bk
		global text_bk
		global url_bk
		global cookie_bk
		global header_bk

		globalCond.acquire()
		ip_addr_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
		request_headers = [{"name": k, "value": v} for k, v in f.request.headers.items()]
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
		f.request.url = re.sub(ip_addr_regex, hostname, f.request.url) if hostname != '' else f.request.url

		if actionName == 'IdPAuthIdPAppRequ' or actionName == 'IdPAuthIdPApp1Requ' or \
		(actionName == 'RPAppHandshakeRPServRequ' and rpLock and extractor.extract_uri(f.request.url, False).lower() == paraPool['uri'].lower() and (Hash == '' or tools.RequestIndex(f, True) == Hash)) or \
		actionName == 'EveIdP_AuthRequ' or actionName == 'EveIdP_Auth1Requ' or actionName == 'IdPShowRPAppInfoRequ' or actionName == 'IdPShowRPAppInfo1Requ' or \
		(actionName == 'ShowUserInfoServRequ' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or \
		(actionName == 'ShowMoreUserInfoServRequ' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or \
		(actionName == 'ShowExtraUserInfoServRequ' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or \
		actionName == 'GetUidRequ' or (actionName == 'ShowUserInfoServ1Requ' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or \
		(actionName == 'ShowMoreUserInfoServ1Requ' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or (actionName == 'ShowExtraUserInfoServ1Requ' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or actionName == 'GetUid1Requ' or actionName == 'GetATRequ' or actionName == 'RefreshATRequ':
			uri = extractor.extract_uri(f.request.url, False)
			if paraPool['current']['name'] == '' or uri.lower() != paraPool['uri'].lower() or 'action' in paraPool['current']:
				pass
			elif 'order' in paraPool['current'] and paraPool['current']['order'] > 1:
				paraPool['current']['order'] -=1
			else:
				if actionName == 'RPAppHandshakeRPServRequ':
					rpLock = False
				enter = True
				query_bk = f.request.query
				text_bk = f.request.text
				url_bk = f.request.url
				cookie_bk = f.request.cookies
				header_bk = dict(f.request.headers)
				if paraPool['current']['mth'] == 'get':
					#paras = extractor.extract_parameters(f.request.url)
					#running_logger.info('Parsed get requests: '+str(paras))
					if paraPool['current']['name'] in f.request.query:
						running_logger.debug('Change Before {}'.format(str(f.request.query)))
						if paraPool['current']['operation'] == 'rm':
							tmpBuf = f.request.query.pop(paraPool['current']['name'])
						elif paraPool['current']['operation'] == 'ran':
							f.request.query[paraPool['current']['name']] = tools.checkTypeAlter(f.request.url, paraPool['current']['name'],  f.request.query[paraPool['current']['name']])
						elif paraPool['current']['operation'] == 'rep' or paraPool['current']['operation'] == 'rep1':
							f.request.query[paraPool['current']['name']] = paraPool['current']['value']
						#f.request.query[paraPool['get']] = uri + '?' + urllib.urlencode(paras)
						#Tell response I have changed the request, you can verify. Consider the case of same uri
						paraPool['current']['action'] = 'done'
						running_logger.debug('Change After {}'.format(str(f.request.query)))
					else:
						paraPool['current']['action'] = 'done'
						running_logger.info(paraPool['current']['name']+' not in '+f.request.url)
				if paraPool['current']['mth'] == 'post':
					if tools.isJson(f.request.text):
						paras = json.loads(f.request.text)
						if paraPool['current']['name'] in paras:
							if paraPool['current']['operation'] == 'rm':
								tmpBuf = paras.pop(paraPool['current']['name'])
							elif paraPool['current']['operation'] == 'ran':
								paras[paraPool['current']['name']] = tools.checkTypeAlter(f.request.url, paraPool['current']['name'], paras[paraPool['current']['name']])
							elif paraPool['current']['operation'] == 'rep' or paraPool['current']['operation'] == 'rep1':
								paras[paraPool['current']['name']] = paraPool['current']['value']
							running_logger.debug('Change Before {}'.format(str(f.request.text)))
							f.request.text = json.dumps(paras)
							paraPool['current']['action'] = 'done'
							running_logger.debug('Change After {}'.format(str(f.request.text)))
						else:
							paraPool['current']['action'] = 'done'
							running_logger.info(paraPool['current']['name']+' not in '+f.request.text)
					#content can be a string, like device_name=OnePlus-A0001&aid=01AuuOePuDnW4_O6XlUM-ckClBN1fyfJAUZzlRGo-UXfulnjo.&imei=864587020507548
					elif paraPool['current']['name'] in f.request.text:
						paraList = f.request.text.split('&')
						targetID = None
						for paraid in range(len(paraList)):
							if re.search(r'^'+paraPool['current']['name']+'=', paraList[paraid]) != None:
								targetID = paraid
								break
						if targetID != None:
							if paraPool['current']['operation'] == 'rm':
								paraList.pop(targetID)
							elif paraPool['current']['operation'] == 'ran':
								newVal = tools.checkTypeAlter(f.request.url, paraList[targetID].split('=')[0], paraList[targetID].split('=')[1])
								paraList[targetID] = paraPool['current']['name']+'='+newVal
							elif paraPool['current']['operation'] == 'rep' or paraPool['current']['operation'] == 'rep1':
								paraList[targetID] = paraPool['current']['name']+'='+paraPool['current']['value']
						running_logger.debug('Change Before {}'.format(str(f.request.text)))
						paraList = [x.encode('UTF8') for x in paraList]
						f.request.text = '&'.join(paraList)
						paraPool['current']['action'] = 'done'
						running_logger.debug('Change After {}'.format(str(f.request.text)))
					else:
						paraPool['current']['action'] = 'done'
						running_logger.info('Not a Json or parameter '+paraPool['current']['name']+' not exist in '+f.request.text+' for '+f.request.url)
				if paraPool['current']['mth'] == 'header':
					if paraPool['current']['name'] in f.request.headers:
						running_logger.debug('Change Before {}'.format(str(f.request.headers)))
						if paraPool['current']['operation'] == 'rm':
							tmpBuf = f.request.headers.pop(paraPool['current']['name'])
						elif paraPool['current']['operation'] == 'ran':
							f.request.headers[paraPool['current']['name']] = bytes(tools.checkTypeAlter(f.request.url, paraPool['current']['name'],  f.request.headers[paraPool['current']['name']], True))
						elif paraPool['current']['operation'] == 'rep' or paraPool['current']['operation'] == 'rep1':
							f.request.headers[paraPool['current']['name']] = bytes(paraPool['current']['value'])
						paraPool['current']['action'] = 'done'
						running_logger.debug('Change After {}'.format(str(f.request.headers)))
					else:
						paraPool['current']['action'] = 'done'
						running_logger.info(paraPool['current']['name']+' not in the header of '+f.request.url)
				if paraPool['current']['mth'] == 'cookie':
					if paraPool['current']['name'] in f.request.cookies:
						running_logger.debug('Change Before {}'.format(str(f.request.cookies)))
						if paraPool['current']['operation'] == 'rm':
							tmpBuf = f.request.cookies.pop(paraPool['current']['name'])
						elif paraPool['current']['operation'] == 'ran':
							f.request.cookies[paraPool['current']['name']] = bytes(tools.checkTypeAlter(f.request.url, paraPool['current']['name'],  f.request.cookies[paraPool['current']['name']]))
						elif paraPool['current']['operation'] == 'rep' or paraPool['current']['operation'] == 'rep1':
							f.request.cookies[paraPool['current']['name']] = bytes(paraPool['current']['value'])
						paraPool['current']['action'] = 'done'
						running_logger.debug('Change After {}'.format(str(f.request.cookies)))
					else:
						paraPool['current']['action'] = 'done'
						running_logger.info(paraPool['current']['name']+' not in the cookie of '+f.request.url)
				if paraPool['current']['mth'] == 'hybrid':
					#pdb.set_trace()
					reqCounter = 0
					for paraName, paraRepVal in zip(paraPool['current']['name'].split('^v^'), paraPool['current']['value'].split('^v^')):
						reqOperation = paraPool['current']['operation'][reqCounter]
						pmth = 'get'
						if '^_^' in paraName:
							pmth = 'post'
							paraName = paraName.replace('^_^', '')
						elif '=_=' in paraName:
							pmth = 'header'
							paraName = paraName.replace('=_=', '')
						elif '-=-' in paraName:
							pmth = 'cookie'
							paraName = paraName.replace('-=-', '')
						if pmth == 'get':
							if paraName in f.request.query:
								running_logger.debug('Change Before {}'.format(str(f.request.query)))
								if reqOperation == 'rm':
									tmpBuf = f.request.query.pop(paraName)
								elif reqOperation == 'ran':
									f.request.query[paraName] = tools.checkTypeAlter(f.request.url, paraName,  f.request.query[paraName])
								elif reqOperation == 'rep' or reqOperation == 'rep1':
									f.request.query[paraName] = paraRepVal
								running_logger.debug('Change After {}'.format(str(f.request.query)))
							else:
								running_logger.info(paraName +' not in '+f.request.url)
						elif pmth == 'post':
							if tools.isJson(f.request.text):
								paras = json.loads(f.request.text)
								if paraName in paras:
									if reqOperation == 'rm':
										tmpBuf = paras.pop(paraName)
									elif reqOperation == 'ran':
										paras[paraName] = tools.checkTypeAlter(f.request.url, paraName, paras[paraName])
									elif reqOperation == 'rep' or reqOperation == 'rep1':
										paras[paraName] = paraRepVal
									running_logger.debug('Change Before {}'.format(str(f.request.text)))
									f.request.text = json.dumps(paras)
									running_logger.debug('Change After {}'.format(str(f.request.text)))
								else:
									running_logger.info(paraName +' not in '+f.request.text)
							#content can be a string, like device_name=OnePlus-A0001&aid=01AuuOePuDnW4_O6XlUM-ckClBN1fyfJAUZzlRGo-UXfulnjo.&imei=864587020507548
							elif paraName in f.request.text:
								paraList = f.request.text.split('&')
								targetID = None
								for paraid in range(len(paraList)):
									if re.search(r'^'+paraName+'=', paraList[paraid]) != None:
										targetID = paraid
										break
								if targetID != None:
									if reqOperation == 'rm':
										paraList.pop(targetID)
									elif reqOperation == 'ran':
										newVal = tools.checkTypeAlter(f.request.url, paraList[targetID].split('=')[0], paraList[targetID].split('=')[1])
										paraList[targetID] = paraName+'='+newVal
									elif reqOperation == 'rep' or reqOperation == 'rep1':
										paraList[targetID] = paraName+'='+ paraRepVal
								running_logger.debug('Change Before {}'.format(str(f.request.text)))
								paraList = [x.encode('UTF8') for x in paraList]
								f.request.text = '&'.join(paraList)
								running_logger.debug('Change After {}'.format(str(f.request.text)))
							else:
								running_logger.info('Not a Json or parameter '+paraName+' not exist in '+f.request.text+' for '+f.request.url)
						elif pmth == 'header':
							if paraName in f.request.headers:
								running_logger.debug('Change Before {}'.format(str(f.request.headers)))
								if reqOperation == 'rm':
									tmpBuf = f.request.headers.pop(paraName)
								elif reqOperation == 'ran':
									f.request.headers[paraName] = bytes(tools.checkTypeAlter(f.request.url, paraName,  f.request.headers[paraName], True))
								elif reqOperation == 'rep' or reqOperation == 'rep1':
									f.request.headers[paraName] = bytes(paraRepVal)
								running_logger.debug('Change After {}'.format(str(f.request.headers)))
							else:
								running_logger.info(paraName +' not in the header of '+f.request.url)
						elif pmth == 'cookie':
							if paraName in f.request.cookies:
								running_logger.debug('Change Before {}'.format(str(f.request.cookies)))
								if reqOperation == 'rm':
									tmpBuf = f.request.cookies.pop(paraName)
								elif reqOperation == 'ran':
									f.request.cookies[paraName] = bytes(tools.checkTypeAlter(f.request.url, paraName,  f.request.cookies[paraName]))
								elif reqOperation == 'rep' or reqOperation == 'rep1':
									f.request.cookies[paraName] = bytes(paraRepVal)
								running_logger.debug('Change After {}'.format(str(f.request.cookies)))
							else:
								running_logger.info(paraName +' not in the cookie of '+f.request.url)
						reqCounter = reqCounter + 1
					paraPool['current']['action'] = 'done'

		elif actionName == 'response':
			pass

		globalCond.release()

	@controller.handler
	def response(self, f):
		global globalCond
		global appiumCond
		global appiumSignal
		global actionName
		global paraPool
		global requParaPool
		global enter
		global aliceAT
		global aliceAT1
		global extraAT
		global idp_name
		global code
		global ui_support
		global refURL
		global refLocation
		global refAlice
		global refEve
		global refHash
		global refOrder
		global counter
		global Hash
		global rpLock
		global query_bk
		global text_bk
		global url_bk
		global cookie_bk
		global header_bk

		globalCond.acquire()
		running_logger.debug("get response from {}".format(f.request.url))
		#	reset the counter
		if actionName != 'Initialize':
			if idp_name == 'sina' and 'api.weibo.com/oauth2/sso_authorize' in f.request.url and 'access_token' in json.loads(f.response.content):
				counter = refOrder
				if 'result' in paraPool:
					paraPool.pop('result', None)
				if actionName == 'RPAppHandshakeRPServRequ' or actionName == 'RPAppHandshakeRPServResp':
					rpLock = True
					running_logger.debug('change rpLock')
			elif idp_name == 'wechat' and ('open.weixin.qq.com/connect/oauth2/authorize_reply' in f.request.url or 'sz.open.weixin.qq.com/connect/oauth2/authorize_reply' in f.request.url or 'api.weixin.qq.com/sns/oauth2/access_token' in f.request.url):
				counter = refOrder
				if 'result' in paraPool:
					paraPool.pop('result', None)
				if actionName == 'RPAppHandshakeRPServRequ' or actionName == 'RPAppHandshakeRPServResp':
					rpLock = True
					running_logger.debug('change rpLock')
			elif idp_name == 'fb' and (re.search('m.facebook.com/v(.*)/dialog/oauth/confirm', f.request.url) or re.search('m.facebook.com/v(.*)/dialog/oauth/read', f.request.url)):
				counter = refOrder
				if 'result' in paraPool:
					paraPool.pop('result', None)
				if actionName == 'RPAppHandshakeRPServRequ' or actionName == 'RPAppHandshakeRPServResp':
					rpLock = True
					running_logger.debug('change rpLock')

		def check_error_code(idp, url, flow):
			if idp == 'sina':
				if 'weibo' in url:
					try:
						if re.match(r'\{.*\:\{.*\:.*\}\}', flow.response.content):
							data = json.loads(flow.response.content)
							if 'error_code' in data and str(data['error_code']) == '10023':
								running_logger.error('idp api encounter rate limit!')
								error_exit()
					except Exception:
						running_logger.exception("Exception in loading response content of weibo api, url: {}, reponse: {}".format(url, flow.response.content))
			elif idp == 'wechat':
				pass
			elif idp == 'fb':
				pass
			else:
				running_logger.debug('skip, unknown idp')
					
		# todo: refactor error code checking function, can change the parameter to some variable later
		check_error_code(idp_name, f.request.url ,f)
		if actionName == 'Initialize':
			pass

		#Verify the response after changing request parameters
		#If there is an error, try fuzzing in the proxy side
		if (actionName == 'IdPAuthIdPAppRequ' or actionName == 'IdPAuthIdPApp1Requ' or actionName == 'EveIdP_AuthRequ' or actionName == 'EveIdP_Auth1Requ' or actionName == 'IdPShowRPAppInfoRequ' or actionName == 'IdPShowRPAppInfo1Requ' or actionName == 'ShowUserInfoServRequ' or actionName == 'ShowMoreUserInfoServRequ' or actionName == 'ShowExtraUserInfoServRequ' or actionName == 'GetUidRequ' or actionName == 'ShowUserInfoServ1Requ' or actionName == 'ShowMoreUserInfoServ1Requ' or actionName == 'ShowExtraUserInfoServ1Requ' or actionName == 'GetUid1Requ' or actionName == 'GetATRequ' or actionName == 'RefreshATRequ') and 'action' in paraPool['current'] and 'result' not in paraPool and 'error' not in paraPool['current']:
			uri = extractor.extract_uri(f.request.url, False)
			if uri.lower() != paraPool['uri'].lower():
				pass 
			else:
				try:
					if (idp_name == 'fb' and (actionName == 'EveIdP_AuthRequ' or actionName == 'EveIdP_Auth1Requ')) or tools.isJson(f.response.content):
						if idp_name == 'fb' and (actionName == 'EveIdP_AuthRequ' or actionName == 'EveIdP_Auth1Requ'):
							data = tools.decoupleFBResponse(f.response.content)[1]
						elif tools.isJson(f.response.content):						
							data = json.loads(f.response.content)
						for k in data:
							if ('error' in k or 'errcode' in k or 'errmsg' in k) and (isinstance(data[k], str) or isinstance(data[k], int) or isinstance(data[k], unicode)) and str(data[k]).strip() != '':
								paraPool['current']['error'] = 'yes'
								if g_conf["snapshot"] != "True":
									rpActions.writeResult(False)
									p = psutil.Process(testing.process.pid)
									p.terminate()
									tools.removeLockFiles()
								break					
					else:
						data = str(f.response.content)
						if 'error' in data or 'errcode' in data or 'errmsg' in data:
							paraPool['current']['error'] = 'yes'
							if g_conf["snapshot"] != "True":
								rpActions.writeResult(False)
								p = psutil.Process(testing.process.pid)
								p.terminate()
								tools.removeLockFiles()							
				except Exception:
					paraPool['current']['error'] = 'yes'
					if g_conf["snapshot"] != "True":
						try:
							rpActions.writeResult(False)
							p = psutil.Process(testing.process.pid)
							p.terminate()
							tools.removeLockFiles()
						except Exception:
							pass
					
				appiumCond.acquire()
				if 'error' in paraPool['current']:
					running_logger.debug('Error detected in response!')
					keepFuz = True
					appiumSignal = 'Break'
					#Keep fuzz until get normal response
					wantedUri = paraPool['uri']
					if idp_name == 'sina':
						if actionName == 'EveIdP_AuthRequ':
							wantedUri += '+'
						if actionName == 'IdPShowRPAppInfo1Requ':
							wantedUri += '++'
						if actionName == 'IdPAuthIdPApp1Requ':
							wantedUri += '+'
						if actionName == 'EveIdP_Auth1Requ':
							wantedUri += '+++'
						if actionName == 'GetUid1Requ':
							wantedUri += '+'
						if actionName == 'ShowUserInfoServ1Requ':
							wantedUri += '+'
					elif idp_name == 'fb':
						if actionName == 'ShowUserInfoServRequ':
							wantedUri = g_conf['modelMap']['fb']['ShowUserInfo']
						elif actionName == 'ShowMoreUserInfoServRequ':
							wantedUri = g_conf['modelMap']['fb']['ShowMoreUserInfo']
						elif actionName == 'ShowExtraUserInfoServRequ':
							wantedUri = g_conf['modelMap']['fb']['ShowExtraUserInfo']						
						elif actionName == 'ShowUserInfoServ1Requ':
							wantedUri = g_conf['modelMap']['fb']['ShowUserInfo1']
						elif actionName == 'ShowMoreUserInfoServ1Requ':
							wantedUri = g_conf['modelMap']['fb']['ShowMoreUserInfo1']
						elif actionName == 'ShowExtraUserInfoServ1Requ':
							wantedUri = g_conf['modelMap']['fb']['ShowExtraUserInfo1']
						else:
							wantedUri = g_conf['modelMap']['fb'][actionName[0:-4]]
					result_logger.info('Error caused: Apply '+paraPool['current']['mth']+' on '+paraPool['current']['name']+' for url '+ wantedUri)
					for mth in requParaPool[wantedUri]:
						for paras in requParaPool[wantedUri][mth]:
							varName = ''
							repVal = ''
							operations = []
							if paras.keys()[0] == 'replacedValue':
								varName = paras.keys()[1]
								operations = paras.values()[1]
								repVal = paras.values()[0]
							else:
								varName = paras.keys()[0]
								operations = paras.values()[0]
								if 'replacedValue' in paras:
									repVal = paras.values()[1]
							newOpr = copy.deepcopy(operations)
							for opr in operations:
								#Alread testedwantedUri
								if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
									continue

								isExtra = False
								if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
									isExtra = True
									if isinstance(opr, list) and 'rep1' in opr:
										opr = ['rep'] * len(opr)
									else:
										opr = 'rep'
									
								#If its current, since it's error, update operation
								if varName == paraPool['current']['name'] and mth == paraPool['current']['mth'] and opr == paraPool['current']['operation'] and 'error' in paraPool['current']:
									try:
										newOpr.pop(newOpr.index(opr))
									except Exception:
										pass
									if varName not in paraPool['tested'][mth]:
										paraPool['tested'][mth][varName] = [opr]
									else:
										paraPool['tested'][mth][varName].append(opr)
									continue
								
								try:
									presult = tools.proxyFuzzy(url_bk, mth, opr, varName, repVal, query_bk, text_bk, header_bk, cookie_bk)
								except Exception:
									raise
									presult = 'Error'
								
								if presult == 'Error':
									if isExtra:
										if opr == 'rep':
											opr == 'rep1'
										elif isinstance(opr, list):
											opr = ['rep1'] * len(opr)
									running_logger.warn('Continue with variable name: {} and operation: {}'.format(varName, opr))
									tools.writeTested(wantedUri, 'request', mth, varName, opr, last=False)
									tools.writeRedundant(wantedUri, 'request', mth, varName, opr)
									result_logger.info('Error caused: Apply '+mth+' on '+varName+' for url '+ wantedUri)								
									try:
										newOpr.pop(newOpr.index(opr))
									except Exception:
										pass
									if varName not in paraPool['tested'][mth]:
										paraPool['tested'][mth][varName] = [opr]
									else:
										paraPool['tested'][mth][varName].append(opr)
								else:
									#Get a normal response
									keepFuz = False
									break
										
							paras[varName] = newOpr
							if not keepFuz:
								break
						if not keepFuz:
							break
					
					#Fail the response
					f.response.status_code = 500
					f.response.content = ''
				else:
					appiumSignal = 'Go'
				appiumCond.notify_all()
				appiumCond.release()
		
		running_logger.debug('before checking block, f.request.url:{}, refURL in f.request.url: {}, tools.RequestIndex(f, True): {}, tools.RequestIndex(f, True) == refHash, {}'.format(f.request.url, refURL in f.request.url, tools.RequestIndex(f, True), tools.RequestIndex(f, True) == refHash))
		#Verify result for changing response and changing RP request/response
		if (( (actionName == 'IdPAuthIdPAppResp' or actionName == 'IdPAuthIdPApp1Resp' or actionName == 'RPAppHandshakeRPServResp' or actionName == 'EveIdP_AuthResp' or actionName == 'EveIdP_Auth1Resp' or actionName == 'IdPShowRPAppInfoResp' or actionName == 'IdPShowRPAppInfo1Resp' or actionName == 'ShowUserInfoServResp' or actionName == 'ShowMoreUserInfoServResp' or actionName == 'ShowExtraUserInfoServResp' or actionName == 'GetUidResp' or actionName == 'ShowUserInfoServ1Resp' or actionName == 'ShowMoreUserInfoServ1Resp' or actionName == 'ShowExtraUserInfoServ1Resp' or actionName == 'GetUid1Resp' or actionName == 'GetATResp' or actionName == 'RefreshATResp') \
			and 'result' not in paraPool) or \
			( (actionName == 'IdPAuthIdPAppRequ' or actionName == 'IdPAuthIdPApp1Requ' or actionName == 'RPAppHandshakeRPServRequ' or actionName == 'EveIdP_AuthRequ' or actionName == 'EveIdP_Auth1Requ' or actionName == 'IdPShowRPAppInfoRequ' or actionName == 'IdPShowRPAppInfo1Requ' or actionName == 'ShowUserInfoServRequ' or actionName == 'ShowMoreUserInfoServRequ'or actionName == 'ShowExtraUserInfoServRequ' or actionName == 'GetUidRequ' or actionName == 'ShowUserInfoServ1Requ' or actionName == 'ShowMoreUserInfoServ1Requ' or actionName == 'ShowExtraUserInfoServ1Requ' or actionName == 'GetUid1Requ' or actionName == 'GetATRequ' or actionName == 'RefreshATRequ') \
			and 'result' not in paraPool)) and not ui_support and refURL in f.request.url and (refHash == '' or tools.RequestIndex(f, True) == refHash):
				running_logger.debug('before checking counter: {}'.format(counter))
				if counter > 1:
					counter = counter - 1
				elif counter == 1:
					running_logger.debug('Enter verification block!')
					counter = 0
					if idp_name == 'fb' and 'www.googleapis.com/identitytoolkit/v3/relyingparty/verifyAssertion' in refURL:
						if refAlice in str(f.response.content):
							paraPool['result'] = 'Alice'
						elif refEve in str(f.response.content):
							paraPool['result'] = 'Eve'
						elif 'error' not in str(f.response.content).lower():
							paraPool['result'] = 'Others'
					else:
						try:
							data = json.loads(f.response.content)
							observation = tools.extractValue(refLocation, data)
							if observation == refAlice:
								paraPool['result'] = 'Alice'
							elif observation == refEve:
								paraPool['result'] = 'Eve'
							elif observation != None and 'error' not in str(observation).lower():
								paraPool['result'] = 'Others'
						except Exception:
							pass
					if g_conf["snapshot"] != "True":
						try:
							rpActions.writeResult(True)
							p = psutil.Process(testing.process.pid)
							p.terminate()
							tools.removeLockFiles()
						except Exception:
							pass
					
				else:
					pass
			# todo: this part check the user info from network trace, may use para from ronghai's code later  
			# if uri != 'https://passport.amap.com/ws/pp/provider/login/weibo':
			# 	pass
			# else:
			# 	try:
			# 		data = json.loads(f.response.content)
			# 		if str(data['data']['username']) == '40539849':
			# 			paraPool['result'] = False
			# 		else:
			# 			paraPool['result'] = True
			# 	except Exception:
			# 		paraPool['result'] = False

		#Get access token
		if actionName != 'Initialize':
			uri = extractor.extract_uri(f.request.url, False)
			# refactor: revoke access token 
			if uri == 'api.weibo.com/oauth2/sso_authorize':
				try:
					data = json.loads(f.response.content)
					if 'access_token' in data and str(data['access_token']) != aliceAT and str(data['access_token']) != extraAT:
						running_logger.info('Write into access_token')
						paraPool['access_token'] = data['access_token']
				except Exception:
					pass
			elif "api.weixin.qq.com/sns/oauth2/access_token" in f.request.url or "api.weixin.qq.com/sns/oauth2/refresh_token" in f.request.url:
				try:
					data = json.loads(f.response.content)
					if 'access_token' in data:
						running_logger.info('Write into access_token')
						paraPool['access_token'] = data['access_token']
				except Exception:
					pass
			elif re.search('m.facebook.com/v(.*)/dialog/oauth/confirm', f.request.url) or re.search('m.facebook.com/v(.*)/dialog/oauth/read', f.request.url):
				try:
					tempAT = tools.getFBResponseValue(f.response.content, 'access_token')
					if tempAT != aliceAT and tempAT != aliceAT1 and tempAT != extraAT and tempAT is not None:
						paraPool['access_token'] = tempAT
						running_logger.info('Write into access_token')
				except Exception:
					pass					

		#Access token disclosure
		if actionName != 'Initialize':
			uriNetLoc = extractor.extract_netloc(f.request.url)
			try:
				if g_appinfo['appNetloc'] in uriNetLoc.lower() and 'access_token' in paraPool and paraPool['access_token'] != '' and f.request.scheme.lower() == 'http' and 'access_token' in paraPool and \
				(paraPool['access_token'] in str(f.response.content) or paraPool['access_token'] in f.request.text or paraPool['access_token'] in f.request.url or \
				'access_token' in f.response.content or 'access_token' in f.request.text or 'access_token' in f.request.url):
					result_logger.error('Access token disclosure in uri '+extractor.extract_uri(f.request.url))
			except Exception:
				pass
		#client secret disclosure
		if actionName != 'Initialize':
			try:
				if 'client_secret' in f.request.text or 'client_secret' in f.request.url or 'client_secret' in f.response.content:
					result_logger.error('Client secret disclosure in uri '+extractor.extract_uri(f.request.url))
			except Exception:
				pass
		
		#Get code
		if actionName != 'Initialize':
			if "open.weixin.qq.com/connect/oauth2/authorize_reply" in f.request.url:
				try:
					data = urlparse(f.response.headers['Location'])
					code = parse_qs(data.query)['code'][0]
					running_logger.info('Write into CODE')
				except Exception:
					pass

		#Code disclosure
		if actionName != 'Initialize':
			try:
				if code != '' and f.request.scheme.lower() == 'http' and (code in str(f.response.content) or code in f.request.text or code in f.request.url or 'code' in str(f.response.content) or 'code' in f.request.text or 'code' in f.request.url):
					result_logger.error('Code disclosure in uri '+extractor.extract_uri(f.request.url))
			except Exception:
				pass

		#Change response parameters
		if (actionName == 'IdPAuthIdPAppResp' or actionName == 'IdPAuthIdPApp1Resp' or (actionName == 'RPAppHandshakeRPServResp' and rpLock and (Hash == '' or tools.RequestIndex(f, True) == Hash)) or actionName == 'EveIdP_AuthResp' or actionName == 'EveIdP_Auth1Resp' or actionName == 'IdPShowRPAppInfoResp' or actionName == 'IdPShowRPAppInfo1Resp' or (actionName == 'ShowUserInfoServResp' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or (actionName == 'ShowMoreUserInfoServResp' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or (actionName == 'ShowExtraUserInfoServResp' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or actionName == 'GetUidResp' or (actionName == 'ShowUserInfoServ1Resp' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or (actionName == 'ShowMoreUserInfoServ1Resp' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or (actionName == 'ShowExtraUserInfoServ1Resp' and (idp_name != 'fb' or (idp_name == 'fb' and Hash == tools.getFBGraphHash(f)))) or actionName == 'GetUid1Resp' or actionName == 'GetATResp' or actionName == 'RefreshATResp') \
			and 'action' not in paraPool:
			appiumCond.acquire()
			appiumSignal = 'Go'
			appiumCond.notify_all()
			appiumCond.release()
			if len(paraPool) != 0 and 'action' not in paraPool:
				uri = extractor.extract_uri(f.request.url, False)
				if uri in paraPool:
					if 'order' in paraPool and paraPool['order'] > 1:
						paraPool['order'] -= 1
					else:
						if actionName == 'RPAppHandshakeRPServResp':
							rpLock = False
						enter = True
						paths = copy.deepcopy(paraPool[uri])
						try:
							if paths[0] != "hybrid" and paths[0] != "header" and paths[0] != "cookie":
								if idp_name == 'fb' and (actionName == 'EveIdP_AuthResp' or actionName == 'EveIdP_Auth1Resp'):
									[prefix, tmpParaList, suffix, tmpOrder] = tools.decoupleFBResponse(f.response.content)
									alterValue = paths.pop(-1)
									tmpKey = paths[0]
									if paraPool['operation'] == 'rm':
										tmpParaList.pop(tmpKey, None)
									elif paraPool['operation'] == 'ran':
										alterValue = tools.checkTypeAlter(f.request.url, paraPool[uri], alterValue)
										tmpParaList[tmpKey] = alterValue
									elif paraPool['operation'] == 'rep' or paraPool['operation'] == 'rep1':
										tmpParaList[tmpKey] = alterValue
									paraPool['action'] = 'done'
									running_logger.debug('Change Before {}'.format(str(f.response.content)))
									f.response.content = str(tools.constructFBResponse(prefix, tmpParaList, suffix, tmpOrder))
									running_logger.debug('Change After {}'.format(str(f.response.content)))
								elif idp_name == 'fb' and (actionName == 'IdPAuthIdPAppResp' or actionName == 'IdPAuthIdPApp1Resp'):
									prefix = 'for (;;);'
									data = json.loads(f.response.content[9:])
									tmpD = data
									alterValue = paths.pop(-1)
									if paraPool['operation'] == 'rm':
										alterValue = None
									elif paraPool['operation'] == 'ran':
										alterValue = tools.checkTypeAlter(f.request.url, paraPool[uri], alterValue)
									paraExist = True
									for pid in range(len(paths)):
										if paths[pid] not in tmpD and type(tmpD) is dict:
											paraExist = False
											break
										elif type(tmpD) is list and paths[pid] >= len(tmpD):
											paraExist = False
											break
										if pid == len(paths)-1:
											if alterValue == None:
												if isinstance(tmpD, dict): 
													tmpBuf = tmpD.pop(paths[pid], None)
												elif isinstance(tmpD, list):
													tmpBuf = tmpD.pop(paths[pid])

											else:
												tmpD[paths[pid]] = alterValue
										else:
											tmpD = tmpD[paths[pid]]
									paraPool['action'] = 'done'
									if paraExist:
										running_logger.debug('Change Before {}'.format(str(f.response.content)))
										f.response.content = prefix + json.dumps(data)
										running_logger.debug('Change After {}'.format(str(f.response.content)))
								elif tools.isJson(f.response.content):
									data = json.loads(f.response.content)
									tmpD = data
									alterValue = paths.pop(-1)
									if paraPool['operation'] == 'rm':
										alterValue = None
									elif paraPool['operation'] == 'ran':
										alterValue = tools.checkTypeAlter(f.request.url, paraPool[uri], alterValue)
									paraExist = True
									for pid in range(len(paths)):
										if paths[pid] not in tmpD and type(tmpD) is dict:
											paraExist = False
											break
										elif type(tmpD) is list and paths[pid] >= len(tmpD):
											paraExist = False
											break
										if pid == len(paths)-1:
											if alterValue == None:
												tmpBuf = tmpD.pop(paths[pid], None)
											else:
												tmpD[paths[pid]] = alterValue
										else:
											tmpD = tmpD[paths[pid]]
									paraPool['action'] = 'done'
									if paraExist:
										running_logger.debug('Change Before {}'.format(str(f.response.content)))
										f.response.content = json.dumps(data)
										running_logger.debug('Change After {}'.format(str(f.response.content)))
								elif tools.isHTML(f.response.content) or len(paths) == 1:
									alterValue = paths[0]
									if paraPool['operation'] == 'rm':
										alterValue = None
									elif paraPool['operation'] == 'ran':
										alterValue = tools.checkTypeAlter(f.request.url, paraPool[uri], alterValue)
									paraPool['action'] = 'done'
									running_logger.debug('Change Before {}'.format(str(f.response.content)))
									if alterValue == None:
										f.response.content = alterValue
									else:
										f.response.content = alterValue.encode('utf8')
									running_logger.debug('Change After {}'.format(str(f.response.content)))
							elif paths[0] == "header":
								if idp_name == 'wechat' and actionName == 'EveIdP_AuthResp' and paths[1] == 'Location':
									paraName = paths[2]
									alterValue = paths[3]
									if paraPool['operation'] == 'rm':
										alterValue = None
									elif paraPool['operation'] == 'ran':
										alterValue = tools.checkTypeAlter(f.request.url, paraName, alterValue, True)
									prefix = f.response.headers['Location'].split('?')[0] + '?'
									if paraName == 'code':
										if alterValue == None:
											content = prefix + f.response.headers['Location'].split('?')[1].split('&')[1]
										else:
											content = prefix + 'code=' + alterValue + '&' + f.response.headers['Location'].split('?')[1].split('&')[1]
									elif paraName == 'state':
										if alterValue == None:
											content = prefix + f.response.headers['Location'].split('?')[1].split('&')[0]
										else:
											content = prefix + f.response.headers['Location'].split('?')[1].split('&')[0] + '&' + 'state=' + alterValue
									paraPool['action'] = 'done'
									running_logger.debug('Change Before {}'.format(str(f.response.headers)))
									f.response.headers['Location'] = bytes(content)
									running_logger.debug('Change After {}'.format(str(f.response.headers)))
								else:
									paraName = paths[1]
									alterValue = paths[2]
									if paraName in f.response.headers:
										if paraPool['operation'] == 'rm':
											alterValue = None
										elif paraPool['operation'] == 'ran':
											alterValue = tools.checkTypeAlter(f.request.url, paraName, alterValue, True)
										paraPool['action'] = 'done'
										running_logger.debug('Change Before {}'.format(str(f.response.headers)))
										if alterValue == None:
											f.response.headers.pop(paraName)
										else:
											f.response.headers[paraName] = bytes(alterValue)
										running_logger.debug('Change After {}'.format(str(f.response.headers)))
									else:
										paraPool['action'] = 'done'
										running_logger.info(paraName+' not in the response header of '+f.request.url)
							elif paths[0] == "cookie":
								paraName = paths[1]
								alterValue = paths[2]
								if paraName in f.response.cookies:
									if paraPool['operation'] == 'rm':
										alterValue = None
									elif paraPool['operation'] == 'ran':
										alterValue = tools.checkTypeAlter(f.request.url, paraName, alterValue)
									paraPool['action'] = 'done'
									running_logger.debug('Change Before {}'.format(str(f.response.cookies)))
									if alterValue == None:
										f.response.cookies.pop(paraName)
									else:
										if 'SetCookie' in str(f.response.cookies[paraName]):
											f.response.cookies[paraName] = f.response.cookies[paraName]._replace(value=bytes(alterValue))
										else:
											f.response.cookies[paraName] = bytes(alterValue)
									running_logger.debug('Change After {}'.format(str(f.response.cookies)))
								else:
									paraPool['action'] = 'done'
									running_logger.info(paraName+' not in the response cookie of '+f.request.url)
							elif paths[0] == "hybrid":
								respCounter = 0
								for i in range(1, len(paths)):
									respOperation = paraPool['operation'][respCounter]
									currentPath = paths[i]
									if isinstance(currentPath, list) and currentPath[0] == 'text':
										currentPath.pop(0)
									if isinstance(currentPath, list) and currentPath[0] == 'header':
										if idp_name == 'wechat' and actionName == 'EveIdP_AuthResp' and currentPath[1] == 'Location':
											paraName = currentPath[2]
											alterValue = currentPath[3]
											if respOperation == 'rm':
												alterValue = None
											elif respOperation == 'ran':
												alterValue = tools.checkTypeAlter(f.request.url, paraName, alterValue, True)
											prefix = f.response.headers['Location'].split('?')[0] + '?'
											if paraName == 'code':
												if alterValue == None:
													if 'state' in f.response.headers['Location']:
														content = prefix + f.response.headers['Location'].split('?')[1].split('&')[1]
													else:
														content = prefix
												else:
													if 'state' in f.response.headers['Location']:
														content = prefix + 'code=' + alterValue + '&' + f.response.headers['Location'].split('?')[1].split('&')[1]
													else:
														content = prefix + 'code=' + alterValue
											elif paraName == 'state':
												if alterValue == None:
													if 'code' in f.response.headers['Location']:
														content = prefix + f.response.headers['Location'].split('?')[1].split('&')[0]
													else:
														content = prefix
												else:
													if 'code' in f.response.headers['Location']:
														content = prefix + f.response.headers['Location'].split('?')[1].split('&')[0] + '&' + 'state=' + alterValue
													else:
														content = prefix + 'state=' + alterValue
											running_logger.debug('Change Before {}'.format(str(f.response.headers)))
											f.response.headers['Location'] = bytes(content)
											running_logger.debug('Change After {}'.format(str(f.response.headers)))
										else:
											paraName = currentPath[1]
											alterValue = currentPath[2]
											if paraName in f.response.headers:
												if respOperation == 'rm':
													alterValue = None
												elif respOperation == 'ran':
													alterValue = tools.checkTypeAlter(f.request.url, paraName, alterValue, True)
												running_logger.debug('Change Before {}'.format(str(f.response.headers)))
												if alterValue == None:
													f.response.headers.pop(paraName)
												else:
													f.response.headers[paraName] = bytes(alterValue)
												running_logger.debug('Change After {}'.format(str(f.response.headers)))
											else:
												running_logger.info(paraName+' not in the response header of '+f.request.url)
									elif isinstance(currentPath, list) and currentPath[0] == 'cookie':
										paraName = currentPath[1]
										alterValue = currentPath[2]
										if paraName in f.response.cookies:
											if respOperation == 'rm':
												alterValue = None
											elif respOperation == 'ran':
												alterValue = tools.checkTypeAlter(f.request.url, paraName, alterValue)
											running_logger.debug('Change Before {}'.format(str(f.response.cookies)))
											if alterValue == None:
												f.response.cookies.pop(paraName)
											else:
												if 'SetCookie' in str(f.response.cookies[paraName]):
													f.response.cookies[paraName] = f.response.cookies[paraName]._replace(value=bytes(alterValue))
												else:
													f.response.cookies[paraName] = bytes(alterValue)		
											running_logger.debug('Change After {}'.format(str(f.response.cookies)))
										else:
											running_logger.info(paraName+' not in the response cookie of '+f.request.url)
									elif idp_name == 'fb' and (actionName == 'EveIdP_AuthResp' or actionName == 'EveIdP_Auth1Resp') and currentPath[0] != 'cookie' and currentPath[0] != 'header':
										[prefix, tmpParaList, suffix, tmpOrder] = tools.decoupleFBResponse(f.response.content)
										alterValue = currentPath.pop(-1)
										tmpKey = currentPath[0]
										if respOperation == 'rm':
											tmpParaList.pop(tmpKey, None)
										elif respOperation == 'ran':
											alterValue = tools.checkTypeAlter(f.request.url, currentPath, alterValue)
											tmpParaList[tmpKey] = alterValue
										elif respOperation == 'rep' or respOperation == 'rep1':
											tmpParaList[tmpKey] = alterValue
										running_logger.debug('Change Before {}'.format(str(f.response.content)))
										f.response.content = str(tools.constructFBResponse(prefix, tmpParaList, suffix, tmpOrder))
										running_logger.debug('Change After {}'.format(str(f.response.content)))
									elif idp_name == 'fb' and (actionName == 'IdPAuthIdPAppResp' or actionName == 'IdPAuthIdPApp1Resp') and currentPath[0] != 'cookie' and currentPath[0] != 'header':
										prefix = 'for (;;);'
										data = json.loads(f.response.content[9:])
										tmpD = data
										alterValue = currentPath.pop(-1)
										if respOperation == 'rm':
											alterValue = None
										elif respOperation == 'ran':
											alterValue = tools.checkTypeAlter(f.request.url, currentPath, alterValue)
										paraExist = True 
										for pid in range(len(currentPath)):
											if currentPath[pid] not in tmpD and type(tmpD) is dict:
												paraExist = False
												break
											elif type(tmpD) is list and currentPath[pid] >= len(tmpD):
												paraExist = False
												break
											if pid == len(currentPath)-1:
												if alterValue == None:
													tmpBuf = tmpD.pop(currentPath[pid], None)
												else:
													tmpD[currentPath[pid]] = alterValue												
											else:
												tmpD = tmpD[currentPath[pid]]
										if paraExist:
											running_logger.debug('Change Before {}'.format(str(f.response.content)))
											f.response.content = prefix + json.dumps(data)
											running_logger.debug('Change After {}'.format(str(f.response.content)))								
									elif tools.isJson(f.response.content):
										data = json.loads(f.response.content)
										tmpD = data
										alterValue = currentPath.pop(-1)
										if respOperation == 'rm':
											alterValue = None
										elif respOperation == 'ran':
											alterValue = tools.checkTypeAlter(f.request.url, currentPath, alterValue)
										paraExist = True 
										for pid in range(len(currentPath)):
											if currentPath[pid] not in tmpD and type(tmpD) is dict:
												paraExist = False
												break
											elif type(tmpD) is list and currentPath[pid] >= len(tmpD):
												paraExist = False
												break
											if pid == len(currentPath)-1:
												if alterValue == None:
													tmpBuf = tmpD.pop(currentPath[pid], None)
												else:
													tmpD[currentPath[pid]] = alterValue												
											else:
												tmpD = tmpD[currentPath[pid]]
										if paraExist:
											running_logger.debug('Change Before {}'.format(str(f.response.content)))
											f.response.content = json.dumps(data)
											running_logger.debug('Change After {}'.format(str(f.response.content)))
									elif tools.isHTML(f.response.content) or len(currentPath) == 1:
										alterValue = currentPath[0]
										if respOperation == 'rm':
											alterValue = None
										elif respOperation == 'ran':
											alterValue = tools.checkTypeAlter(f.request.url, currentPath, alterValue)
										running_logger.debug('Change Before {}'.format(str(f.response.content)))
										if alterValue == None:
											f.response.content = alterValue
										else:
											f.response.content = alterValue.encode('utf8')
										running_logger.debug('Change After {}'.format(str(f.response.content)))
									respCounter = respCounter + 1
								paraPool['action'] = 'done'
						except Exception:
							running_logger.exception("exception in fuzzing:")
		globalCond.release()

	@controller.handler
	def error(self, f):
		running_logger.warn("Network communication error in proxy, url: {}, error: {}".format(f.request.url, f.error))

	@controller.handler
	def log(self, l):
		pass

#proxy thread class
class proxyThread(threading.Thread):
	def __init__(self, name):
		threading.Thread.__init__(self)
		self.name = name

	def run(self):
		global proxy_port
		running_logger.info('Proxy is starting...')
		try:
			opts = options.Options(cadir="~/.mitmproxy/",listen_port=proxy_port, rawtcp=True)
			#Ignore TruelsException('Cannot validate certificate hostname without SNI',) error in older version of Android
			opts.ssl_insecure = True
			config = ProxyConfig(opts)
			state = flow.State()
			server = ProxyServer(config)
			m = proxyMaster(opts, server, state)
			m.run()
		except Exception,e :
			running_logger.exception('Error in proxyThread')
			raise
		finally:
			pass

	def stop(self):
		running_logger.info('Proxy thread exit')
		sys.exit(0)

# function to check action result
# if result is -1, then there are errors in appium side
# all components should be restarted 
def checkActionResult(result):
	if result == -1:
		sys.exit()

#control thread class
class controlThread(threading.Thread):
	def __init__(self, name):
		threading.Thread.__init__(self)
		self.name = name
	def run(self):
		global globalCond
		global appiumCond
		global appiumSignal
		global actionName
		global paraPool
		global enter
		global idp_name
		global ui_support
		global ui_reset
		global appium_port
		global system_port

		running_logger.info('Launching control unit...')
		try:
			#control the phone
			while True:
				didSth = False
				globalCond.acquire()
				if actionName == 'Initialize':
					globalCond.release()
					didSth = True
					running_logger.debug('Control goes into Initialize')
					time.sleep(1)

				elif actionName == 'IdPAuthIdPAppRequ' or actionName == 'IdPAuthIdPAppResp' or actionName == 'IdPAuthIdPApp':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					loginResult = None					
					if actionName != 'IdPAuthIdPApp':
						loginResult = testing.rpConfirm(idp_name, True, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						if loginResult == -1:
							error_exit()
						running_logger.debug('Controller return from confirm')
						#After fuzzing, if response contain error, on hold and wait proxy to fuzz more
						appiumCond.acquire()
						if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
							appiumCond.wait()
						#If later on decide only change response need to go to the end, then can comment out IdPAuthIdPAppRequ
						resultNum = testing.getResultNum()
						if not SSO.Eve_Auth_RP and loginResult != False and (testing.process != None and testing.process.poll() == None):
							loginResult = testing.rpAuthorize(resultNum)
							if loginResult == -1:
								error_exit()
						if ui_support:
							loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						else:
							if 'result' not in paraPool:
								loginResult = False
							else:
								loginResult = paraPool['result']
						if loginResult == 'Alice' or loginResult == 'Others':
							paraPool['result'] = True
						elif loginResult == 'Eve':
							paraPool['result'] = False
						if loginResult != False:
							if testing.rpLogout(g_appinfo['view'],g_appinfo['activity'], appium_port, ui_reset, system_port) == -1:
								if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
									error_exit()
						appiumCond.release()
						running_logger.debug('Controller realease key')

				elif actionName == 'IdPAuthIdPApp1Requ' or actionName == 'IdPAuthIdPApp1Resp' or actionName == 'IdPAuthIdPApp1':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					#testing.rpLogin()
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					loginResult = None					
					if actionName != 'IdPAuthIdPApp1':
						loginResult = testing.rpConfirm(idp_name, SSO.doubleRequests, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						if loginResult == -1:
							error_exit()
						running_logger.debug('Controller return from confirm')			
						#After fuzzing, if response contain error, on hold and wait proxy to fuzz more
						appiumCond.acquire()
						running_logger.debug('Controller acuired key')
						if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
							appiumCond.wait()
						if SSO.doubleRequests:
							resultNum = testing.getResultNum()
							if loginResult != False and (testing.process != None and testing.process.poll() == None):
								loginResult = testing.rpAuthorize(resultNum)
							if loginResult == -1:
								error_exit()							
						#if appiumSignal == 'Go':
						#If later on decide only change response need to go to the end, then can comment out IdPAuthIdPAppRequ
						if ui_support:
							loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						else:
							if 'result' not in paraPool:
								loginResult = False
							else:
								loginResult = paraPool['result']
						if loginResult == 'Alice' or loginResult == 'Others':
							paraPool['result'] = True
						elif loginResult == 'Eve':
							paraPool['result'] = False
						if loginResult != False:
							if testing.rpLogout(g_appinfo['view'],g_appinfo['activity'], appium_port, ui_reset, system_port) == -1:
								if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:							
									error_exit()
						appiumCond.release()
						running_logger.debug('Controller realease key')

				elif actionName == 'IdPShowRPAppInfoRequ' or actionName == 'IdPShowRPAppInfoResp' or actionName == 'IdPShowRPAppInfo':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					#testing.rpLogin()
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					loginResult = False					
					if actionName != 'IdPShowRPAppInfo':
						loginResult = testing.rpConfirm(idp_name, True, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						if loginResult == -1:
							error_exit()
						running_logger.debug('Controller return from confirm')				
						appiumCond.acquire()
						running_logger.debug('Controller acuired key')
						if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
							appiumCond.wait()
						resultNum = testing.getResultNum()
						if loginResult != False and (testing.process != None and testing.process.poll() == None):
							loginResult = testing.rpAuthorize(resultNum)
						if loginResult == -1:
							error_exit()
						if ui_support:	
							loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						else:
							if 'result' not in paraPool:
								loginResult = False
							else:
								loginResult = paraPool['result']
						if loginResult == 'Alice' or loginResult == 'Others':
							paraPool['result'] = True
						elif loginResult == 'Eve':
							paraPool['result'] = False
						if loginResult != False:
							if testing.rpLogout(g_appinfo['view'],g_appinfo['activity'], appium_port, ui_reset, system_port) == -1:
								if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:							
									error_exit()
						appiumCond.release()
						running_logger.debug('Controller realease key')

				elif actionName == 'IdPShowRPAppInfo1Requ' or actionName == 'IdPShowRPAppInfo1Resp' or actionName == 'IdPShowRPAppInfo1':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into'+actionName)
					#testing.rpLogin()
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					loginResult = False					
					if actionName != 'IdPShowRPAppInfo1':
						loginResult = testing.rpConfirm(idp_name, SSO.doubleRequests, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						if loginResult == -1:
							error_exit()
						running_logger.debug('Controller return from confirm')
						appiumCond.acquire()
						running_logger.debug('Controller acuired key')
						if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
							appiumCond.wait()
						if SSO.doubleRequests:
							resultNum = testing.getResultNum()
							if loginResult != False and (testing.process != None and testing.process.poll() == None):
								loginResult = testing.rpAuthorize(resultNum)
							if loginResult == -1:
								error_exit()		
						if ui_support:	
							loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						else:
							if 'result' not in paraPool:
								loginResult = False
							else:
								loginResult = paraPool['result']
						if loginResult == 'Alice' or loginResult == 'Others':
							paraPool['result'] = True
						elif loginResult == 'Eve':
							paraPool['result'] = False
						if loginResult != False:
							if testing.rpLogout(g_appinfo['view'],g_appinfo['activity'], appium_port, ui_reset, system_port) == -1:
								if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:							
									error_exit()		
						appiumCond.release()
						running_logger.debug('Controller realease key')
					if actionName == 'IdPShowRPAppInfo1' and not SSO.doubleRequests:
						if testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
							error_exit()

				elif actionName == 'EveIdP_AuthRequ' or actionName == 'EveIdP_AuthResp' or actionName == 'EveIdP_Auth':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into ' + actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					loginResult = None			
					loginResult = testing.rpConfirm(idp_name, True, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					resultNum = testing.getResultNum()
					if loginResult != False and (testing.process != None and testing.process.poll() == None):				
						loginResult = testing.rpAuthorize(resultNum)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')
					if actionName != 'EveIdP_Auth':
						appiumCond.acquire()
						running_logger.debug('Controller acuired key')
						if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
							appiumCond.wait()
						if ui_support:	
							loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						else:
							if 'result' not in paraPool:
								loginResult = False
							else:
								loginResult = paraPool['result']
						if loginResult == 'Alice' or loginResult == 'Others':
							paraPool['result'] = True
						elif loginResult == 'Eve':
							paraPool['result'] = False
						if loginResult != False:
							if testing.rpLogout(g_appinfo['view'],g_appinfo['activity'], appium_port, ui_reset, system_port) == -1:
								if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
									error_exit()
						appiumCond.release()
						running_logger.debug('Controller realease key')

				elif actionName == 'EveIdP_Auth1Requ' or actionName == 'EveIdP_Auth1Resp' or actionName == 'EveIdP_Auth1':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into'+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					loginResult = None					
					loginResult = testing.rpConfirm(idp_name, True, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					resultNum = testing.getResultNum()
					if loginResult != False and (testing.process != None and testing.process.poll() == None):			
						loginResult = testing.rpAuthorize(resultNum)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')
					if actionName != 'EveIdP_Auth1':
						appiumCond.acquire()
						running_logger.debug('Controller acuired key')
						if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
							appiumCond.wait()
						if ui_support:	
							loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
						else:
							if 'result' not in paraPool:
								loginResult = False
							else:
								loginResult = paraPool['result']
						if loginResult == 'Alice' or loginResult == 'Others':
							paraPool['result'] = True
						elif loginResult == 'Eve':
							paraPool['result'] = False
						if loginResult != False:
							if testing.rpLogout(g_appinfo['view'],g_appinfo['activity'], appium_port, ui_reset, system_port) == -1:
								if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
									error_exit()
						appiumCond.release()
						running_logger.debug('Controller realease key')					

				elif actionName == 'RPAppHandshakeRPServRequ' or actionName == 'RPAppHandshakeRPServResp' or actionName == 'RPAppHandshakeRPServ':
					globalCond.release()
					didSth = True
					running_logger.debug('Control goes into' + actionName)
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False		

				elif actionName == 'ShowUserInfoServRequ' or actionName == 'ShowUserInfoServResp' or actionName	 == 'ShowUserInfo':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()			
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'],appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False
					appiumCond.release()
					running_logger.debug('Controller realease key')

				elif actionName == 'ShowMoreUserInfoServRequ' or actionName == 'ShowMoreUserInfoServResp' or actionName	 == 'ShowMoreUserInfo':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()			
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'],appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False	
					appiumCond.release()
					running_logger.debug('Controller realease key')

				elif actionName == 'ShowExtraUserInfoServRequ' or actionName == 'ShowExtraUserInfoServResp' or actionName == 'ShowExtraUserInfo':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()			
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'],appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False
					appiumCond.release()
					running_logger.debug('Controller realease key')

				elif actionName == 'ShowUserInfoServ1Requ' or actionName == 'ShowUserInfoServ1Resp' or actionName == 'ShowUserInfo1':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()		
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']		
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False
					appiumCond.release()
					running_logger.debug('Controller realease key')	

				elif actionName == 'ShowMoreUserInfoServ1Requ' or actionName == 'ShowMoreUserInfoServ1Resp' or actionName == 'ShowMoreUserInfo1':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()		
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']		
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False
					appiumCond.release()
					running_logger.debug('Controller realease key')	

				elif actionName == 'ShowExtraUserInfoServ1Requ' or actionName == 'ShowExtraUserInfoServ1Resp' or actionName == 'ShowExtraUserInfo1':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()		
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']		
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False
					appiumCond.release()
					running_logger.debug('Controller realease key')	

				elif actionName == 'GetUidRequ' or actionName == 'GetUidResp' or actionName	 == 'GetUid':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into'+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()	
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'],appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']			
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False
					appiumCond.release()
					running_logger.debug('Controller realease key')

				elif actionName == 'GetUid1Requ' or actionName == 'GetUid1Resp' or actionName  == 'GetUid1':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()	
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']				
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False
					appiumCond.release()
					running_logger.debug('Controller realease key')

				elif actionName == 'GetATRequ' or actionName == 'GetATResp' or actionName	 == 'GetAT':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()	
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']				
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False
					appiumCond.release()
					running_logger.debug('Controller realease key')		

				elif actionName == 'RefreshATRequ' or actionName == 'RefreshATResp' or actionName	 == 'RefreshAT':
					globalCond.release()
					enter = False
					didSth = True
					running_logger.debug('Control goes into '+actionName)
					appiumCond.acquire()
					appiumSignal = 'Wait'
					appiumCond.release()
					if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
						error_exit()
					loginResult = False
					loginResult = testing.rpConfirm(idp_name, False, g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					if loginResult == -1:
						error_exit()
					running_logger.debug('Controller return from confirm')					
					appiumCond.acquire()
					running_logger.debug('Controller acuired key')
					if appiumSignal != 'Go' and appiumSignal != 'Break' and enter:
						appiumCond.wait()	
					if ui_support:	
						loginResult = testing.rpInfo(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port)
					else:
						if 'result' not in paraPool:
							loginResult = False
						else:
							loginResult = paraPool['result']				
					if loginResult == 'Alice' or loginResult == 'Others':
						paraPool['result'] = True
					elif loginResult == 'Eve':
						paraPool['result'] = False
					appiumCond.release()
					running_logger.debug('Controller realease key')				

				elif actionName == 'EveLoggedoutApp':
					globalCond.release()
					didSth = True
					running_logger.debug('Control goes into EveLoggedoutApp')
					if testing.rpLogout(g_appinfo['view'],g_appinfo['activity'], appium_port, ui_reset, system_port) == -1:
						if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
							error_exit()

				elif actionName == 'EveLoggedoutApp1':
					globalCond.release()
					didSth = True
					running_logger.debug('Control goes into EveLoggedoutApp1')
					if testing.rpLogout(g_appinfo['view'],g_appinfo['activity'], appium_port, ui_reset, system_port) == -1:
						if testing.resetRp(g_appinfo['view'],g_appinfo['activity'], appium_port, system_port) == -1:
							error_exit()
				
				elif actionName == 'response':
					globalCond.release()
					didSth = True
					running_logger.debug('Control goes into response modification')
					time.sleep(60)

				elif actionName == 'Game_Over':
					actionName = 'Finish'
					globalCond.notify_all()
					globalCond.release()
					running_logger.info('Controller exit.')
					break

				else:
					globalCond.release()

				globalCond.acquire()
				if actionName != None and didSth == True:
					actionName = 'Finish'
					globalCond.notify_all()
				globalCond.release()

		except Exception, e:
			running_logger.exception('exception in controlThread')
			running_logger.warning('Control unit exits!')
			error_exit()

#PyModel thread
def TestAction(aname, args, modelResult):
	def init_idp(idp):
		global respParaPool
		global requParaPool
		global aliceAT
		global aliceAT1
		global extraAT

		with open('response_para') as f:
			tmpPool = json.load(f)
			respParaPool = tmpPool
		#Initial resquest para pool
		with open('request_para') as f:
			tmpPool = json.load(f)
			requParaPool = tmpPool
		if idp == 'sina':
			if requParaPool['api.weibo.com/oauth2/sso_authorize+++'] != {} or respParaPool['api.weibo.com/oauth2/sso_authorize+++'] != []:
				SSO.doubleRequests = True
			for item in respParaPool['api.weibo.com/oauth2/sso_authorize+']:
				if 'access_token' in str(item):
					aliceAT = str(item['path'][-1])
					break
			if 'access_token' in str(respParaPool['api.weibo.com/oauth2/sso_authorize+'][-1]) and respParaPool['api.weibo.com/oauth2/sso_authorize+'][-1]['operation'] == ['rep']:
				extraAT = str(respParaPool['api.weibo.com/oauth2/sso_authorize+'][-1]['path'][-1])
				extraCase = respParaPool['api.weibo.com/oauth2/sso_authorize+'][-1]
				respParaPool['api.weibo.com/oauth2/sso_authorize+'] = respParaPool['api.weibo.com/oauth2/sso_authorize+'][:-1]
				respParaPool['api.weibo.com/oauth2/sso_authorize+'].insert(0, extraCase)		
			if 'api.weibo.com/2/users/show.json' not in requParaPool and 'api.weibo.com/2/users/show.json' not in respParaPool:
				SSO.fuzzShowUserInfo = False
				SSO.fuzzShowUserInfo1 = False
			if 'api.weibo.com/2/account/get_uid.json' not in requParaPool and 'api.weibo.com/2/account/get_uid.json' not in respParaPool:
				SSO.fuzzGetUid = False
				SSO.fuzzGetUid1 = False
		elif idp == 'wechat':
			if 'api.weixin.qq.com/sns/userinfo' not in requParaPool and 'api.weixin.qq.com/sns/userinfo' not in respParaPool:
				SSO.fuzzShowUserInfo = False
			if 'api.weixin.qq.com/sns/oauth2/access_token' not in requParaPool and 'api.weixin.qq.com/sns/oauth2/access_token' not in respParaPool:
				SSO.fuzzGetAT = False
			if 'api.weixin.qq.com/sns/oauth2/refresh_token' not in requParaPool and 'api.weixin.qq.com/sns/oauth2/refresh_token' not in respParaPool:
				SSO.fuzzRefreshAT = False	
			if 'open.weixin.qq.com/connect/oauth2/authorize_reply' not in respParaPool and 'sz.open.weixin.qq.com/connect/oauth2/authorize_reply' not in respParaPool:
				if 'open.weixin.qq.com/connect/oauth2/authorize_reply' in requParaPool:
					respParaPool['open.weixin.qq.com/connect/oauth2/authorize_reply'] = []		
				elif 'sz.open.weixin.qq.com/connect/oauth2/authorize_reply' in requParaPool:
					respParaPool['sz.open.weixin.qq.com/connect/oauth2/authorize_reply'] = []
			if 'open.weixin.qq.com/connect/oauth2/authorize_reply' not in requParaPool and 'sz.open.weixin.qq.com/connect/oauth2/authorize_reply' not in requParaPool and 'open.weixin.qq.com/connect/oauth2/authorize_reply' not in respParaPool and 'sz.open.weixin.qq.com/connect/oauth2/authorize_reply' not in respParaPool:
				SSO.Eve_state = True
				SSO.Eve_Auth_RP = True
				SSO.fuzzIdPShowRPAppInfo = False
				SSO.fuzzEveIdP_Auth = False
			if 'api.weixin.qq.com/sns/oauth2/access_token' in respParaPool and 'access_token' in str(respParaPool['api.weixin.qq.com/sns/oauth2/access_token'][-1]) and respParaPool['api.weixin.qq.com/sns/oauth2/access_token'][-1]['operation'] == ['rep']:
				extraAT = str(respParaPool['api.weixin.qq.com/sns/oauth2/access_token'][-1]['path'][-1])
				extraCase = respParaPool['api.weixin.qq.com/sns/oauth2/access_token'][-1]
				respParaPool['api.weixin.qq.com/sns/oauth2/access_token'] = respParaPool['api.weixin.qq.com/sns/oauth2/access_token'][:-1]
				respParaPool['api.weixin.qq.com/sns/oauth2/access_token'].insert(0, extraCase)
			if extraAT == None:
				extraAT = ''
		elif idp == 'fb':
			g_conf['modelMap'][idp_name]['IdPShowRPAppInfo'] = tools.extractFBURL(respParaPool, 'm.facebook.com/v(.*)/dialog/oauth', 'm.facebook.com/v(.*)/dialog/oauth/read', 'm.facebook.com/v(.*)/dialog/oauth/confirm')
			if g_conf['modelMap'][idp_name]['IdPShowRPAppInfo'][-1] == '+':
				g_conf['modelMap'][idp_name]['IdPShowRPAppInfo'] = g_conf['modelMap'][idp_name]['IdPShowRPAppInfo'][0:-1]
			g_conf['modelMap'][idp_name]['IdPShowRPAppInfo1'] = g_conf['modelMap'][idp_name]['IdPShowRPAppInfo'] + '+'
			g_conf['modelMap'][idp_name]['EveIdP_Auth'] = tools.extractFBURL(respParaPool, 'm.facebook.com/v(.*)/dialog/oauth/read')
			g_conf['modelMap'][idp_name]['EveIdP_Auth1'] = tools.extractFBURL(respParaPool, 'm.facebook.com/v(.*)/dialog/oauth/confirm')
			
			for item in respParaPool[g_conf['modelMap'][idp_name]['EveIdP_Auth']]:
				if 'access_token' in str(item):
					aliceAT = str(item['path'][-1])
					break
			for item in respParaPool[g_conf['modelMap'][idp_name]['EveIdP_Auth1']]:
				if 'access_token' in str(item):
					aliceAT1 = str(item['path'][-1])
					break
			if 'access_token' in str(respParaPool[g_conf['modelMap'][idp_name]['EveIdP_Auth']][-1]) and respParaPool[g_conf['modelMap'][idp_name]['EveIdP_Auth']][-1]['operation'] == ['rep']:
				extraAT = str(respParaPool[g_conf['modelMap'][idp_name]['EveIdP_Auth']][-1]['path'][-1])
				extraCase = respParaPool[g_conf['modelMap'][idp_name]['EveIdP_Auth']][-1]
				respParaPool[g_conf['modelMap'][idp_name]['EveIdP_Auth']] = respParaPool[g_conf['modelMap'][idp_name]['EveIdP_Auth']][:-1]
				respParaPool[g_conf['modelMap'][idp_name]['EveIdP_Auth']].insert(0, extraCase)

			if tools.countURL(respParaPool, 'graph.facebook.com/v(.*)/me', True) == 2 and tools.countURL(respParaPool, 'graph.facebook.com/v(.*)/me\\+\\+\\+', True) == 1:
				SSO.fuzzShowMoreUserInfo = False
				SSO.fuzzShowMoreUserInfo1 = False
				SSO.fuzzShowExtraUserInfo = False
				SSO.fuzzShowExtraUserInfo1 = False
				g_conf['modelMap'][idp_name]['ShowUserInfo'] = tools.extractFBURL(respParaPool, 'graph.facebook.com/v(.*)/me', 'graph.facebook.com/v(.*)/me\\+\\+\\+')
				g_conf['modelMap'][idp_name]['ShowUserInfo1'] = tools.extractFBURL(respParaPool, 'graph.facebook.com/v(.*)/me\\+\\+\\+')
			elif tools.countURL(respParaPool, 'graph.facebook.com/v(.*)/me', True) == 4 and tools.countURL(respParaPool, 'graph.facebook.com/v(.*)/me\\+\\+\\+', True) == 2:
				SSO.fuzzShowExtraUserInfo = False
				SSO.fuzzShowExtraUserInfo1 = False				
				g_conf['modelMap'][idp_name]['ShowUserInfo'] = tools.processFBURL(respParaPool)[0]
				g_conf['modelMap'][idp_name]['ShowMoreUserInfo'] = tools.processFBURL(respParaPool)[1]
				g_conf['modelMap'][idp_name]['ShowUserInfo1'] = tools.processFBURL(respParaPool)[2]
				g_conf['modelMap'][idp_name]['ShowMoreUserInfo1'] = tools.processFBURL(respParaPool)[3]
			elif tools.countURL(respParaPool, 'graph.facebook.com/v(.*)/me', True) == 6 and tools.countURL(respParaPool, 'graph.facebook.com/v(.*)/me\\+\\+\\+', True) == 3:			
				g_conf['modelMap'][idp_name]['ShowUserInfo'] = tools.processFBURL(respParaPool, 3)[0]
				g_conf['modelMap'][idp_name]['ShowMoreUserInfo'] = tools.processFBURL(respParaPool, 3)[1]
				g_conf['modelMap'][idp_name]['ShowExtraUserInfo'] = tools.processFBURL(respParaPool, 3)[2]
				g_conf['modelMap'][idp_name]['ShowUserInfo1'] = tools.processFBURL(respParaPool, 3)[3]
				g_conf['modelMap'][idp_name]['ShowMoreUserInfo1'] = tools.processFBURL(respParaPool, 3)[4]				
				g_conf['modelMap'][idp_name]['ShowExtraUserInfo1'] = tools.processFBURL(respParaPool, 3)[5]
			else:
				SSO.fuzzShowUserInfo = False
				SSO.fuzzShowUserInfo1 = False
				SSO.fuzzShowMoreUserInfo = False
				SSO.fuzzShowMoreUserInfo1 = False
				SSO.fuzzShowExtraUserInfo = False
				SSO.fuzzShowExtraUserInfo1 = False	
			SSO.fuzzIdPAuthIdPApp = False
			SSO.fuzzIdPAuthIdPApp1 = False
			SSO.fuzzIdPShowRPAppInfo = False
			SSO.fuzzIdPShowRPAppInfo1 = False
		else:
			running_logger.debug('skip, unknown idp')

	def revoke_access_token(idp, access_token):
		if idp == 'sina':
			try:
				resp = requests.get('https://api.weibo.com/oauth2/revokeoauth2?access_token='+access_token, timeout = 1200)
				if 'error' in resp.text:
					running_logger.warn('Fail to revoke access token') 
					running_logger.warn('idp: %s, access_token: %s', idp, access_token)
				else:
					running_logger.debug('Revoke access token') 
			except Exception:
				running_logger.warn('Fail to revoke access token')
				running_logger.warn('idp: %s, access_token: %s', idp, access_token)
		elif idp == 'wechat':
			running_logger.debug('skip, not applicable to wechat!')
		elif idp == 'fb':
			try:
				resp = requests.get('https://graph.facebook.com/me/permissions?method=delete&access_token='+access_token, timeout = 1200)
				if '"success":true' not in resp.text:
					running_logger.warn('Fail to revoke access token') 
					running_logger.warn('idp: %s, access_token: %s', idp, access_token)
				else:
					running_logger.debug('Revoke access token') 
			except Exception:
				running_logger.warn('Fail to revoke access token')			
				running_logger.warn('idp: %s, access_token: %s', idp, access_token)
		else:
			running_logger.debug('skip, unknown idp')
		return ''

	global globalCond
	global actionName
	global respParaPool
	global requParaPool
	global paraPool
	global idp_name
	global ui_reset
	global Hash
	global rpLock
	global extraAT
	global max_test
	global mainProcess

	globalCond.acquire()
	if aname == 'Initialize':
		try:
			lastFuzzing = tools.getLast()
			if not os.path.exists('appiumError.log'):
				json.dump({}, open('appiumError.log', 'w'))	
			else:
				with open('appiumError.log') as f:
					errorLog = json.load(f)	
					if str(lastFuzzing) in errorLog.keys() and errorLog[str(lastFuzzing)] > 1:
						running_logger.info('Appium Error caused: Apply '+ lastFuzzing[4] +' on '+ lastFuzzing[3] +' for the ' + lastFuzzing[1] + ' of ' + lastFuzzing[0])
					else:				
						tools.removeLast()
			tools.removeLockFiles()
			tools.checkLockFiles()
			actionName = 'Initialize'
			# todo: refactor idp initialisation into a function, may change the parameter to a variable later
			initializeState(idp_name)
			init_idp(idp_name)
			if actionName != 'Finish':
				globalCond.wait()
			SSO.initialized = True
			readState()
		except Exception:
			running_logger.exception('exception in Initialize')
			mainProcess.terminate()
	elif aname == 'IdPAuthIdPApp':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzIdPAuthIdPApp:
				#Change request
				actionName = 'IdPAuthIdPAppRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				#requParaPool format: {uri:{post:[{para1:[rm, ran]}, {para2:[rm]}], get:[{para1:[rm]}, {para2:[ran]}]}}
				#Prepare paraPool
				wantedUri = g_conf['modelMap'][idp_name]['IdPAuthIdPApp']
				actual_url = tools.refineURL(wantedUri)[2]
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'',  'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							#Use deep copy since proxy may change paras[varName]
							operations = copy.deepcopy(paras.values()[1])
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = copy.deepcopy(paras.values()[0])
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {} method, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)

								#Decide to let oauth process finished even just chaning request. So need to reset here
								if not SSO.Eve_Auth_RP and paraPool['access_token'] != '':
									# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)						

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'IdPAuthIdPAppRequ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'IdPAuthIdPAppResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)
						paraPool = {actual_url: path, 'access_token':'', 'operation':opr, 'order':1}
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							if not SSO.Eve_Auth_RP and paraPool['access_token'] != '':
								# todo: refactor revoke access token into a function, may change the parameter to a variable later
								paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
							#Update para pool
							if 'result' in paraPool:  
								if paraPool['result']:
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											try:
												result_logger.error(u'Alert: (Resp) Apply rep on '+u'-'.join(str(x) for x in path).encode('utf-8').strip() +u' for url ' + wantedUri + ' by using the data from another RP app')
											except Exception:
												result_logger.error(u'Alert: (Resp) Apply rep on '+u'-'.join(str(x) for x in path[:-1]).encode('utf-8').strip() +u' for url ' + wantedUri + ' by using the data from another RP app')
										else:
											try:
												result_logger.error(u'Alert: (Resp) Apply rep on '+str(path).encode('utf-8').strip()+u' for url ' + wantedUri + ' by using the data from another RP app')
											except Exception:
												result_logger.error(u'Alert: (Resp) Apply rep on '+u' on '+u'-'.join(x for x in path[:-1]).encode('utf-8').strip() +u' for url ' + wantedUri + ' by using the data from another RP app')
									else:
										if isinstance(path, list):
											try:
												result_logger.error(u'Alert: (Resp) Apply '+str(opr)+u' on '+u'-'.join(str(x) for x in path).encode('utf-8').strip() +u' for url ' + wantedUri)
											except Exception:
												result_logger.error(u'Alert: (Resp) Apply '+str(opr)+u' on '+u'-'.join(str(x) for x in path[:-1]).encode('utf-8').strip() +u' for url ' + wantedUri)
										else:
											try:
												result_logger.error(u'Alert: (Resp) Apply '+str(opr)+u' on '+str(path).encode('utf-8').strip()+u' for url ' + wantedUri)
											except Exception:
												result_logger.error(u'Alert: (Resp) Apply '+str(opr)+u' on '+u' on '+u'-'.join(x for x in path[:-1]).encode('utf-8').strip() +u' for url ' + wantedUri )
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'IdPAuthIdPAppResp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

			#After testing, resume to normal state
			actionName = 'IdPAuthIdPApp'
			paraPool = {}
			if actionName != 'Finish':
				globalCond.wait()
			SSO.finishIdPAuthIdPApp = True	
		except Exception as e:
			mainProcess = psutil.Process(os.getpid())
			running_logger.exception('exception in IdPAuthIdPApp')
			running_logger.error(e)
			mainProcess.terminate()
	elif aname == 'IdPAuthIdPApp1':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzIdPAuthIdPApp1:
				#Change request
				actionName = 'IdPAuthIdPApp1Requ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				#Prepare paraPool
				wantedUri = g_conf['modelMap'][idp_name]['IdPAuthIdPApp1']
				actual_url = tools.refineURL(wantedUri)[2]
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'',  'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							#Use deep copy since proxy may change paras[varName]
							operations = copy.deepcopy(paras.values()[1])
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = copy.deepcopy(paras.values()[0])
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)

								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	
				
								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'IdPAuthIdPApp1Requ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'IdPAuthIdPApp1Resp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)
						paraPool = {actual_url: path, 'access_token':'', 'operation':opr, 'order':1}
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							#Update para pool
							if 'result' in paraPool:
								if paraPool['result']:
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for url ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for url ' + wantedUri + ' by using the data from another RP app')	
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for url ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for url ' + wantedUri)
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)						

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'IdPAuthIdPApp1Resp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

			#After testing, resume to normal state
			actionName = 'IdPAuthIdPApp1'
			paraPool = {}
			if actionName != 'Finish':
				globalCond.wait()
			SSO.finishIdPAuthIdPApp1 = True	
		except Exception:
			running_logger.exception('exception in IdPAuthIdPApp1')
			mainProcess.terminate()
	elif aname == 'IdPShowRPAppInfo':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzIdPShowRPAppInfo:
				#Change request
				wantedUri = g_conf['modelMap'][idp_name]['IdPShowRPAppInfo']
				if wantedUri not in requParaPool and idp_name == 'wechat':
					wantedUri = "sz." + wantedUri
				actual_url = tools.refineURL(wantedUri)[2]
				actionName = 'IdPShowRPAppInfoRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				if idp_name == 'fb' and g_conf['snapshot'] != 'True':
					paraPool['current']['order'] = 2
					currentOrder = 2
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()#Reset IdP state
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)

								#Decide to let oauth process finished even just chaning request. So need to reset here
								if paraPool['access_token'] != '':
									# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')										
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)		

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'IdPShowRPAppInfoRequ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'IdPShowRPAppInfoResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				if wantedUri not in respParaPool:
					running_logger.error('Wrong key.')
					running_logger.error(wantedUri)
					running_logger.error(respParaPool)
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						if idp_name == 'fb' and g_conf['snapshot'] != 'True':
							paraPool['order'] = 2
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							#Reset IdP state
							if paraPool['access_token'] != '':
								# refactor: revoke access token 
								# todo: refactor revoke access token into a function, may change the parameter to a variable later
								paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
							#Update para pool
							'''
							if 'action' in paraPool and paraPool['action'] != 'done1':
								actionName = 'IdPShowRPAppInfoResp'
								break						
							'''
							if 'result' in paraPool: 
								if paraPool['result']:
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for url ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for url ' + wantedUri + ' by using the data from another RP app')										
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for url ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for url ' + wantedUri)
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)															

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'IdPShowRPAppInfoResp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

			#After testing, resume to normal state
			actionName = 'IdPShowRPAppInfo'
			paraPool = {}
			if actionName != 'Finish':
				globalCond.wait()
			SSO.finishIdPShowRPAppInfo = True
		except Exception:
			running_logger.exception('exception in IdPShowRPAppInfo')
			mainProcess.terminate()
	elif aname == 'IdPShowRPAppInfo1':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzIdPShowRPAppInfo1:
				#Change request
				wantedUri = g_conf['modelMap'][idp_name]['IdPShowRPAppInfo1']
				actual_url = tools.refineURL(wantedUri)[2]
				actionName = 'IdPShowRPAppInfo1Requ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				if idp_name == 'fb' and g_conf['snapshot'] != 'True':
					paraPool['current']['order'] = 2
					currentOrder = 2			
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()#Reset IdP state
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'IdPShowRPAppInfo1Requ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'IdPShowRPAppInfo1Resp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						if idp_name == 'fb' and g_conf['snapshot'] != 'True':
							paraPool['order'] = 2			
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							#Update para pool
							'''
							if 'action' in paraPool and paraPool['action'] != 'done1':
								actionName = 'IdPShowRPAppInfo1Resp'
								break						
							'''
							if 'result' in paraPool: 
								if extraAT in str(path) and extraAT != '' and paraPool['result']:
									result_logger.error('Alert: (Resp) Apply access_token from another RP on' + wantedUri)	
								if paraPool['result']:
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for url ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for url ' + wantedUri + ' by using the data from another RP app')		
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for url ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for url ' + wantedUri)					
								elif path_bk[0] != 'hybrid':
									if extraAT in str(path) and extraAT != '':
										pass
									else:
										running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
										for item in respParaPool[wantedUri]:
											if item["path"][0] == 'hybrid' and path_bk in item['path']:
												for oper in item["operation"]:
													if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
														tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
														tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
														running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)							

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'IdPShowRPAppInfo1Resp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

			#After testing, resume to normal state
			actionName = 'IdPShowRPAppInfo1'
			paraPool = {}
			if not SSO.doubleRequests:
				SSO.Eve_state = True
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']			
			SSO.finishIdPShowRPAppInfo1 = True
			if actionName != 'Finish':
				globalCond.wait()
		except Exception:
			running_logger.exception('exception in IdPShowRPAppInfo1')
			mainProcess.terminate()
	elif aname == 'EveIdP_Auth':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzEveIdP_Auth:
				wantedUri = g_conf['modelMap'][idp_name]['EveIdP_Auth']
				if wantedUri not in requParaPool and idp_name == 'wechat':
					wantedUri = "sz." + wantedUri			
				actual_url = tools.refineURL(wantedUri)[2]
				actionName = 'EveIdP_AuthRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				#requParaPool format: {uri:{post:[{para1:[rm, ran]}, {para2:[rm]}], get:[{para1:[rm]}, {para2:[ran]}]}}
				currentOrder = 2
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':2, 'value':''}}
				if idp_name == 'wechat' or idp_name == 'fb':
					paraPool['current']['order'] = 1
					currentOrder = 1
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)

								if paraPool['access_token'] != '':
									# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'EveIdP_AuthRequ'

						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'EveIdP_AuthResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)			
						paraPool = {actual_url: path, 'access_token':'', 'operation':opr, 'order':2}
						if idp_name == 'wechat' or idp_name == 'fb':
							paraPool['order'] = 1			
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							if paraPool['access_token'] != '':
								# todo: refactor revoke access token into a function, may change the parameter to a variable later
								paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								
							if 'state' in path and opr == 'rep' and idp_name == 'fb' and 'result' in paraPool:
								result_logger.error('State is mis-used!')

							#Update para pool
							if 'result' in paraPool:
								if extraAT in str(path) and extraAT != '' and paraPool['result']:
									result_logger.error('Alert: (Resp) Apply access_token from another RP on' + wantedUri)
								if 'header' in str(path) and 'Location' in str(path) and 'state' in str(path) and idp_name == 'wechat' and not paraPool['result']:
									result_logger.error('Alert: State is misused in' + wantedUri)
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')		
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri)
									#pdb.set_trace()
								elif path_bk[0] != 'hybrid':
									if extraAT in str(path) and extraAT != '':
										pass
									else:
										running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
										for item in respParaPool[wantedUri]:
											if item["path"][0] == 'hybrid' and path_bk in item['path']:
												for oper in item["operation"]:
													if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
														tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
														tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
														running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)	
							
							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'EveIdP_AuthResp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

			#After testing, resume to normal state
			actionName = 'EveIdP_Auth'
			if actionName != 'Finish':
				globalCond.wait()
				SSO.Eve_Auth_RP = True
				SSO.Eve_state = True
				SSO.finishEveIdP_Auth = True
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
		except Exception:
			running_logger.exception('exception in EveIdP_Auth')
			mainProcess.terminate()
	elif aname == 'EveIdP_Auth1':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzEveIdP_Auth1:
				wantedUri = g_conf['modelMap'][idp_name]['EveIdP_Auth1']
				actual_url = tools.refineURL(wantedUri)[2]
				actionName = 'EveIdP_Auth1Requ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				#requParaPool format: {uri:{post:[{para1:[rm, ran]}, {para2:[rm]}], get:[{para1:[rm]}, {para2:[ran]}]}}
				currentOrder = 2
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':2, 'value':''}}			
				if idp_name == 'wechat' or idp_name == 'fb':
					paraPool['current']['order'] = 1
					currentOrder = 1			
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'EveIdP_Auth1Requ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'EveIdP_Auth1Resp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)			
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':2}
						if idp_name == 'wechat' or idp_name == 'fb':
							paraPool['order'] = 1		
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							if 'state' in path and opr == 'rep' and idp_name == 'fb' and 'result' in paraPool:
								result_logger.error('State is mis-used!')

							#Update para pool
							if 'result' in paraPool:
								if extraAT in str(path) and extraAT != '' and paraPool['result']:
									result_logger.error('Alert: (Resp) Apply access_token from another RP on' + wantedUri)
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')	
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri)						
								elif path_bk[0] != 'hybrid':
									if extraAT in str(path) and extraAT != '':
										pass
									else:
										running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
										for item in respParaPool[wantedUri]:
											if item["path"][0] == 'hybrid' and path_bk in item['path']:
												for oper in item["operation"]:
													if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
														tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
														tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
														running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)			

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'EveIdP_Auth1Resp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

			#After testing, resume to normal state
			actionName = 'EveIdP_Auth1'
			if actionName != 'Finish':
				globalCond.wait()
				SSO.Eve_state = True
				SSO.finishEveIdP_Auth1 = True
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
		except Exception:
			running_logger.exception('exception in EveIdP_Auth1')
			mainProcess.terminate()
	elif aname == 'RPAppHandshakeRPServ':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzRPAppHandshakeRPServ:
				actionName = 'RPAppHandshakeRPServRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				#requParaPool format: {uri:{post:[{para1:[rm, ran]}, {para2:[rm]}], get:[{para1:[rm]}, {para2:[ran]}]}}
				#Get all RPApp-RPServer request urls
				rpurls = [u for u in requParaPool.keys() if g_appinfo['appNetloc'] in  u.split('/')[0]]
				for rurl in rpurls:
					if '{' in  rurl:
						Hash = rurl.split('{')[1]
					else:
						Hash = ''
					mthList = requParaPool[rurl].keys()
					if 'hybrid' in mthList:
						mthList.remove('hybrid')
						mthList.append('hybrid')
					if 'header' in mthList:
						mthList.remove('header')
						mthList.append('header')
					if 'cookie' in mthList:
						mthList.remove('cookie')
						mthList.append('cookie')
					if 'get' in mthList:
						mthList.remove('get')
						mthList.insert(0, 'get')
					if 'post' in mthList:
						mthList.remove('post')
						mthList.insert(0, 'post')
					for mth in mthList:
						for paras in requParaPool[rurl][mth]:
							newOpr = []
							varName = ''
							repVal = ''
							operations = []
							if paras.keys()[0] == 'replacedValue':
								varName = paras.keys()[1]
								operations = paras.values()[1]
								repVal = paras.values()[0]
							else:
								varName = paras.keys()[0]
								operations = paras.values()[0]
								if 'replacedValue' in paras:
									repVal = paras.values()[1]
							for opr in operations:
								rpLock = False
								if tools.checkTested(rurl, 'request', mth, varName, opr):
									continue
								tools.writeTested(rurl, 'request', mth, varName, opr)
								#continue							
								paraPool = {'uri':tools.refineURL(rurl)[2], 'access_token':'', 'tested':{'post':{}, 'get':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':tools.refineURL(rurl)[1], 'value':''}}							
								paraPool['current']['mth'] = mth
								paraPool['current']['operation'] = opr
								paraPool['current']['value'] = repVal
								paraPool['current']['name'] = varName
								paraPool['current'].pop('error', None)
								paraPool['current'].pop('action', None)
								#paraPool['current'].pop('result', None)	
								paraPool.pop('result', None)						
								running_logger.debug('Change request %s', json.dumps(paraPool))
								if actionName != 'Finish':
									globalCond.wait()
									#Update para pool
									if 'action' not in paraPool['current']:
										with open('proxyMissing.log','a+') as f:
											f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
											tools.removeLastTested()  									
									if 'result' in paraPool:
										if paraPool['result']:
											newOpr.append(opr)
											result_logger.error('Apply '+str(opr)+' on '+varName+' for url' + rurl)
										elif mth != 'hybrid':
											running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + rurl)
											if 'hybrid' in requParaPool[rurl]:
												for item in requParaPool[rurl]['hybrid']:
													if item.keys()[0] == "replacedValue":
														for oper in item.values()[1]:
															if varName in item.keys()[1] and not tools.checkTested(rurl, 'request', 'hybrid', item.keys()[1], oper):
																tools.writeTested(rurl, 'request', 'hybrid', item.keys()[1], oper, last=False)
																tools.writeRedundant(rurl, 'request', 'hybrid', item.keys()[1], oper)
																running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + rurl)
													else:
														for oper in item.values()[0]:
															if varName in item.keys()[0] and not tools.checkTested(rurl, 'request', 'hybrid', item.keys()[0], oper):
																tools.writeTested(rurl, 'request', 'hybrid', item.keys()[0], oper, last=False)	
																tools.writeRedundant(rurl, 'request', 'hybrid', item.keys()[0], oper)	
																running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + rurl)								
									if max_test != 0 and tools.countFuzzedCases(rurl, 'request') > max_test - 1:
										break
									actionName = 'RPAppHandshakeRPServRequ'
							paras[varName] = newOpr
							if max_test != 0 and tools.countFuzzedCases(rurl, 'request') > max_test - 1:
								break
						if max_test != 0 and tools.countFuzzedCases(rurl, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(rurl, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'RPAppHandshakeRPServResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				rpurls = [u for u in respParaPool.keys() if g_appinfo['appNetloc'] in  u.split('/')[0]]
				for rurl in rpurls:
					if '{' in  rurl:
						Hash = rurl.split('{')[1]
					else:
						Hash = ''
					for para in respParaPool[rurl]:
						path = copy.deepcopy(para['path'])
						path_bk = para['path']
						if isinstance(path, list) and path[0] == 'text':
							tmpBuf = path.pop(0)
						newOpr = []
						for opr in para['operation']:
							rpLock = False
							if tools.checkTested(rurl, 'response', None, str(path), opr):
								continue
							tools.writeTested(rurl, 'response', None, str(path), opr)							
							#continue
							paraPool = {tools.refineURL(rurl)[2]:path, 'operation':opr, 'access_token':'', 'order':tools.refineURL(rurl)[1]}
							running_logger.debug('Change response {}'.format(paraPool))
							if actionName != 'Finish':
								globalCond.wait()
								#Update para pool
								if 'action' not in paraPool:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
										tools.removeLastTested() 					
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for url '+rurl)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for url '+rurl)
									elif path_bk[0] != 'hybrid':
										running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + rurl)
										for item in respParaPool[rurl]:
											if item["path"][0] == 'hybrid' and path_bk in item['path']:
												for oper in item["operation"]:
													if not tools.checkTested(rurl, 'response', None, str(item['path']), oper):
														tools.writeTested(rurl, 'response', None, str(item['path']), oper, last=False)
														tools.writeRedundant(rurl, 'response', None, str(item['path']), oper)
														running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + rurl)
								if max_test != 0 and tools.countFuzzedCases(rurl, 'response') > max_test - 1:
									break
								actionName = 'RPAppHandshakeRPServResp'
						para['operation'] = newOpr
						if max_test != 0 and tools.countFuzzedCases(rurl, 'response') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(rurl, 'response') > max_test - 1:
						break

			#After testing, resume to normal state
			actionName = 'RPAppHandshakeRPServ'
			if actionName != 'Finish':
				globalCond.wait()
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
				SSO.finishRPAppHandshakeRPServ = True
		except Exception:
			running_logger.exception('exception in RPAppHandshakeRPServ')
			mainProcess.terminate()
	elif aname == 'EveLoggedoutApp':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			actionName = 'EveLoggedoutApp'
			paraPool = {}
			if actionName != 'Finish':
				globalCond.wait()
			SSO.Eve_state = False
			SSO.traceOneFinished = True	
		except Exception:
			running_logger.exception('exception in EveLoggedoutApp')
			mainProcess.terminate()
	elif aname == 'EveLoggedoutApp1':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			actionName = 'EveLoggedoutApp1'
			paraPool = {}
			# todo: refactor revoke access token into a function, may change the parameter to a variable later
			SSO.access_token = revoke_access_token(idp_name, SSO.access_token)
			if actionName != 'Finish':
				globalCond.wait()			
			#driver_tools.delete_app(driver_eve, SSO.client_id, g_appinfo['appName'], 'weibo', 'Eve')
			SSO.Eve_state = False
			SSO.traceTwoFinished = True	
			SSO.Eve_Auth_RP = False	
		except Exception:
			running_logger.exception('exception in EveLoggedoutApp1')
			mainProcess.terminate()
	elif aname == 'ShowUserInfo':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzShowUserInfo:
				if SSO.access_token != '':
					# todo: refactor revoke access token into a function, may change the parameter to a variable later
					SSO.access_token = revoke_access_token(idp_name, SSO.access_token)
			
			
				wantedUri = g_conf['modelMap'][idp_name]['ShowUserInfo']
				actual_url = tools.refineURL(wantedUri)[2]
				if idp_name == 'fb':
					Hash = tools.refineURL(wantedUri)[0]
				actionName = 'ShowUserInfoServRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)

								if paraPool['access_token'] != '':
									# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')										
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'ShowUserInfoServRequ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'ShowUserInfoServResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							if paraPool['access_token'] != '':
								# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
							#Update para pool
							if 'result' in paraPool:
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')	
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri)
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)						

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'ShowUserInfoServResp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'ShowUserInfo'
				if actionName != 'Finish':
					globalCond.wait()
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
				SSO.finishShowUserInfo = True
		except Exception:
			running_logger.exception('exception in ShowUserInfo')
			mainProcess.terminate()
	elif aname == 'ShowMoreUserInfo':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzShowMoreUserInfo:
				if SSO.access_token != '':
					# todo: refactor revoke access token into a function, may change the parameter to a variable later
					SSO.access_token = revoke_access_token(idp_name, SSO.access_token)

				wantedUri = g_conf['modelMap'][idp_name]['ShowMoreUserInfo']
				actual_url = tools.refineURL(wantedUri)[2]
				if idp_name == 'fb':
					Hash = tools.refineURL(wantedUri)[0]
				actionName = 'ShowMoreUserInfoServRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				if '+' in wantedUri and idp_name == 'fb':
					currentOrder = 2
					paraPool['order'] = 2
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)

								if paraPool['access_token'] != '':
									# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')	
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'ShowMoreUserInfoServRequ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'ShowMoreUserInfoServResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						if '+' in wantedUri and idp_name == 'fb':
							paraPool['order'] = 2				
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							if paraPool['access_token'] != '':
								# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
							#Update para pool
							if 'result' in paraPool:
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')	
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri)
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)		

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'ShowMoreUserInfoServResp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'ShowMoreUserInfo'
				if actionName != 'Finish':
					globalCond.wait()
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
				SSO.finishShowMoreUserInfo = True					
		except Exception:
			running_logger.exception('exception in ShowMoreUserInfo')
			mainProcess.terminate()
	elif aname == 'ShowExtraUserInfo':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzShowExtraUserInfo:
				if SSO.access_token != '':
					# todo: refactor revoke access token into a function, may change the parameter to a variable later
					SSO.access_token = revoke_access_token(idp_name, SSO.access_token)
				
				wantedUri = g_conf['modelMap'][idp_name]['ShowExtraUserInfo']
				actual_url = tools.refineURL(wantedUri)[2]
				if idp_name == 'fb':
					Hash = tools.refineURL(wantedUri)[0]
				actionName = 'ShowExtraUserInfoServRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				if '++' in wantedUri and idp_name == 'fb':
					currentOrder = 3
					paraPool['order'] = 3
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)

								if paraPool['access_token'] != '':
									# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'ShowExtraUserInfoServRequ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'ShowExtraUserInfoServResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						if '++' in wantedUri and idp_name == 'fb':
							paraPool['order'] = 3			
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							if paraPool['access_token'] != '':
								# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
							#Update para pool
							if 'result' in paraPool:
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri)
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)									

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'ShowExtraUserInfoServResp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'ShowExtraUserInfo'
				if actionName != 'Finish':
					globalCond.wait()
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
				SSO.finishShowExtraUserInfo = True	
		except Exception:
			running_logger.exception('exception in ShowExtraUserInfo')
			mainProcess.terminate()
	elif aname == 'ShowUserInfo1':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzShowUserInfo1:	
				wantedUri = g_conf['modelMap'][idp_name]['ShowUserInfo1']
				actual_url = tools.refineURL(wantedUri)[2]
				if idp_name == 'fb':
					Hash = tools.refineURL(wantedUri)[0]
				actionName = 'ShowUserInfoServ1Requ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')										
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'ShowUserInfoServ1Requ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'ShowUserInfoServ1Resp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							#Update para pool
							if 'result' in paraPool: 
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri )
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri )
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)
									
							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'ShowUserInfoServ1Resp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'ShowUserInfo1'
				if actionName != 'Finish':
					globalCond.wait()
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
				SSO.finishShowUserInfo1 = True		
		except Exception:
			running_logger.exception('exception in ShowUserInfo1')
			mainProcess.terminate()
	elif aname == 'ShowMoreUserInfo1':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzShowMoreUserInfo1:	
				wantedUri = g_conf['modelMap'][idp_name]['ShowMoreUserInfo1']
				actual_url = tools.refineURL(wantedUri)[2]
				if idp_name == 'fb':
					Hash = tools.refineURL(wantedUri)[0]
				actionName = 'ShowMoreUserInfoServ1Requ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				if '++++' in wantedUri and idp_name == 'fb':
					currentOrder = 2
					paraPool['order'] = 2
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)											

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'ShowMoreUserInfoServ1Requ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'ShowMoreUserInfoServ1Resp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						if '++++' in wantedUri and idp_name == 'fb':
							paraPool['order'] = 2
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							#Update para pool
							if 'result' in paraPool:
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')	
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri )
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri )
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)
									
							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'ShowMoreUserInfoServ1Resp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'ShowMoreUserInfo1'
				if actionName != 'Finish':
					globalCond.wait()
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
				SSO.finishShowMoreUserInfo1 = True
		except Exception:
			running_logger.exception('exception in ShowMoreUserInfo1')
			mainProcess.terminate()
	elif aname == 'ShowExtraUserInfo1':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzShowExtraUserInfo1:	
				wantedUri = g_conf['modelMap'][idp_name]['ShowExtraUserInfo1']
				actual_url = tools.refineURL(wantedUri)[2]
				if idp_name == 'fb':
					Hash = tools.refineURL(wantedUri)[0]
				actionName = 'ShowExtraUserInfoServ1Requ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				if '+++++' in wantedUri and idp_name == 'fb':
					currentOrder = 3
					paraPool['order'] = 3
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')									
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'ShowExtraUserInfoServ1Requ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'ShowExtraUserInfoServ1Resp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						if '+++++' in wantedUri and idp_name == 'fb':
							paraPool['order'] = 2
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							#Update para pool
							if 'result' in paraPool:
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri )
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri )
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)						

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'ShowExtraUserInfoServ1Resp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'ShowExtraUserInfo1'
				if actionName != 'Finish':
					globalCond.wait()
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
				SSO.finishShowExtraUserInfo1 = True
		except Exception:
			running_logger.exception('exception in ShowExtraUserInfo1')
			mainProcess.terminate()
	elif aname == 'GetUid':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzGetUid:
				if SSO.access_token != '':
					# todo: refactor revoke access token into a function, may change the parameter to a variable later
					SSO.access_token = revoke_access_token(idp_name, SSO.access_token)
				wantedUri = g_conf['modelMap'][idp_name]['GetUid']
				actual_url = tools.refineURL(wantedUri)[2]
				actionName = 'GetUidRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)
								
								if paraPool['access_token'] != '':
									# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'GetUidRequ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'GetUidResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							if paraPool['access_token'] != '':
								# todo: refactor revoke access token into a function, may change the parameter to a variable later
								paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
							#Update para pool
							if 'result' in paraPool: 
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')	
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri)
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)													

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'GetUidResp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'GetUid'
				if actionName != 'Finish':
					globalCond.wait()
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
				SSO.finishGetUid = True					
		except Exception:
			running_logger.exception('exception in GetUid')
			mainProcess.terminate()
	elif aname == 'GetUid1':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzGetUid1:			
				wantedUri = g_conf['modelMap'][idp_name]['GetUid']
				actual_url = tools.refineURL(wantedUri)[2]
				actionName = 'GetUid1Requ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue
							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'GetUid1Requ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'GetUid1Resp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							#Update para pool
							if 'result' in paraPool: 
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')	
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri )
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri )
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)														

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'GetUid1Resp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'GetUid1'
				if actionName != 'Finish':
					globalCond.wait()
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				paraPool = {}
				SSO.finishGetUid1 = True	
 		except Exception:
			running_logger.exception('exception in GetUid1')
			mainProcess.terminate()
	elif aname == 'GetAT':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzGetAT:
				'''
				if SSO.access_token != '':
					# todo: refactor revoke access token into a function, may change the parameter to a variable later
					SSO.access_token = revoke_access_token(idp_name, SSO.access_token)
				'''
				wantedUri = g_conf['modelMap'][idp_name]['GetAT']
				actual_url = tools.refineURL(wantedUri)[2]
				actionName = 'GetATRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)
								'''
								if paraPool['access_token'] != '':
									# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								'''
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')									
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'GetATRequ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'GetATResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 
							'''
							if paraPool['access_token'] != '':
								# todo: refactor revoke access token into a function, may change the parameter to a variable later
								paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
							'''
							#Update para pool
							if 'result' in paraPool:
								if extraAT in str(path) and extraAT != '' and paraPool['result']:
									result_logger.error('Alert: (Resp) Apply access_token from another RP on' + wantedUri)
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')	
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri)
								elif path_bk[0] != 'hybrid':
									if extraAT in str(path) and extraAT != '':
										pass
									else:
										running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
										for item in respParaPool[wantedUri]:
											if item["path"][0] == 'hybrid' and path_bk in item['path']:
												for oper in item["operation"]:
													if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
														tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
														tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
														running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)														

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'GetATResp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'GetAT'
				if actionName != 'Finish':
					globalCond.wait()
				'''
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				'''
				paraPool = {}
				SSO.finishGetAT = True	
		except Exception:
			running_logger.exception('exception in GetAT')
			mainProcess.terminate()
	elif aname == 'RefreshAT':
		try:
			tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
			if SSO.fuzzRefreshAT:
				'''
				if SSO.access_token != '':
					# todo: refactor revoke access token into a function, may change the parameter to a variable later
					SSO.access_token = revoke_access_token(idp_name, SSO.access_token)
				'''
				wantedUri = g_conf['modelMap'][idp_name]['RefreshAT']
				actual_url = tools.refineURL(wantedUri)[2]
				actionName = 'RefreshATRequ'
				if len(requParaPool) == 0:
					running_logger.error('Empty request parameter pool.')
				currentOrder = 1
				paraPool = {'uri':actual_url, 'access_token':'', 'tested':{'post':{}, 'get':{}, 'hybrid':{}, 'cookie':{}, 'header':{}}, 'current':{'mth':'', 'name':'', 'operation':'', 'order':1, 'value':''}}
				mthList = requParaPool[wantedUri].keys()
				if 'hybrid' in mthList:
					mthList.remove('hybrid')
					mthList.append('hybrid')
				if 'header' in mthList:
					mthList.remove('header')
					mthList.append('header')
				if 'cookie' in mthList:
					mthList.remove('cookie')
					mthList.append('cookie')
				if 'get' in mthList:
					mthList.remove('get')
					mthList.insert(0, 'get')
				if 'post' in mthList:
					mthList.remove('post')
					mthList.insert(0, 'post')
				for mth in mthList:
					for paras in requParaPool[wantedUri][mth]:
						paraPool['current'].pop('error', None)
						newOpr = []
						varName = ''
						repVal = ''
						operations = []
						if paras.keys()[0] == 'replacedValue':
							varName = paras.keys()[1]
							operations = paras.values()[1]
							repVal = paras.values()[0]
						else:
							varName = paras.keys()[0]
							operations = paras.values()[0]
							if 'replacedValue' in paras:
								repVal = paras.values()[1]
						for opr in operations:
							if tools.checkTested(wantedUri, 'request', mth, varName, opr):
								continue
							tools.writeTested(wantedUri, 'request', mth, varName, opr)						
							#Alread tested
							if varName in paraPool['tested'][mth] and opr in paraPool['tested'][mth][varName]:
								#running_logger.debug('Continue with variable name: {} and operation: {}'.format(varName, opr))
								continue

							paraPool['current']['mth'] = mth
							paraPool['current']['operation'] = opr
							paraPool['current']['value'] = repVal
							paraPool['current']['name'] = varName
							paraPool['current']['order'] = currentOrder
							paraPool['current'].pop('error', None)
							paraPool['current'].pop('action', None)
							#paraPool['current'].pop('result', None)
							paraPool.pop('result', None)
							running_logger.debug('Main thread Change request for {}, variable name: {}, operation: {}'.format(mth, varName, opr))
							if actionName != 'Finish':
								globalCond.wait()
								if 'action' not in paraPool['current']:
									with open('proxyMissing.log','a+') as f:
										f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')
										tools.removeLastTested()  
								if varName not in paraPool['tested'][mth]:
									paraPool['tested'][mth][varName] = [opr]
								else:
									paraPool['tested'][mth][varName].append(opr)
								'''
								if paraPool['access_token'] != '':
									# todo: refactor revoke access token into a function, may change the parameter to a variable later
									paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
								'''
								#Update para pool
								if 'result' in paraPool:
									if paraPool['result']:
										newOpr.append(opr)
										if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
											result_logger.error('Apply rep on '+varName+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Apply '+str(opr)+' on '+varName+' for ' + wantedUri)
									elif mth != 'hybrid':
										running_logger.debug('Redundant request test case: ' + str(opr) + ' on ' + varName + ' for ' + wantedUri)
										if 'hybrid' in requParaPool[wantedUri]:
											for item in requParaPool[wantedUri]['hybrid']:
												if item.keys()[0] == "replacedValue":
													for oper in item.values()[1]:
														if varName in item.keys()[1] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[1], oper, last=False)
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[1], oper)
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[1] + ' for ' + wantedUri)
												else:
													for oper in item.values()[0]:
														if varName in item.keys()[0] and not tools.checkTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper):
															tools.writeTested(wantedUri, 'request', 'hybrid', item.keys()[0], oper, last=False)	
															tools.writeRedundant(wantedUri, 'request', 'hybrid', item.keys()[0], oper)	
															running_logger.debug('Skip redundant request test case: ' + str(oper) + ' on ' + item.keys()[0] + ' for ' + wantedUri)	

								if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
									break
								actionName = 'RefreshATRequ'
						#Since this parameter has been updated in proxy
						if 'error' not in paraPool['current']:
							paras[varName] = newOpr
						if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
							break
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'request') > max_test - 1:
						break

				#Change response
				actionName = 'RefreshATResp'
				if len(respParaPool) == 0:
					running_logger.error('Empty response parameter pool.')
				for para in respParaPool[wantedUri]:
					path = copy.deepcopy(para['path'])
					path_bk = para['path']
					if isinstance(path, list) and path[0] == 'text':
						tmpBuf = path.pop(0)
					newOpr = []
					for opr in para['operation']:
						if tools.checkTested(wantedUri, 'response', None, str(path), opr):
							continue
						tools.writeTested(wantedUri, 'response', None, str(path), opr)						
						paraPool = {actual_url:path, 'access_token':'', 'operation':opr, 'order':1}
						running_logger.debug('Change response {}'.format(paraPool))
						if actionName != 'Finish':
							globalCond.wait()
							if 'action' not in paraPool:
								with open('proxyMissing.log','a+') as f:
									f.write('fuzzing missed in ' + str(tools.getLast()) + '\n')		
									tools.removeLastTested() 	
							'''
							if paraPool['access_token'] != '':
								# todo: refactor revoke access token into a function, may change the parameter to a variable later
								paraPool['access_token'] = revoke_access_token(idp_name, paraPool['access_token'])
							'''
							#Update para pool
							if 'result' in paraPool:
								if paraPool['result']:	
									newOpr.append(opr)
									if opr == 'rep1' or (isinstance(opr, list) and 'rep1' in opr):
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply rep on '+'-'.join(str(x) for x in path)+' for ' + wantedUri + ' by using the data from another RP app')
										else:
											result_logger.error('Alert: (Resp) Apply rep on '+str(path)+' for ' + wantedUri + ' by using the data from another RP app')
									else:
										if isinstance(path, list):
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+'-'.join(str(x) for x in path)+' for ' + wantedUri)
										else:
											result_logger.error('Alert: (Resp) Apply '+str(opr)+' on '+str(path)+' for ' + wantedUri)
								elif path_bk[0] != 'hybrid':
									running_logger.debug('Redundant response test case: ' + str(opr) + ' on ' + str(path) + ' for ' + wantedUri)
									for item in respParaPool[wantedUri]:
										if item["path"][0] == 'hybrid' and path_bk in item['path']:
											for oper in item["operation"]:
												if not tools.checkTested(wantedUri, 'response', None, str(item['path']), oper):
													tools.writeTested(wantedUri, 'response', None, str(item['path']), oper, last=False)
													tools.writeRedundant(wantedUri, 'response', None, str(item['path']), oper)
													running_logger.debug('Skip redundant response test case: ' + str(oper) + ' on ' + str(item['path']) + ' for ' + wantedUri)									

							if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
								break
							actionName = 'RefreshATResp'
					para['operation'] = newOpr
					if max_test != 0 and tools.countFuzzedCases(wantedUri, 'response') > max_test - 1:
						break

				#After testing, resume to normal state
				actionName = 'RefreshAT'
				if actionName != 'Finish':
					globalCond.wait()
				'''
				if 'access_token' in paraPool:
					SSO.access_token = paraPool['access_token']
				'''
				paraPool = {}
				SSO.finishRefreshAT = True	
		except Exception:
			running_logger.exception('exception in RefreshAT')
			mainProcess.terminate()
	elif aname == 'Game_Over':
		tools.writeState(SSO.access_token,SSO.initialized, SSO.Eve_state, SSO.IdP_App_Installed, SSO.IdP_Name, SSO.Eve_Auth_RP, SSO.doubleRequests, SSO.fuzzIdPAuthIdPApp, SSO.fuzzIdPShowRPAppInfo, SSO.fuzzEveIdP_Auth, SSO.fuzzIdPAuthIdPApp1, SSO.fuzzIdPShowRPAppInfo1, SSO.fuzzEveIdP_Auth1, SSO.fuzzRPAppHandshakeRPServ, SSO.fuzzGetUid, SSO.fuzzShowUserInfo, SSO.fuzzShowMoreUserInfo, SSO.fuzzShowExtraUserInfo, SSO.fuzzGetAT, SSO.fuzzRefreshAT, SSO.fuzzGetUid1, SSO.fuzzShowUserInfo1, SSO.fuzzShowMoreUserInfo1, SSO.fuzzShowExtraUserInfo1, SSO.finishIdPAuthIdPApp, SSO.finishIdPShowRPAppInfo, SSO.finishEveIdP_Auth, SSO.finishIdPAuthIdPApp1, SSO.finishIdPShowRPAppInfo1, SSO.finishEveIdP_Auth1, SSO.finishRPAppHandshakeRPServ, SSO.finishGetUid, SSO.finishShowUserInfo, SSO.finishShowMoreUserInfo, SSO.finishShowExtraUserInfo, SSO.finishGetAT, SSO.finishRefreshAT, SSO.finishGetUid1, SSO.finishShowUserInfo1, SSO.finishShowMoreUserInfo1, SSO.finishShowExtraUserInfo1, SSO.traceOneFinished, SSO.traceTwoFinished)
		paraPool = {}
		if SSO.Eve_Auth_RP:
			# todo: refactor revoke access token into a function, may change the parameter to a variable later
			SSO.access_token = revoke_access_token(idp_name, SSO.access_token)
		actionName = 'Game_Over'
		if actionName != 'Finish':
			globalCond.wait()
		sys.exit(0)
	actionName = None
	globalCond.release()
	return


#Initial Thread
globalCond = threading.Condition()
appiumCond = threading.Condition()
appiumSignal = 'Wait'
proxyThd = proxyThread('proxy')
proxyThd.start()
contThd = controlThread('controller')
contThd.start()
aliceAT = None
aliceAT1 = None
extraAT = ''
enter = False
idp_name = g_conf["idp"]
code = ''

ui_support = None
refURL = ''
refLocation = []
refAlice = ''
refEve = ''
[ui_support, refURL, refLocation, refAlice, refEve] = tools.loadRef()
refOrder = 1
refHash = ''
if not ui_support:
	[refHash, refOrder, refURL] = tools.refineURL(refURL)
counter = refOrder
Hash = ''
rpLock = False

ui_reset = None
if g_conf["ui_reset"] == "False":
	ui_reset = False
else:
	ui_reset = True

query_bk = None
text_bk = None
url_bk = None
header_bk = None
cookie_bk = None

max_test = 0
if g_conf["max_test"] != 0:
	max_test = g_conf["max_test"]

#Test single function
if __name__ == '__main__':	
	#try:
	logging.basicConfig(level=logging.DEBUG, format='[%(name)s][%(levelname)s]%(asctime)s %(message)s', datefmt='%m-%d %H:%M', filename='Stepper.log', filemode='w')
	running_logger = logging.getLogger('Stepper')
	running_logger.setLevel(logging.DEBUG)
	TestAction('Initialize', 'None', 'None')
	#TestAction('ShowExtraUserInfo1', 'None', 'None')
	#import TestAction
	#TestAction('EveLoginIdPApp', 'None', 'None')
	TestAction('IdPAuthIdPApp', 'None', 'None')
	#TestAction('EveIdP_Auth', 'None', 'None')
	#TestAction('EveLoggedoutIdPApp', 'None', 'None')
	#TestAction('EveLoggedoutApp1', 'None', 'None')
	#TestAction('Game_Over', 'None', 'None')
	#TestAction('response', 'None', 'None')
	#TestAction('IdPAuthIdPApp', 'None', 'None')				
	
	#TestAction('GetAT', 'None', 'None')
	#TestAction('IdPShowRPAppInfo', 'None', 'None')	
	#TestAction('EveIdP_Auth', 'None', 'None')
	#TestAction('IdPAuthIdPApp', 'None', 'None')
	#TestAction('IdPShowRPAppInfo1', 'None', 'None')
	#TestAction('Game_Over', 'None', 'None')
	#SSO.fuzzRPAppHandshakeRPServ = True
	#TestAction('RPAppHandshakeRPServ', 'None', 'None')
	#TestAction('RPAppHandshakeRPServ', 'None', 'None')
	p = psutil.Process(os.getpid())
	p.terminate() 

#!/usr/bin/env python
# -*- coding: utf-8 -*-

#This script provides some handy tools
import logging
import conf
import json
import urllib
import extractor
import os
import re
import itertools
import copy
import pdb
from logger import MyLogger

running_logger = MyLogger(__name__).get_logger()

result_logger = logging.getLogger('result')
g_config = conf.g_config

g_ignoreHeaders = ['content-length', 'cookie', 'set-cookie', 'date']

#Let proxy to fuzze parameter
#fHeader and fCookie are dict, in the format of {'name1':'value1', 'name2':'value2'}
def proxyFuzzy(url, mth, opr, vName, repVal, fQuery, fText, fHeader, fCookie):
  def recoverPostData(input):
    result = ''
    for item in input.keys():
      result = result + item + '=' + input[item] + '&'
    return result[:-1]

  import extractor
  #import urllib

  isjsonformat = True

  if fText != None:
    tmpParams = {}
    if isJson(fText):
      fText = json.loads(fText)
    else:
      isjsonformat = False
      for prt in fText.split('&'):
        try:
          k, v = prt.split('=')
        except:
          continue
        tmpParams[k] = v
      fText = tmpParams
      
  resp = None
  if mth == 'get':
    paras = extractor.extract_parameters(url)
    schema = 'http://'
    if 'https://' in url:
      schema = 'https://'
    uri = extractor.extract_uri(url, False)
    if opr == 'rep':
      paras[vName] = repVal
    elif opr == 'ran':
      paras[vName] = checkTypeAlter(url, vName, repVal)
    elif opr == 'rm':
      paras.pop(vName)
    newUrl = schema + uri + '?' + urllib.urlencode(paras)
    if fText == None:
      resp = toServer(newUrl, 'GET', postData=None, cookies=fCookie, headers=fHeader)
    else:
      if isjsonformat:
        resp = toServer(newUrl, 'POST', postData=json.dumps(fText), cookies=fCookie, headers=fHeader)
      else:
        resp = toServer(newUrl, 'POST', postData=recoverPostData(fText), cookies=fCookie, headers=fHeader)
  elif mth == 'post':
    if vName in fText:
      if opr == 'rep':
        fText[vName] = repVal
      elif opr == 'ran':
        fText[vName] = checkTypeAlter(url, vName, repVal)
      elif opr == 'rm':
        fText.pop(vName)
      if isjsonformat:
        resp = toServer(url, 'POST', postData=json.dumps(fText), cookies=fCookie, headers=fHeader)
      else:
        resp = toServer(url, 'POST', postData=recoverPostData(fText), cookies=fCookie, headers=fHeader)
  elif mth == 'hybrid':
    counter = 0
    for paraName, paraRepVal in zip(vName.split('^v^'), repVal.split('^v^')):
      operation = opr[counter]
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
        paras = extractor.extract_parameters(url)
        schema = 'http://'
        if 'https://' in url:
          schema = 'https://'
        uri = extractor.extract_uri(url, False)
        if operation == 'rep':
          paras[paraName] = paraRepVal
        elif opr == 'ran':
          paras[paraName] = checkTypeAlter(url, paraName, paraRepVal)
        elif opr == 'rm':
          paras.pop(paraName)
        url = schema + uri + '?' + urllib.urlencode(paras)
      elif pmth == 'post':
        if paraName in fText:
          if operation == 'rep':
            fText[paraName] = paraRepVal
          elif opr == 'ran':
            fText[paraName] = checkTypeAlter(url, paraName, paraRepVal)
          elif opr == 'rm':
            fText.pop(paraName)
      elif pmth == 'header':
        if paraName in fHeader:
          if opr == 'rep':
            fHeader[paraName] = paraRepVal
          elif opr == 'ran':
            fHeader[paraName] = checkTypeAlter(url, paraName, paraRepVal, True)
          elif opr == 'rm':
            fHeader.pop(paraName)
      elif pmth == 'cookie':
        if paraName in fCookie:
          if opr == 'rep':
            fCookie[paraName] = paraRepVal
          elif opr == 'ran':
            fCookie[paraName] = checkTypeAlter(url, paraName, paraRepVal)
          elif opr == 'rm':
            fCookie.pop(paraName)
      counter = counter + 1

    if fText == None:
      resp = toServer(url, 'GET', postData=None, cookies=fCookie, headers=fHeader)
    else:
      if isjsonformat:
        resp = toServer(url, 'POST', postData=json.dumps(fText), cookies=fCookie, headers=fHeader)
      else:
        resp = toServer(url, 'POST', postData=recoverPostData(fText), cookies=fCookie, headers=fHeader)
  elif mth == 'header':
    if vName in fHeader:
      if opr == 'rep':
        fHeader[vName] = repVal
      elif opr == 'ran':
        fHeader[vName] = checkTypeAlter(url, vName, repVal, True)
      elif opr == 'rm':
        fHeader.pop(vName)
      if fText == None:
        resp = toServer(url, 'GET', postData=None, cookies=fCookie, headers=fHeader)
      else:
        if isjsonformat:
          resp = toServer(url, 'POST', postData=json.dumps(fText), cookies=fCookie, headers=fHeader)
        else:
          resp = toServer(url, 'POST', postData=recoverPostData(fText), cookies=fCookie, headers=fHeader)
  elif mth == 'cookie':
    if vName in fCookie:
      if opr == 'rep':
        fCookie[vName] = repVal
      elif opr == 'ran':
        fCookie[vName] = checkTypeAlter(url, vName, repVal)
      elif opr == 'rm':
        fCookie.pop(vName)
      if fText == None:
        resp = toServer(url, 'GET', postData=None, cookies=fCookie, headers=fHeader)
      else:
        if isjsonformat:
          resp = toServer(url, 'POST', postData=json.dumps(fText), cookies=fCookie, headers=fHeader)
        else:
          resp = toServer(url, 'POST', postData=recoverPostData(fText), cookies=fCookie, headers=fHeader)


  if resp == None:
    return 'Error'
  try:
    respText = resp.text.decode('utf-8')
  except:
    respText = repr(resp.text)
  
  if isJson(respText):
    data = json.loads(respText)
    #For weibo case
    for k in data:
      if 'error' in k and (isinstance(data[k], str) or isinstance(data[k], int) or isinstance(data[k], unicode)) and str(data[k]).strip() != '':
        return 'Error'
        
  return 'Succ'

################################################################################

#Given a url, permunate all possible variable value and check the response
#Input are in HAR format
#params: postdata in this url
def permunateUrl(g_appinfo, folder_location, idp_name, filter_subsequent=True):
  running_logger.info("Request key parameters extraction from network trace files, writing to request_para...")
  rawTrace = json.load(open('eveA.trace', 'r'))
  IdPDomain = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]['domain']
  fuzzyHC = json.load(open('config.json', 'r'))['fuzzy_headercookie']

  trace = extractor.clean_trace(rawTrace['log']['entries'], [IdPDomain, g_appinfo['appNetloc']], False, idp_name)

  # trace = None
  # if idp_name == 'sina':
  #   trace = extractor.clean_trace(rawTrace['log']['entries'], ['api.weibo', g_appinfo['appNetloc']], False, idp_name = 'sina')
  # elif idp_name == 'wechat':
  #   trace = extractor.clean_trace(rawTrace['log']['entries'], ['weixin', g_appinfo['appNetloc']], False, idp_name = 'wechat')
  
  if os.path.exists(os.path.join(folder_location,'request_para')):
    os.remove(os.path.join(folder_location,'request_para'))
  json.dump({}, open(os.path.join(folder_location,'request_para'), 'w+'))
  hasOauth = False
  authUserUrl = ''
  if filter_subsequent:
    userIdentifier = json.load(open(os.path.join(folder_location,'user_para'),"r"))
    userIdentifier['userIdentifier'].pop('Alice')
    userIdentifier['userIdentifier'].pop('Eve')
    # The url which identifies the user
    authUserUrl = next(iter(userIdentifier['userIdentifier']))

  for header in trace:
    pData = None
    if 'postData' in header['request']:
      # Note that header['request']['postData']['text'] may not be the same as header['request']['postData']['params]
      pData = header['request']['postData']['text']
    uniqueUri = addHash4Request(header, idp_name)

    do_permunateUrl(header['request']['url'], header['request']['queryString'], pData, header['response'], cookies=header['request']['cookies'], headers=header['request']['headers'], uniqueUri = uniqueUri, appendix='', folder_location=folder_location, fuzzyHC=fuzzyHC)
    if filter_subsequent and authUserUrl in uniqueUri:
      running_logger.debug("find the authUserUrl {} and ignore subsequent request".format(header['request']['url']))
      break

  if idp_name == 'sina' or idp_name == 'fb':
    running_logger.info("Request key parameters extraction from network trace files, writing to request_para+...")
    rawTrace = json.load(open('eveA+.trace', 'r'))
    trace = extractor.clean_trace(rawTrace['log']['entries'], [IdPDomain, g_appinfo['appNetloc']], False, idp_name)
    if os.path.exists(os.path.join(folder_location,'request_para+')):
      os.remove(os.path.join(folder_location,'request_para+'))
    hasOauth = False
    authUserUrl = ''
    if filter_subsequent:
      userIdentifier = json.load(open(os.path.join(folder_location,'user_para'),"r"))
      userIdentifier['userIdentifier'].pop('Alice')
      userIdentifier['userIdentifier'].pop('Eve')
      authUserUrl = next(iter(userIdentifier['userIdentifier']))
    for header in trace:
      pData = None
      if 'postData' in header['request']:
        pData = header['request']['postData']['text']
      uniqueUri = addHash4Request(header, idp_name)
      do_permunateUrl(header['request']['url'], header['request']['queryString'], pData, header['response'], cookies=header['request']['cookies'], headers=header['request']['headers'], uniqueUri = uniqueUri, appendix='+', folder_location=folder_location, fuzzyHC=fuzzyHC)
      if filter_subsequent and authUserUrl in uniqueUri:
        running_logger.debug("the subsequent request {} occurs after the authUserUrl and can be ignored so far".format(header['request']['url']))
        break
      
      # permunateUrl(header['request']['url'], header['request']['queryString'], pData, header['response'], appendix='+', folder_location=folder_location)
  return

def jsonizePostdata(params):
  #params is the post data
  #params can be a string in form of key1=value1&key2=value2...
  #params can also be a json object
  # params can be a string in the form of json object

  try:
    params = json.loads(params)
  except:
    pass

  tmpParams = {}
  try:
    if params != None:
      if type(params) is str or type(params) is unicode:
        for prt in params.split('&'):
          try:
            k, v = prt.split('=')
          except:
            continue
          tmpParams[k] = v
      elif type(params) is list:
        for token in params:
          tmpParams[token["name"]] = token["value"]
          token.pop('name', None)
          token.pop('value', None)
          #after pop, if there are still elements in token, then such elements should be the attributes associated with this element, like httponly
          for key,value in token.iteritems():
            if not isinstance(key, str) or not isinstance(key, unicode):
              key = unicode(key)
            if not isinstance(value, str) or not isinstance(value, unicode):
              value = unicode(value)
            tmpParams[key] = value
      elif type(params) is dict:
        return params
  except:
    pass
  return tmpParams

def jsonizeQuerydata(queryString):
  '''
  expected input
  "queryString": [
            {
              "name": "resource", 
              "value": "search/hotwords"
            }, 
            {
              "name": "channel", 
              "value": "news_toutiao"
            }]
  '''
  tmpQuery = {}
  for item in queryString:
    tmpQuery[item['name']] = item['value']
  return tmpQuery

def jsonizeHeader(headers):
  newHeaders = {}
  for token in headers:
    newHeaders[token["name"]] = token["value"]
  return newHeaders

def jsonizeCookies(cookies):
  newCookies = {}
  for token in cookies:
    newCookies[token["name"]] = token["value"]
    token.pop('name', None)
    token.pop('value', None)
    #after pop, if there are still elements in token, then such elements should be the attributes associated with this element, like httponly
    '''
    for key,value in token.iteritems():
      if not isinstance(key, str) or not isinstance(key, unicode):
        key = unicode(key)
      if not isinstance(value, str) or not isinstance(value, unicode):
        value = unicode(value)
      newCookies[key] = value
    '''
  return newCookies

def do_permunateUrl(url, queryString, params, response, cookies, headers, uniqueUri, appendix, folder_location, fuzzyHC):
  # import urllib

  import extractor
  import csv
  # import json

  global running_logger

  # extract the context so that we can replay the request
  # unify the format of params: key-value pair      
  params = jsonizePostdata(params)
  newHeaders = jsonizeHeader(headers)
  newCookies = jsonizeCookies(cookies) 
  queryString = jsonizeQuerydata(queryString)

  rmPKeys = {}
  rmGKeys = {}
  rmHKeys = {}
  rmCKeys = {}
  alterPKeys = {}
  alterGKeys = {}
  alterHKeys = {}
  alterCKeys = {}

  if params != None:
    method = 'POST'
  else:
    method = 'GET'

  outputf = open('report.csv', 'a')
  report = csv.writer(outputf, delimiter=',')
  report.writerow(['URL', url, ''])
  outputf.close()
  
  req_para_cat = json.load(open(os.path.join(folder_location,'request_para_category'+appendix))) # three catagories
  user_para = req_para_cat['user']
  session_para = req_para_cat['session']
  #header_para = req_para_cat['header']
  #cookie_para = req_para_cat['cookie']
  #device_para = req_para_cat['device']
  reqSubVal = json.load(open(os.path.join(folder_location,'request_para_sub'+appendix)))
  #header_para = json.load(open(folder_location+'/request_para_header'+appendix))
  #cookie_para = json.load(open(folder_location+'/request_para_cookie'+appendix))

  global g_ignoreHeaders
  #ignoreHeaders = ['content-length', 'cookie', 'set-cookie']

  uri = extractor.extract_uri(url)
  # NetlocPath = extractor.extract_netloc(url) + extractor.extract_path(url)

  uniqueUri = extractor.remove_http_scheme(uniqueUri)
  uri2 = uniqueUri
  # The uri is not the uris of our interest.
  if uniqueUri not in user_para and uniqueUri not in session_para:
    return

  # replay the request without any changes of the parameter and check if the response is the same or not
  # if it is the same, then it means we can recover the context. Otherwise, we directly add those parameters that are user-dependant or session-dependant
  # import pdb; pdb.set_trace()
  queryString = {key.encode('utf-8'): queryString[key].encode('utf-8') for key in queryString}
  resp = toServer(uri+'?'+urllib.urlencode(queryString), method, params, newCookies, newHeaders)
  
  #pdb.set_trace()
  # if resp == None:
  #   # running_logger.error('Unable to open '+uri+'?'+urllib.urlencode(queryString))
  # The response is different (therefore changing other parameters is useless)
  if resp == None or diffResp("recover context", response, resp):
    # uri2 = extractor.extract_uri(url, False)
    for obj in [rmGKeys, rmPKeys, rmHKeys, rmCKeys]:
      if uri2 not in obj:
        obj[uri2] = []

    for obj in [alterGKeys, alterPKeys, alterHKeys, alterCKeys]:
      if uri2 not in obj:
        obj[uri2] = {}

    for p in set(session_para[uri2]['get']).union(set(user_para[uri2]['get'])):
      if p not in rmGKeys[uri2]:
        rmGKeys[uri2].append(p)

      if p not in alterGKeys[uri2]:
        repVal = ''
        if uri2 in reqSubVal and p in reqSubVal[uri2]['get']:
          repVal = reqSubVal[uri2]['get'][p]
        if repVal == '':
          running_logger.error('Unable to find replace value in '+uri+' for get '+p)
        alterGKeys[uri2][p] = repVal
    
    for p in set(session_para[uri2]['post']).union(set(user_para[uri2]['post'])):
      if p not in rmPKeys[uri2]:
        rmPKeys[uri2].append(p)

      if p not in alterPKeys[uri2]:
        repVal = ''
        if uri2 in reqSubVal:
          if p in reqSubVal[uri2]['post']:
            repVal = reqSubVal[uri2]['post'][p]
          else:
            for pp in reqSubVal[uri2]['post']:
              if isinstance(reqSubVal[uri2]['post'][pp], dict) and p in reqSubVal[uri2]['post'][pp]:
                repVal = reqSubVal[uri2]['post'][pp][p]
                break
        if repVal == '':
          running_logger.error('Unable to find replace value in '+uri+' for post '+p)
        alterPKeys[uri2][p] = repVal

    if fuzzyHC:
      for p in set(session_para[uri2]['header']).union(set(user_para[uri2]['header'])):
        #If header has cookie, ignore it since cookie will be handled separately
        if p.lower() in g_ignoreHeaders:
          continue
        if p not in rmHKeys[uri2]:
          rmHKeys[uri2].append(p)

        if p not in alterHKeys[uri2]:
          repVal = ''
          if uri2 in reqSubVal and p in reqSubVal[uri2]['header']:
            repVal = reqSubVal[uri2]['header'][p]
          if repVal == '':
            running_logger.error('Unable to find replace value in '+uri+' for header '+p)
          alterHKeys[uri2][p] = repVal

      for p in set(session_para[uri2]['cookie']).union(set(user_para[uri2]['cookie'])):
        if p not in rmCKeys[uri2]:
          rmCKeys[uri2].append(p)

        if p not in alterCKeys[uri2]:
          repVal = ''
          if uri2 in reqSubVal and p in reqSubVal[uri2]['cookie']:
            repVal = reqSubVal[uri2]['cookie'][p]
          if repVal == '':
            running_logger.error('Unable to find replace value in '+uri+' for cookie '+p)
          alterCKeys[uri2][p] = repVal
  
    jsonDumpKeyPara(uniqueUri, rmGKeys, rmPKeys, rmHKeys, rmCKeys, alterGKeys, alterPKeys, alterHKeys, alterCKeys, folder_location, appendix)
    return 

  #We can recover the context to replay
  #uri2 = extractor.extract_uri(url, False)
  #Remove one of the get key
  for p in queryString:
    #Bypass time related and device related parameters
    if p not in session_para[uniqueUri]['get'] and p not in user_para[uniqueUri]['get']:
      continue
    newQuery = queryString.copy()
    buf = newQuery.pop(p)
    if uri2 not in rmGKeys:
      rmGKeys[uri2] = []

    try:
      # import pdb; pdb.set_trace()
      resp = toServer(uri+'?'+urllib.urlencode(newQuery), method, params, newCookies, newHeaders)
      if resp == None:
        # running_logger.error('Unable to open '+uri+'?'+urllib.urlencode(newQuery))
        print 'Unable to open '+uri+'?'+urllib.urlencode(newQuery)

      if diffResp('Get Remove '+p, response, resp):
        if p not in rmGKeys[uri2]:
          rmGKeys[uri2].append(p)
    except:
      pass 
  
  #Remove one of the post key
  if params != None:
    for p in params:
      # uri = extractor.extract_uri(url)
      #Bypass time related and device related parameters
      if p not in session_para[uniqueUri]['post'] and p not in user_para[uniqueUri]['post']:
        continue
      if type(params) != dict:
        continue
      # print uri, p
      newQuery = params.copy()
      buf = newQuery.pop(p)
      if uri2 not in rmPKeys:
        rmPKeys[uri2] = []
      try:
        resp = toServer(uri+'?'+urllib.urlencode(queryString), method, newQuery, newCookies, newHeaders)
        if resp == None:
          # running_logger.error('Unable to open '+uri+'?'+urllib.urlencode(queryString))
          print 'Unable to open '+uri+'?'+urllib.urlencode(queryString)
          rmPKeys[uri2].append(p)
        if diffResp('Post Remove '+p, response, resp):
          if p not in rmPKeys[uri2]:
            rmPKeys[uri2].append(p)
      except:
        pass
  
  #Remove one of the header key
  for p in newHeaders:
    #If header has cookie, ignore it since cookie will be handled separately
    if p.lower() in g_ignoreHeaders:
      continue
    if p not in session_para[uniqueUri]['header'] and p not in user_para[uniqueUri]['header']:
      continue

    tmpHeaders = newHeaders.copy()
    buf = tmpHeaders.pop(p)
    if uri2 not in rmHKeys:
      rmHKeys[uri2] = []

    try:
      resp = toServer(uri+'?'+urllib.urlencode(queryString), method, params, newCookies, tmpHeaders)
      if resp == None:
        # running_logger.error('Unable to open '+uri+'?'+urllib.urlencode(newQuery))
        print 'Unable to open '+uri+'?'+urllib.urlencode(queryString)

      if diffResp('Header Remove '+p, response, resp):
        if p not in rmHKeys[uri2]:
          rmGKeys[uri2].append(p)
    except:
      pass 

  #Remove one of the cookie key
  for p in newCookies:
    if p not in session_para[uniqueUri]['cookie'] and p not in user_para[uniqueUri]['cookie']:
      continue

    tmpCookies = newCookies.copy()
    buf = tmpCookies.pop(p)
    if uri2 not in rmCKeys:
      rmCKeys[uri2] = []

    try:
      resp = toServer(uri+'?'+urllib.urlencode(queryString), method, params, tmpCookies, newHeaders)
      if resp == None:
        # running_logger.error('Unable to open '+uri+'?'+urllib.urlencode(newQuery))
        print 'Unable to open '+uri+'?'+urllib.urlencode(queryString)

      if diffResp('Cookie Remove '+p, response, resp):
        if p not in rmCKeys[uri2]:
          rmCKeys[uri2].append(p)
    except:
      pass 

  #Alter get parameter value
  for p in queryString:
    if p not in session_para[uniqueUri]['get'] and p not in user_para[uniqueUri]['get']:
      continue
    newQuery = queryString.copy()
    newQuery[p] = checkTypeAlter(url, p, newQuery[p])
    if uri2 not in alterGKeys:
      alterGKeys[uri2] = {}
    resp = toServer(uri+'?'+urllib.urlencode(newQuery), method, params, newCookies, newHeaders)
    if resp == None:
      running_logger.error('Unable to open '+uri+'?'+urllib.urlencode(newQuery))
    if diffResp('Get Modify '+p, response, resp):
      if p not in alterGKeys[uri2]:
        repVal = ''
        if uri2 in reqSubVal and p in reqSubVal[uri2]['get']:
          repVal = reqSubVal[uri2]['get'][p]
        alterGKeys[uri2][p] = repVal

  #Alter post parameter
  if params != None:
    for p in params:
      if p not in session_para[uniqueUri]['post'] and p not in user_para[uniqueUri]['post']:
        continue
      if type(params) != dict:
        continue
      newQuery = params.copy()
      newQuery[p] = checkTypeAlter(url, p, newQuery[p])
      #if p == 'UID':
      # newQuery[p] = '_wb337823091'
      if uri2 not in alterPKeys:
        alterPKeys[uri2] = {}
      resp = toServer(uri+'?'+urllib.urlencode(queryString), method, newQuery, newCookies, newHeaders)
      if resp == None:
        running_logger.error('Unable to open '+uri+'?'+urllib.urlencode(queryString))
      if diffResp('Post Modify '+p, response, resp):
        if p not in alterPKeys[uri2]:
          repVal = ''
          if uri2 in reqSubVal:
            if p in reqSubVal[uri2]['post']:
              repVal = reqSubVal[uri2]['post'][p]
            else:
              for pp in reqSubVal[uri2]['post']:
                if p in reqSubVal[uri2]['post'][pp]:
                  repVal = reqSubVal[uri2]['post'][pp][p]
                  break
          alterPKeys[uri2][p] = repVal

  #Alter header parameter value
  for p in newHeaders:
    #If header has cookie, ignore it since cookie will be handled separately
    if p.lower() in g_ignoreHeaders:
      continue
    if p not in session_para[uniqueUri]['header'] and p not in user_para[uniqueUri]['header']:
      continue

    tmpHeaders = newHeaders.copy()
    tmpHeaders[p] = checkTypeAlter(url, p, tmpHeaders[p], True)
    if uri2 not in alterHKeys:
      alterHKeys[uri2] = {}
    resp = toServer(uri+'?'+urllib.urlencode(queryString), method, params, newCookies, tmpHeaders)
    if resp == None:
      running_logger.error('Unable to open '+uri+'?'+urllib.urlencode(queryString))
    if diffResp('Header Modify '+p, response, resp):
      if p not in alterHKeys[uri2]:
        repVal = ''
        if uri2 in reqSubVal and p in reqSubVal[uri2]['header']:
          repVal = reqSubVal[uri2]['header'][p]
        alterHKeys[uri2][p] = repVal

  #Alter header parameter value
  for p in newCookies:
    if p not in session_para[uniqueUri]['cookie'] and p not in user_para[uniqueUri]['cookie']:
      continue

    tmpCookies = newCookies.copy()
    tmpCookies[p] = checkTypeAlter(url, p, tmpCookies[p], False)
    if uri2 not in alterCKeys:
      alterCKeys[uri2] = {}
    resp = toServer(uri+'?'+urllib.urlencode(queryString), method, params, tmpCookies, newHeaders)
    if resp == None:
      running_logger.error('Unable to open '+uri+'?'+urllib.urlencode(queryString))
    if diffResp('Cookie Modify '+p, response, resp):
      if p not in alterCKeys[uri2]:
        repVal = ''
        if uri2 in reqSubVal and p in reqSubVal[uri2]['cookie']:
          repVal = reqSubVal[uri2]['cookie'][p]
        alterCKeys[uri2][p] = repVal

  #Output paramaters to json files
  jsonDumpKeyPara(uniqueUri, rmGKeys, rmPKeys, rmHKeys, rmCKeys, alterGKeys, alterPKeys, alterHKeys, alterCKeys, folder_location, appendix)
  return

def jsonDumpKeyPara(url, rmGKeys, rmPKeys, rmHKeys, rmCKeys, alterGKeys, alterPKeys, alterHKeys, alterCKeys, folder_location, appendix):
  import os
  from os.path import isfile
  if isfile(os.path.join(folder_location,'request_para'+appendix)):
    paraSet = json.load(open(os.path.join(folder_location,'request_para'+appendix)))
  else:
    paraSet = {}
  newuri = extractor.extract_uri(url, False)
  while newuri in paraSet:
    try:
      temp_uri, temp_key = newuri.split("{")
      newuri = temp_uri + "+{" + temp_key
    except:
      newuri += '+'

  for uri in rmPKeys:
    if newuri not in paraSet:
      paraSet[newuri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}
    for p in rmPKeys[uri]:
      paraSet[newuri]['post'].append({p:['rm']})

  for uri in alterPKeys:
    if newuri not in paraSet:
      paraSet[newuri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}
    for p in alterPKeys[uri]:
      if {p:['rm']} not in paraSet[newuri]['post']:
        paraSet[newuri]['post'].append({p:['ran', 'rep'], 'replacedValue':alterPKeys[uri][p]})
      else:
        tmpTarInd = paraSet[newuri]['post'].index({p:['rm']})
        paraSet[newuri]['post'][tmpTarInd][p] += ['ran', 'rep']
        paraSet[newuri]['post'][tmpTarInd]['replacedValue'] = alterPKeys[uri][p]

  for uri in rmGKeys:
    if newuri not in paraSet:
      paraSet[newuri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}
    for p in rmGKeys[uri]:
      paraSet[newuri]['get'].append({p:['rm']})

  for uri in alterGKeys:
    if newuri not in paraSet:
      paraSet[newuri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}
    for p in alterGKeys[uri]:
      if {p:['rm']} not in paraSet[newuri]['get']:
        paraSet[newuri]['get'].append({p:['ran', 'rep'], 'replacedValue':alterGKeys[uri][p]})
      else:
        tmpTarInd = paraSet[newuri]['get'].index({p:['rm']})
        paraSet[newuri]['get'][tmpTarInd][p] += ['ran', 'rep']
        paraSet[newuri]['get'][tmpTarInd]['replacedValue'] = alterGKeys[uri][p]

  for uri in rmHKeys:
    if newuri not in paraSet:
      paraSet[newuri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}
    for p in rmHKeys[uri]:
      paraSet[newuri]['header'].append({p:['rm']})

  for uri in alterHKeys:
    if newuri not in paraSet:
      paraSet[newuri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}
    for p in alterHKeys[uri]:
      if {p:['rm']} not in paraSet[newuri]['header']:
        paraSet[newuri]['header'].append({p:['ran', 'rep'], 'replacedValue':alterHKeys[uri][p]})
      else:
        tmpTarInd = paraSet[newuri]['header'].index({p:['rm']})
        paraSet[newuri]['header'][tmpTarInd][p] += ['ran', 'rep']
        paraSet[newuri]['header'][tmpTarInd]['replacedValue'] = alterHKeys[uri][p]

  for uri in rmCKeys:
    if newuri not in paraSet:
      paraSet[newuri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}
    for p in rmCKeys[uri]:
      paraSet[newuri]['cookie'].append({p:['rm']})

  for uri in alterCKeys:
    if newuri not in paraSet:
      paraSet[newuri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}
    for p in alterCKeys[uri]:
      if {p:['rm']} not in paraSet[newuri]['cookie']:
        paraSet[newuri]['cookie'].append({p:['ran', 'rep'], 'replacedValue':alterCKeys[uri][p]})
      else:
        tmpTarInd = paraSet[newuri]['cookie'].index({p:['rm']})
        paraSet[newuri]['cookie'][tmpTarInd][p] += ['ran', 'rep']
        paraSet[newuri]['cookie'][tmpTarInd]['replacedValue'] = alterCKeys[uri][p]

  json.dump(paraSet, open(os.path.join(folder_location,'request_para'+appendix), 'w+'))
  return

#For str and int
def checkTypeAlter(url, key, val, isHeader=False):
  import random
  import extractor

  newVal = None

  if isHeader:
    if key == 'Accept':
      possibleVs = ['application/xml','application/xhtml+xml','text/html', 'text/plain', 'image/jpeg, application/x-ms-application, image/gif', 'application/x-ms-xbap', 'application/x-shockwave-flash', 'application/msword', 'image/jxr', '*/*']
      newVal = possibleVs[random.randint(0, len(possibleVs)-1)]
      while newVal == val.lower():
        newVal = possibleVs[random.randint(0, len(possibleVs)-1)]
    elif key == 'Cache-Control':
      possibleVs = ['no-store', 'no-cache', 'must-revalidate', 'private', 'public', 'max-age=31536000', 'max-age=10', 
      'max-stale=10', 'max-stale=31536000', 'min-fresh=10', 'min-fresh=3600', 'no-transform', 'only-if-cached', 'must-revalidate',
      's-maxage=10', 's-maxage=31536000']
      newVal = possibleVs[random.randint(0, len(possibleVs)-1)]
      while newVal == val.lower():
        newVal = possibleVs[random.randint(0, len(possibleVs)-1)]
    elif key == 'Connection':
      possibleVs = ['keep-alive', 'close']
      newVal = possibleVs[random.randint(0, len(possibleVs)-1)]
      while newVal == val.lower():
        newVal = possibleVs[random.randint(0, len(possibleVs)-1)]
    elif key == 'Referer':
      newVal = 'http://www.baidu.com'
    elif key == 'Host':
      newVal = 'http://www.baidu.com'
    elif key == 'Authorization':
      newVal = 'BASIC Z3Vlc3Q6Z3Vlc3QxMjM='
    elif key == 'If-Modified-Since':
      newVal = 'Sat, 29 Oct 1994 19:43:31 GMT'
    elif key == 'If-Unmodified-Since':
      newVal = 'Sat, 29 Oct 2050 19:43:31 GMT'
    elif key == 'User-Agent':
      newVal = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/604.4.7 (KHTML, like Gecko) Version/11.0.2 Safari/604.4.7'
    elif key == 'Age':
      newVal = '30'
    elif key == 'Max-Forwards':
      newVal = '1'
    elif key == 'Server':
      newVal = 'Apache/2.2.14 (Win32)'
    elif key == 'Set-Cookie':
      ckVal = val.split(';')[0].split(',')[0].split('=')[1].strip()
      newVal = val.replace(ckVal, ''.join(random.sample(ckVal, len(ckVal))))
    elif key == 'Expires':
      newVal = 'Thu, 01 Dec 1994 16:00:00 GMT'
    elif key == 'Origin':
      newVal = 'http://www.baidu.com'
    else:
      running_logger.error('Haven\'t implement header '+key)
      newVal =''.join(random.sample(val, len(val)))
    return newVal

  #Apply pre-defined method to 
  if extractor.is_IdPReq(url):
    if isinstance(key, list):
      if 'access_token' in key or 'refresh_token' in key:
        newVal = val[:-1]+'W'
      elif 'scope' in key:
        newVal = val+',all' #This is for Weibo. Other platforms may need to change scope
      elif 'uid' in key:
        #Conduct +1 operation in later part
        pass
    else: 
      if key == 'quick_auth':
        if val == 'false':
          newVal = 'true'
        else:
          newVal = 'false'
      elif key == 'access_token':
        newVal = val[:-1]+'W'
      elif key == 'scope':
        newVal = val+',all' #This is for Weibo. Other platforms may need to change scope
      elif key == 'redirect_uri':
        newVal = 'http://www.baidu.com'
      elif key == 'packagename':
        newVal = 'test.ios.com'
    if newVal != None:
      return newVal

  if not isinstance(val, unicode):
    val = str(val)
  try:
    if val.isdigit():
      newVal = str(int(val)+1)
    else:
      newVal = ''.join(random.sample(val, len(val)))
  except:
    newVal = ''.join(random.sample(val, len(val)))

  return newVal

#Check if value is time related so that filter it out from the key parameters
def isTime(inputStr):
  from datetime import datetime, timedelta
  from dateutil import parser

  #If key is time or timing, can just assume it's time type

  if not isinstance(inputStr, str) and not isinstance(inputStr, unicode) and not isinstance(inputStr, int):
    return False

  #If it's second or milisecond
  if isinstance(inputStr, int):
    # for integer, it can be easily report false positive (e.g., uid). for safety, we just assume it is not time-related 
    return False
    # epoch=datetime(1970, 1, 1)
    # try:
    #   #If it's milisecond
    #   if inputStr > 1000000000000:
    #     timedelta(milliseconds=inputStr)
    #   #If it's second
    #   elif inputStr > 1000000000:
    #     timedelta(seconds=inputStr)
    #   else:
    #     return False
    # except:
    #   return False
    # finally:
    #   return True

  #if it's tring, parse it
  try:
    t = parser.parse(inputStr)
    # t = dateparser.parse(inputStr)
    if isinstance(t, datetime.datetime):
      print "istime:\t"+inputStr
      return True
    else:
      return False
  except:
    return False
  #finally:
  # return True
  return False

#compare the response after changing the request parameters 
def diffResp(title, groundResp, testResp):
  import csv
  import json
  from ast import literal_eval

  outputf = open('report.csv', 'a')
  report = csv.writer(outputf, delimiter=',')

  report.writerow([title.encode('utf-8').strip(), '', ''])
  diffContent = []

  if testResp == None:
    return False

  #Test response status
  #Comment this block if no need to test
  if testResp.status_code != groundResp['status']:
    diffContent = ['Statue code', groundResp['status'], testResp.status_code]
    report.writerow(diffContent)

  if testResp.reason != groundResp['statusText']:
    diffContent = ['Statue text', groundResp['statusText'], testResp.reason]
    report.writerow(diffContent)

  #Test Cookie
  #Comment this block if no need to test
  #testCookies = testResp.cookies.get_dict()
  #for ck in groundResp['cookies']:
  # if ck['name'] in testCookies and ck['value'] == testCookies[ck['name']]:
  #   pass
  # else:
  #   reportContent = ['Cookie', ck['name']+','+ck['value'], '']
  #   if ck['name'] in testCookies:
  #     reportContent[2] = ck['name']+','+testCookies[ck['name']]
  #   report.writerow(reportContent)
  #if len(testCookies) != len(groundResp['cookies']):
  # reportContent = ['Cookie count', len(groundResp['cookies']), len(testCookies)]
  # report.writerow(reportContent)

  #Test response content
  #Comment this block if no need to test
  
  try:
    respText = testResp.text.decode('utf-8')
  except:
    respText = repr(testResp.text)
  
  respText = re.sub(r'\s', '', respText)
  groundResp['content']['text'] = re.sub(r'\s', '', groundResp['content']['text'])
  #Facebook add some strings in front of a json
  respText = respText.replace('for(;;);', '')
  groundResp['content']['text'] = groundResp['content']['text'].replace('for(;;);', '')

  if respText != groundResp['content']['text']:
    # content length may be zero 
    if (isJson(respText) and isJson(groundResp['content']['text'])) or ('Content-Type' in testResp and 'json' in testResp.headers['Content-Type'] and 'json' in groundResp['content']['mimeType']):
      if diffJson(groundResp['content']['text'], respText, False):
        diffContent = ['Content', groundResp['content']['text'], respText]
        report.writerow([s.encode('utf-8') for s in diffContent])
      else:
        #Detect if has error message
        try:
          tJson = json.loads(respText)
        except:
          tJson = json.loads(literal_eval(respText))
        try:
          gJson = json.loads(groundResp['content']['text'])
        except:
          gJson = json.loads(literal_eval(groundResp['content']['text']))

        detectDiff = False
        for k0 in tJson:
          if isinstance(tJson[k0], dict):
            for k1 in tJson[k0]:
              if 'error' in repr(tJson[k0][k1]) and 'error' not in repr(gJson[k0][k1]):
                detectDiff = True
                break
            if detectDiff:
              break
          else:
            if 'error' in repr(tJson[k0]) and 'error' not in repr(gJson[k0]):
              detectDiff = True
              break
        if detectDiff:
          diffContent = ['Content', groundResp['content']['text'], respText]
      # try:
        # if diffJson(groundResp['content']['text'], respText, True):
        #   diffContent = ['Content', groundResp['content']['text'], respText]
        #   report.writerow(diffContent)
      # except:
      #   diffContent = []
    else:
      diffContent = ['Content', groundResp['content']['text'], respText]
      report.writerow([s.encode('utf-8') for s in diffContent])

  #Test Header
  #Comment this block if no need to test
  #for h in groundResp['headers']:
  # if h['name'] in testResp.headers  and h['value'] == testResp.headers[h['name']]:
  #   pass
  # else:
  #   reportContent = ['header', h['name']+','+h['value'], '']
  #   if h['name'] in testResp.headers:
  #     reportContent[2] = h['name']+','+testResp.headers[h['name']]
  #   report.writerow(reportContent)
  #if len(testResp.headers) != len(groundResp['headers']):
  # reportContent = ['Headers count', len(groundResp['headers']), len(testCookies.headers)]
  # report.writerow(reportContent)

  #diffContent != 0 means server has detected abnormal request and handled it.
  if len(diffContent) == 0:
    report.writerow(['All the same', '', ''])
    outputf.close()
    return False
  else:
    outputf.close()
    return True

#only return True or False
def diffJson(groundStr, testStr, onlyKeys=False):
  import json
  from ast import literal_eval
  #import collections
  if not groundStr:
    if testStr:
      return True
    else:
      return False
  elif not testStr:
    return True
  # if groundStr == '':
  #   if testStr != '':
  #     return True
  #   else:
  #     return False
  # elif testStr == '' or testStr == :
  #   return True

  # test whether testStr/groundStr is json object or not
  # if it is not json, then assign an empty map to tJson/gJson
  if isJson(testStr):
    try:
      tJson = json.loads(testStr)
    except:
      tJson = json.loads(literal_eval(testStr))
  else:
    tJson = {}
  
  if type(tJson) is list:
    tJson = tJson[0] if len(tJson) > 0 else {}

  if isJson(groundStr):
    try:
      gJson = json.loads(groundStr)
    except:
      gJson = json.loads(literal_eval(groundStr))
  else:
    gJson = {}

  if type(gJson) is list:
    gJson = gJson[0]

  #Compare key difference
  #Compare = lambda x, y: collections.Counter(x) == collections.Counter(y)
  tKeys = []
  for k in tJson:
    if isinstance(tJson[k], dict):
      for sk in tJson[k]:
        tKeys.append(sk)
    else:
      tKeys.append(k)
  gKeys = []
  for k in gJson:
    if isinstance(gJson[k], dict):
      for sk in gJson[k]:
        gKeys.append(sk)
    else:
      gKeys.append(k)
  
  if set(tKeys) != set(gKeys):
    return True

  if onlyKeys:
    return False

  result = compareJsons(gJson, tJson)
  if len(result) == 0:
    return False
  else:
    return True

def toServer(url, method, postData=None, cookies=None, headers=None):
  import requests
  import time

  if url[:4].lower() != 'http':
    url = 'http://'+url

  trylimits = 1
  cnt = 0
  #parseData = {}
  #for pair in postData:
  # parseData[pair['name']] = pair['value']
  #when fuzz cookie, should also change header
  if cookies != None and headers != None:
    headers['Cookie'] = []
    for ckKey in cookies:
      if ckKey is not None and cookies[ckKey] is not None:
        headers['Cookie'].append(ckKey+'='+cookies[ckKey])
    headers['Cookie'] = ';'.join(headers['Cookie'])
  
  resp = None
  while True:
    try:
      if method == 'GET':
        resp = requests.get(url, timeout = 30, cookies=cookies, headers=headers)
      elif method == 'POST':
        resp = requests.post(url, timeout = 30, data=postData, cookies=cookies, headers=headers)
      break
    except:
      cnt+=1
      if cnt < trylimits:
        time.sleep(5)
        continue
      else:
        return None
  return resp


################################################################################

#Compare different network traces and get user specified/ device specified keys in json response and request
#Input are network trace files
def getUDKeys(eveDeviceAFile, eveDeviceBFile, aliceDeviceAFile, eveDeviceA2File, appendix, folder_location, idp_name='sina'):
  import extractor
  import collections
  from collections import Counter as mset
  import json
  import os
  import toolTesting
  from urlparse import urlsplit, urlunsplit

  g_appinfo = json.load(open('appinfo.json', 'r'))
  domainName = g_appinfo['appNetloc']
  IdPUris = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"].values()
  IdPReturnUri = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"]['EveIdP_Auth'] 
  IdPDomain = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]['domain']
  fuzzyHC = json.load(open('config.json', 'r'))['fuzzy_headercookie']

  userIdentifierFound = True

  with open(eveDeviceAFile, 'r') as f:
    rawTrace = json.load(f)
    eveAraw = extractor.clean_trace(rawTrace['log']['entries'], [IdPDomain, g_appinfo['appNetloc']], False, idp_name)
  with open(eveDeviceBFile, 'r') as f:
    rawTrace = json.load(f)
    eveBraw = extractor.clean_trace(rawTrace['log']['entries'], [IdPDomain, g_appinfo['appNetloc']], False, idp_name)
  with open(aliceDeviceAFile, 'r') as f:
    rawTrace = json.load(f)
    aliceAraw = extractor.clean_trace(rawTrace['log']['entries'], [IdPDomain, g_appinfo['appNetloc']], False, idp_name)
  with open(eveDeviceA2File, 'r') as f:
    rawTrace = json.load(f)
    eveA2raw = extractor.clean_trace(rawTrace['log']['entries'], [IdPDomain, g_appinfo['appNetloc']], False, idp_name)

  # Align RPApp-RPServer request order
  # note: for every request, we dintinguish them by uri and postData(querySting) respectively
  # pending: implement network trace alignment algorithm in this situation
  urlset = None
  for targetTrace in [eveAraw, eveBraw, aliceAraw, eveA2raw]:
    # import pdb; pdb.set_trace()
    if urlset == None: 
      urlset = set([extractor.extract_uri(header['request']['url']) for header in targetTrace])
    else:
      urlset = urlset & set([extractor.extract_uri(header['request']['url']) for header in targetTrace])
  urllist = []
  for header in eveAraw:
    uri = extractor.extract_uri(header['request']['url'])
    if uri in urlset:
      # if extractor.remove_http_scheme(uri) not in IdPUris:
      if not isInIdPUris(extractor.remove_http_scheme(header['request']['url']), IdPUris):
        # keyhash = RequestIndex(header)
        urllist.append(addHash4Request(header, idp_name))
      else:
        urllist.append(uri)
  # import pdb; pdb.set_trace()
  # change here, compare uri and the request parameter pool
  eid = 0
  urimap = {}
  for key in urllist:
    while key in urimap:
      try:
        temp_uri, temp_key = key.split("{")
        key = temp_uri + "+{" + temp_key
      except:
        key += '+'
        # import pdb; pdb.set_trace()
      # key = (temp_str, key[1], key[2])
    urimap[key] = eid
    eid += 1
  # urimap = {k: v for v, k in enumerate(urllist)}
  minCnt = len(urimap)
  eveA = [None]*minCnt
  eveB = [None]*minCnt
  aliceA = [None]*minCnt
  eveA2 = [None]*minCnt
  i=0

  for targetpair in [(eveAraw,eveA), (eveBraw,eveB), (aliceAraw,aliceA), (eveA2raw, eveA2)]:
    i += 1
    for header in targetpair[0]:
      uri = extractor.extract_uri(header['request']['url'])
      # if extractor.remove_http_scheme(uri) in IdPUris:
      if isInIdPUris(extractor.remove_http_scheme(header['request']['url']), IdPUris):
        uniqueIndex = uri
        # change Facebook's response for one URI as dictionary so that we can compare/ represent them in a better/ original way
        if idp_name == 'fb':
          # if 'm.facebook.com/v2.5/dialog/oauth/confirm' in uri:
          #   import pdb; pdb.set_trace()
          if re.search(IdPReturnUri, header['request']['url']) != None:
            header['response']['content']['text'] = decoupleFBResponse(header['response']['content']['text'])[1]
          elif 'm.facebook.com/login/async/' in header['request']['url']:
            header['response']['content']['text'] = json.loads(header['response']['content']['text'][9:])
      else:
        # keyhash = RequestIndex(header)
        # uniqueIndex = uri + "{" + keyhash
        uniqueIndex = addHash4Request(header, idp_name)
      if uniqueIndex in urimap:
        while uniqueIndex in urimap and targetpair[1][urimap[uniqueIndex]] != None:
          # if extractor.remove_http_scheme(uri) in IdPUris:
          if isInIdPUris(extractor.remove_http_scheme(header['request']['url']), IdPUris):

            # If the uri belongs to the IdP domain， then we only use + (the )
            uniqueIndex += '+'
          else:
            temp_uri, temp_key = uniqueIndex.split('{')
            temp_uri += '+'
            uniqueIndex = temp_uri + '{' + temp_key
        # replace the original url with the unique urlElements
        urlElements = list(urlsplit(header['request']['url']))
        urlElements[0] =''
        urlElements[1] = uniqueIndex
        urlElements[2] =''
        # import pdb; pdb.set_trace()
        header['request']['url'] = urlunsplit(urlElements).strip("//")
        if uniqueIndex in urimap:
          targetpair[1][urimap[uniqueIndex]] = header

  #Response paras 
  usersKey = collections.defaultdict(list)
  devicesKey = collections.defaultdict(list)
  sessionsKey = collections.defaultdict(list)

  #Response Header
  #respHeaderUsersKey = collections.defaultdict(list)
  #respHeaderDevicesKey = collections.defaultdict(list)
  #respHeaderSessionsKey = collections.defaultdict(list)

  #Response Cookies
  #respCokUsersKey = collections.defaultdict(list)
  #respCokDevicesKey = collections.defaultdict(list)
  #respCokSessionsKey = collections.defaultdict(list)

  global g_ignoreHeaders
  #ignoreHeaders = ['content-length', 'cookie', 'set-cookie']

  # todo: analyze user parameter and get the terminal url for oauth 2.0
  for eid in range(len(eveA)):
    if eveA[eid] == None:
      continue
    uri = extractor.extract_uri(eveA[eid]['request']['url'], False)
    # keyhash = RequestIndex(eveA[eid])
    # uri = uri +'{' + keyhash
    # distinguish different response with the same uri in usersKey  
    while uri in usersKey:
      # import pdb; pdb.set_trace()
      # if extractor.remove_http_scheme(uri) in IdPUris:
      if isInIdPUris(extractor.remove_http_scheme(header['request']['url']), IdPUris):
        uri += '+'
      else:
        temp_uri, keyhash = uri.split('{')
        temp_uri += "+" 
        uri = temp_uri + '{'+ keyhash

    if eveB[eid] != None:
      difList = compareJsons(eveA[eid]['response']['content'], eveB[eid]['response']['content'], True)
      difList = filter(lambda x: x[0] != 'size' and x[0] != 'compression', difList)
      if len(difList) > 0:
        for difl in difList:
          devicesKey[uri].append({'path':difl, 'operation':['rm', 'ran', 'rep']})

      if fuzzyHC:
        #Headers
        difList = compareJsons(jsonizeHeader(eveA[eid]['response']['headers']), jsonizeHeader(eveB[eid]['response']['headers']), True, False)
        if len(difList) > 0:
          for difl in difList:
            if difl[0].lower() not in g_ignoreHeaders:
              #Wechat embed code and state into header
              if difl[0].lower() == 'location' and idp_name == 'wechat' and 'connect/oauth2/authorize_reply' in uri:
                devicesKey[uri].append({'path':['header']+[difl[0]]+['code', difl[1].split('?')[1].split('code=')[1].split('&')[0]], 'operation':['rm', 'ran', 'rep']})
                devicesKey[uri].append({'path':['header']+[difl[0]]+['state', difl[1].split('?')[1].split('state=')[1].split('&')[0]], 'operation':['rm', 'ran', 'rep']})
              else:
                devicesKey[uri].append({'path':['header']+difl, 'operation':['rm', 'ran', 'rep']})

        #Cookies
        difList = compareJsons(jsonizeHeader(eveA[eid]['response']['cookies']), jsonizeHeader(eveB[eid]['response']['cookies']), True, False)
        if len(difList) > 0:
          for difl in difList:
            devicesKey[uri].append({'path':['cookie']+difl, 'operation':['rm', 'ran', 'rep']})

    if aliceA[eid] != None:
      difList = compareJsons(eveA[eid]['response']['content'], aliceA[eid]['response']['content'], True)
      difList = filter(lambda x: x[0] != 'size' and x[0] != 'compression', difList)
      if len(difList) > 0:
        for difl in difList:
          usersKey[uri].append({'path':difl, 'operation':['rm', 'ran', 'rep']})

      if fuzzyHC:
        #Headers
        difList = compareJsons(jsonizeHeader(eveA[eid]['response']['headers']), jsonizeHeader(aliceA[eid]['response']['headers']), True, False)
        if len(difList) > 0:
          for difl in difList:
            if difl[0].lower() not in g_ignoreHeaders:
              #Wechat embed code and state into header
              if difl[0].lower() == 'location' and idp_name == 'wechat' and 'connect/oauth2/authorize_reply' in uri:
                usersKey[uri].append({'path':['header']+[difl[0]]+['code', difl[1].split('?')[1].split('code=')[1].split('&')[0]], 'operation':['rm', 'ran', 'rep']})
                usersKey[uri].append({'path':['header']+[difl[0]]+['state', difl[1].split('?')[1].split('state=')[1].split('&')[0]], 'operation':['rm', 'ran', 'rep']})
              else:
                usersKey[uri].append({'path':['header']+difl, 'operation':['rm', 'ran', 'rep']})

        #Cookies
        difList = compareJsons(jsonizeHeader(eveA[eid]['response']['cookies']), jsonizeHeader(aliceA[eid]['response']['cookies']), True, False)
        if len(difList) > 0:
          for difl in difList:
            usersKey[uri].append({'path':['cookie']+difl, 'operation':['rm', 'ran', 'rep']})
    
    if eveA2[eid] != None:
      difList = compareJsons(eveA[eid]['response']['content'], eveA2[eid]['response']['content'], True)
      difList = filter(lambda x: x[0] != 'size' and x[0] != 'compression', difList)
      if len(difList) > 0:
        for difl in difList:
          sessionsKey[uri].append({'path':difl, 'operation':['rm', 'ran', 'rep']})

      if fuzzyHC:
        #Headers
        difList = compareJsons(jsonizeHeader(eveA[eid]['response']['headers']), jsonizeHeader(eveA2[eid]['response']['headers']), True, False)
        if len(difList) > 0:
          for difl in difList:
            if difl[0].lower() not in g_ignoreHeaders:
              if difl[0].lower() == 'location' and idp_name == 'wechat' and 'connect/oauth2/authorize_reply' in uri:
                sessionsKey[uri].append({'path':['header']+[difl[0]]+['code', difl[1].split('?')[1].split('code=')[1].split('&')[0]], 'operation':['rm', 'ran', 'rep']})
                sessionsKey[uri].append({'path':['header']+[difl[0]]+['state', difl[1].split('?')[1].split('state=')[1].split('&')[0]], 'operation':['rm', 'ran', 'rep']})
              else:
                sessionsKey[uri].append({'path':['header']+difl, 'operation':['rm', 'ran', 'rep']})

        #Cookies
        difList = compareJsons(jsonizeHeader(eveA[eid]['response']['cookies']), jsonizeHeader(eveA2[eid]['response']['cookies']), True, False)
        if len(difList) > 0:
          for difl in difList:
            sessionsKey[uri].append({'path':['cookie']+difl, 'operation':['rm', 'ran', 'rep']})

  for colList in [usersKey, devicesKey, sessionsKey]:
    for k in colList:
      if len(colList[k]) == 1 and isinstance(colList[k][0], list):
        colList[k] = colList[k][0]

  #merge header, cookie and response parameters
  # json.dump({'usersKey':usersKey, 'devicesKey':devicesKey, 'sessionsKey':sessionsKey}, open(os.path.join(folder_location,'response_para_bk'+appendix), 'w'))
  #json.dump({'usersKey':respHeaderUsersKey, 'devicesKey':respHeaderDevicesKey, 'sessionsKey':respHeaderSessionsKey}, open(os.path.join(folder_location,'response_header_para'+appendix), 'w'))
  #json.dump({'usersKey':respCokUsersKey, 'devicesKey':respCokDevicesKey, 'sessionsKey':respCokSessionsKey}, open(os.path.join(folder_location,'response_cookies_para'+appendix), 'w'))

  #Get restricted user specified keys so that it can be used to verify response change effect
  referenceNetwork = retrieveReferenceNetwork(aliceA, eveA)
  usersKeyVerify = userResponsePara(domainName, usersKey, devicesKey, sessionsKey, idp_name)
  usersKeyVerify = rankResponsePara(usersKeyVerify, referenceNetwork, idp_name)
  # filter out those entry which does not contain any parameters
  for key in usersKeyVerify.keys():
    if len(usersKeyVerify[key]) == 0:
      usersKeyVerify.pop(key, None)

  TopUsersKey = selectTopPara(usersKeyVerify, idp_name)

  userIdentifier = collections.defaultdict(list)
  userIdentifierUrl = ''
  if TopUsersKey == None:
    userIdentifierFound = False
  else:
    for uri in TopUsersKey:
      userIdentifier[uri] = TopUsersKey[uri][:-2]
      userIdentifier["Alice"].append(retrieveResponseFieldValue(aliceA, {uri:TopUsersKey[uri][:-2]}))
      userIdentifier["Eve"].append(retrieveResponseFieldValue(eveA, {uri:TopUsersKey[uri][:-2]}))
      userIdentifierUrl = uri
    if not userIdentifier["Alice"] or not userIdentifier["Eve"]:
      running_logger.warn('We cannot identify Alice or Eve user identifier')
      userIdentifierFound = False

    json.dump({'userIdentifier':userIdentifier}, open(os.path.join(folder_location,'user_para'+appendix), 'w'))

  #Request paras
  usersKeyReq = {}
  devicesKeyReq = {}
  sessionsKeyReq = {}

  #Header
  #headerUsersKeyReq = {}
  #headerDevicesKeyReq = {}
  #headerSessionsKeyReq = {}

  #Cookies
  #cokUsersKeyReq = {}
  #cokDevicesKeyReq = {}
  #cokSessionsKeyReq = {}

  reqSubVal = {}

  filtered_usersKey = collections.defaultdict(list)
  filtered_devicesKey = collections.defaultdict(list)
  filtered_sessionsKey = collections.defaultdict(list)

  for eid in range(len(eveA)):
    #Categorize request parameter
    if eveA[eid] == None:
      continue
    uri = extractor.extract_uri(eveA[eid]['request']['url'], False)
    # distinguish different response with the same uri in usersKey  
    while uri in filtered_usersKey:
      # if extractor.remove_http_scheme(uri) in IdPUris
      if isInIdPUris(extractor.remove_http_scheme(eveA[eid]['request']['url']), IdPUris):
        uri += '+'
      else:
        temp_uri, keyhash = uri.split('{')
        temp_uri += "+" 
        uri = temp_uri + '{'+ keyhash

    if uri not in usersKeyReq:
      usersKeyReq[uri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}# 'value':{}}
    if uri not in devicesKeyReq:
      devicesKeyReq[uri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}#, 'value':{}}
    if uri not in sessionsKeyReq:
      sessionsKeyReq[uri] = {'post':[], 'get':[], 'header':[], 'cookie':[]}#, 'value':{}}

    if eveA2[eid] != None:
      tmpPara = compareGPPara(eveA[eid], eveA2[eid])
      sessionsKeyReq[uri]['post']+=tmpPara['post']
      sessionsKeyReq[uri]['get']+=tmpPara['get']
      #sessionsKeyReq[uri]['value'].update(tmpPara['value'])

      if fuzzyHC:
        #Headers
        difList = compareJsons(jsonizeHeader(eveA[eid]['request']['headers']), jsonizeHeader(eveA2[eid]['request']['headers']), True, False)
        if len(difList) > 0:
          for difl in difList:
            if difl[0].lower() not in g_ignoreHeaders:
              sessionsKeyReq[uri]['header'].append(difl[0])
            #try:
            #  headerSessionsKeyReq[uri].append({'path':difl})
            #except:
            #  headerSessionsKeyReq[uri] = [{'path':difl}]

        #Cookies
        difList = compareJsons(jsonizeHeader(eveA[eid]['request']['cookies']), jsonizeHeader(eveA2[eid]['request']['cookies']), True, False)
        if len(difList) > 0:
          for difl in difList:
            sessionsKeyReq[uri]['cookie'].append(difl[0])
            #try:
            #  cokSessionsKeyReq[uri].append({'path':difl})
            #except:
            #  cokSessionsKeyReq[uri] = [{'path':difl}]
      
    if eveB[eid] != None:
      tmpPara = compareGPPara(eveA[eid], eveB[eid])
      devicesKeyReq[uri]['post']+=tmpPara['post']
      devicesKeyReq[uri]['get']+=tmpPara['get']
      #devicesKeyReq[uri]['value'].update(tmpPara['value'])

      if fuzzyHC:
        #Headers
        difList = compareJsons(jsonizeHeader(eveA[eid]['request']['headers']), jsonizeHeader(eveB[eid]['request']['headers']), True, False)
        if len(difList) > 0:
          for difl in difList:
            if difl[0].lower() not in g_ignoreHeaders:
              devicesKeyReq[uri]['header'].append(difl[0])
            #try:
            #  headerDevicesKeyReq[uri].append({'path':difl})
            #except:
            #  headerDevicesKeyReq[uri] = [{'path':difl}]

        #Cookies
        difList = compareJsons(jsonizeHeader(eveA[eid]['request']['cookies']), jsonizeHeader(eveB[eid]['request']['cookies']), True, False)
        if len(difList) > 0:
          for difl in difList:
            devicesKeyReq[uri]['cookie'].append(difl[0])
            #try:
            #  cokDevicesKeyReq[uri].append({'path':difl})
            #except:
            #  cokDevicesKeyReq[uri] = [{'path':difl}]

    if aliceA[eid] != None:
      tmpPara = compareGPPara(eveA[eid], aliceA[eid])
      usersKeyReq[uri]['post']+=tmpPara['post']
      usersKeyReq[uri]['get']+=tmpPara['get']
      #usersKeyReq[uri]['value'].update(tmpPara['value'])

      if fuzzyHC:
        #Headers
        difList = compareJsons(jsonizeHeader(eveA[eid]['request']['headers']), jsonizeHeader(aliceA[eid]['request']['headers']), True, False)
        if len(difList) > 0:
          for difl in difList:
            if difl[0].lower() not in g_ignoreHeaders:
              usersKeyReq[uri]['header'].append(difl[0])
            #try:
            #  headerUsersKeyReq[uri].append({'path':difl})
            #except:
            #  headerUsersKeyReq[uri] = [{'path':difl}]

        #Cookies
        difList = compareJsons(jsonizeHeader(eveA[eid]['request']['cookies']), jsonizeHeader(aliceA[eid]['request']['cookies']), True, False)
        if len(difList) > 0:
          for difl in difList:
            usersKeyReq[uri]['cookie'].append(difl[0])
            #try:
            #  cokUsersKeyReq[uri].append({'path':difl})
            #except:
            #  cokUsersKeyReq[uri] = [{'path':difl}]

      #Read request parameter value used to substitude
      if uri not in reqSubVal:
        reqSubVal[uri] = {'get':{}, 'post':{}, 'header':{}, 'cookie':{}}
      for item in aliceA[eid]['request']['queryString']:
        reqSubVal[uri]['get'][item['name']] = item['value']
      if 'postData' in aliceA[eid]['request']:
        if isJson(aliceA[eid]['request']['postData']['text']):
          try:
            reqSubVal[uri]['post'] = json.loads(urllib.unquote(aliceA[eid]['request']['postData']['text']))
          except ValueError:
            tmp_postData = json.loads(aliceA[eid]['request']['postData']['text'])
            for key in tmp_postData:
              value = tmp_postData[key]
              try:
                tmp_postData[key] = json.loads(urllib.unquote(value))
              except ValueError:
                continue
            reqSubVal[uri]['post'] = tmp_postData
        else:
          for prt in aliceA[eid]['request']['postData']['text'].split('&'):
            try:
              k, v = prt.split('=')
            except:
              continue
            reqSubVal[uri]['post'][k] = urllib.unquote(v)
      for item in aliceA[eid]['request']['headers']:
        reqSubVal[uri]['header'][item['name']] = item['value']
      for item in aliceA[eid]['request']['cookies']:
        reqSubVal[uri]['cookie'][item['name']] = item['value']
    
    # if uri in userIdentifierUrl and extractValue(TopUsersKey[userIdentifierUrl], eveA[eid][]):
    if uri in userIdentifierUrl and extractValue(userIdentifier[userIdentifierUrl], eveA[eid]["response"]["content"]) != None:
      break
    else:
      filtered_usersKey[uri] = usersKey[uri]
      filtered_devicesKey[uri] = devicesKey[uri]
      filtered_sessionsKey[uri] = sessionsKey[uri]

  #Save as file for permunateUrl to use later
  json.dump({'session':sessionsKeyReq, 'device':devicesKeyReq, 'user':usersKeyReq}, open(os.path.join(folder_location,'request_para_category'+appendix), 'w'))
  #json.dump({'session':headerSessionsKeyReq, 'device':headerDevicesKeyReq, 'user':headerUsersKeyReq}, open(folder_location+'/request_para_header'+appendix, 'w'))
  #json.dump({'session':cokSessionsKeyReq, 'device':cokDevicesKeyReq, 'user':cokUsersKeyReq}, open(folder_location+'/request_para_cookie'+appendix, 'w'))

  #Save as file for permunateUrl to substitude
  json.dump(reqSubVal, open(os.path.join(folder_location,'request_para_sub'+appendix), 'w'))
  json.dump({'usersKey':filtered_usersKey, 'devicesKey':filtered_devicesKey, 'sessionsKey':filtered_sessionsKey}, open(os.path.join(folder_location,'response_para'+appendix), 'w'))
  json.dump({'rankedUsersKeyPara':usersKeyVerify}, open(os.path.join(folder_location,'ranked_user_para'+appendix), 'w'))

  return userIdentifierFound

def isInIdPUris(uri, IdPUris):
  specialUri = "graph.facebook.com/v(.*)/me\\?"
  # To distinguish the multiple occurences of this special IdP Uri, we will treat it as if it belongs to RP domain

  if re.search(specialUri, uri) != None and re.search(specialUri, uri).start() < 18:
    return False

  for IdPUri in IdPUris:
    # we are comparing the entire uri (including the parameter). 
    # In case the parameter contains some IdPUri (e.g., redirect_uri), 
    # we add another IdP Uri
    if re.search(IdPUri, uri) != None and re.search(IdPUri, uri).start() < 18:
      return True
  return False

def isInIdPUrisForExtra(uri, IdPUris):
  for IdPUri in IdPUris:
    IdPUri = IdPUri.replace('\\?', '')
    if re.search(IdPUri, uri) != None and re.search(IdPUri, uri).start() < 18:
      return True
  return False

def retrieveReferenceNetwork(aliceA, eveA):
  referenceNetwork = {}
  # usersKeyReq = {}
  for eid in range(len(eveA)):
    #Categorize request parameter
    if eveA[eid] == None or aliceA[eid] == None:
      continue
    uri = extractor.extract_uri(eveA[eid]['request']['url'], False)
    uri = extractor.remove_http_scheme(uri)

    referenceNetwork[uri] = {'post':{}, 'get':{}}

    # if uri not in usersKeyReq:
    #   usersKeyReq[uri] = {'post':[], 'get':[]}#, 'value':{}} 

    tmpPara = compareGPPara(eveA[eid], aliceA[eid])
    # usersKeyReq[uri]['post']+=tmpPara['post']
    # usersKeyReq[uri]['get']+=tmpPara['get']
    referenceNetwork[uri]['get'] = jsonizeQuerydata(aliceA[eid]['request']['queryString'])
    if 'postData' in aliceA[eid]['request']:
      referenceNetwork[uri]['post'] = jsonizePostdata(aliceA[eid]['request']['postData']['params'])
    for key in referenceNetwork[uri]['get'].keys():
      if key not in tmpPara['get']:
        referenceNetwork[uri]['get'].pop(key, None)
    for key in referenceNetwork[uri]['post'].keys():
      if key not in tmpPara['post']:
        referenceNetwork[uri]['post'].pop(key, None)
  return referenceNetwork      
  #   for getPara in tmpPara['get']:
  #     if 


  # for header in aliceA:
  #   if header == None:
  #     continue
  #   # remove http:// or https:// to align with usersKey, usersKeyVerify
  #   uri = extractor.extract_uri(header['request']['url'])

  #   while uri in referenceNetwork:
  #     if uri in IdPUri:
  #       uri += '+'
  #     else:
  #       temp_uri, keyhash = uri.split('{')
  #       temp_uri += "+" 
  #       uri = temp_uri + '{'+ keyhash

  #   referenceNetwork[uri] = {'post':[], 'get':[]}
  #   referenceNetwork[uri]['get'] = header['request']['queryString']
  #   if 'postData' in header['request']:
  #     referenceNetwork[uri]['post'] = header['request']['postData']['params']

def retrieveResponseFieldValue(rawTrace, fields):
  #fields should be in the form of 
  #{u'uri': [u'text', u'data', u'username']
  import extractor
  
  uri, fieldPosition = fields.items()[0]
  for trace in rawTrace:
    try:
      temp_uri = extractor.extract_uri(trace['request']['url'], False)
    except:
      continue

    if uri in extractor.extract_uri(trace['request']['url'], False):
      response = trace['response']['content']
      for pos in fieldPosition:
        if isinstance(response, str) or isinstance(response, unicode):
          response = json.loads(response)
        response = response[pos]
      return response

def selectTopPara(usersKeyPara, idp_name="sina"):
  import json
  import toolTesting

  if len(usersKeyPara) == 0:
    return 

  maxScore = 0
  topUri = ""
  TopPara = {}

  # import pdb; pdb.set_trace()
  # In case of false positive, we prefer those fields which are not IdP generated.
  uid,unionid = toolTesting.extractUidfromTrace(json.load(open('aliceA.trace', 'r'))['log']['entries'], idp_name)

  username = toolTesting.extractUsernamefromTrace(json.load(open('aliceA.trace', 'r'))['log']['entries'], idp_name)
  for uri in usersKeyPara:
    # item is array in form of [u'text', u'username', u'Alicesso2', {'score': 5.571428571428571}]
    # determine uri first
    uriScore = 0
    
    for item in usersKeyPara[uri]:
      uriScore += item[-1]['score']

    nonZeroItems = len(filter(lambda x: x[-1]['score'] !=0, usersKeyPara[uri]))
    if nonZeroItems != 0 and uriScore/nonZeroItems > maxScore:
      maxScore = uriScore/nonZeroItems
      topUri = uri

  # all the scores in usersKeyPara are 0
  if topUri == "":
    return 
  maxScore = 0
  value = lambda x, y: similarity(x, y) if y != None else 0
  for item in usersKeyPara[topUri]:
    weightScore = item[-1]['score'] - max( value(item[-2], uid), value(item[-2], unionid), value(item[-2], username))
    # we do not want the key to be nickname-like
    weightScore -= similarity(item[-3],'nickname',0.8)
    if weightScore > maxScore:
      # clear the content in TopPara and put this parameter as well as the corresponding uri into the dict
      TopPara.clear()
      TopPara[topUri] = item
      maxScore = weightScore
  # for uri in usersKeyPara:      
  #       if uri in TopPara:
  #         TopPara[uri].append(item)
  #       else:
  #         TopPara[uri]=[item]
  #     elif item[-1]['score'] == maxScore:
  #       if uri in TopPara:
  #         TopPara[uri].append(item)
  #       else:
  #         TopPara[uri]=[item]
  return TopPara

def addHash4Request(header, idp_name = 'sina'):
  IdPUris = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"].values()
  uri = extractor.extract_uri(header['request']['url'])
  specialUri =  "graph.facebook.com/v(.*)/me\\?"

  if not isInIdPUris(extractor.remove_http_scheme(header['request']['url']), IdPUris):
  # if extractor.remove_http_scheme(uri) not in IdPUris:
    if re.search(specialUri, extractor.remove_http_scheme(header['request']['url'])) != None:
      # import pdb; pdb.set_trace()
      sortedFieldValue = [""]
      try:
        fieldValue = filter(lambda x: x['name'] == 'fields', header['request']['queryString'])[0]['value']
        sortedFieldValue = sorted(fieldValue.split(','))
      except:
        # In case there is no such fields field, we will use empty string when computing hash value
        running_logger.info("GraphAPI does not contain fields key-value pair")
      keyhash = RequestIndex(header, False, value2Hash = sortedFieldValue)
    else:
      keyhash = RequestIndex(header)
    return uri + '{' + keyhash
  else:
    return uri

def RequestIndex(header, on_the_fly=False, value2Hash = None):
  # value2Hash is the value which should be considered when computing the hash value
  # It should be sorted
  # One example is as follows: ['first_name', 'id', 'last_name', 'link', 'middle_name', 'name']

  def name_value(obj):
    result = []
    for k, v in obj.items():
      parseK = None
      parseV = None
      try:
        k.decode('utf-8')
        parseK = k
      except:
        parseK = repr(k)
      try:
        v.decode('utf-8')
        parseV = v
      except:
        parseV = repr(v)
      result.append({"name": parseK, "value": parseV})
    return result

  # extract necessary parameters for key generation
  url = ''
  querystr = ''
  poststr = ''

  if on_the_fly:
    url = header.request.url
    querystr = name_value(header.request.query or {})
    if header.request.method in ["POST", "PUT", "PATCH"]:
      poststr = header.request.get_text(strict=False)
    else:
      poststr = None
  else:
    url = header['request']['url']
    querystr = header['request']['queryString']
    if 'postData' in header['request']:
      poststr = header['request']['postData']['text']
    else:
      poststr = None

  if poststr:
    postdata = {}
    if isJson(poststr):
        postdata = json.loads(poststr)
    else:
      for prt in poststr.split('&'):
        try:
          k, v = prt.split('=')
          postdata[k] = v
        except:
          continue
    if value2Hash == None:
      keyhash = generateKey(url, querystr, postdata)
    else: 
      keyhash = generateKey(url, querystr, postdata, value2Hash)
  else:
    if value2Hash == None:
      keyhash = generateKey(url, querystr)
    else:
      keyhash = generateKey(url, querystr, postParams=None, value2Hash = value2Hash)
  return keyhash
  
# We should make sure the value stored in these two arguments are from the same user.
# Currently, it is from Alice
def rankResponsePara(UsersKeyPara, referenceNetwork, idp_name):
  import toolTesting
  import alignment
  #pip install python-levenshtein
  import Levenshtein

  def inner_too_short_variable(x, boarderline=3):
    '''
    x is an array in the following form:
    [[u'text', u'id', u'100008301542680', {'score': 2.5}], [u'text', u'last_name', u'Oauth', {'score': 2.0}]
    '''
    if isinstance(x[-2], int) and len(str(x[-2])) <= boarderline:
      return x
    elif isinstance(x[-2], str) and len(x[-2]) <= boarderline:
      return x
    elif isinstance(x[-2], unicode) and len(x[-2]) <= boarderline:
      return x

  rankedUsersKeyPara = UsersKeyPara
  file_format = ['.jpg', '.png', '.gif', '.css', '.js', '.ico']

  for key in rankedUsersKeyPara:
    # We only care about the response.content.text so far. 
    # Other response data can be response.content.compression, etc, 
    # which seems unrelated to user identifier
    rankedUsersKeyPara[key] = [x for x in rankedUsersKeyPara[key] if not x[0] !='text']

    for element in rankedUsersKeyPara[key]:
        element.append({"score":0})

  for key in rankedUsersKeyPara.keys():
    for element in rankedUsersKeyPara[key]:
      # element[-2] is the value of this parameter
      # we try to filter out unimportant paramenters according to its value first.
      for ff in file_format:
        if (isinstance(element[-2],str) or isinstance(element[-2],unicode)) \
        and element[-2].lower().find(ff) >= 0 and '.json' not in element[-2].lower():
          rankedUsersKeyPara[key].remove(element)
          break
      # the length of the user identifier is too small and should not be possible to be a identifier
      try:
        rankedUsersKeyPara[key] = filter(lambda element: not inner_too_short_variable(element), rankedUsersKeyPara[key])
      except:
        pass
      # There is not any parameters associated with this URI
      if len(rankedUsersKeyPara[key]) == 0:
        rankedUsersKeyPara.pop(key)
        break

  access_token = toolTesting.extractATfromTrace(json.load(open('aliceA.trace', 'r'))['log']['entries'], idp_name)

  # for wechat, uid corresponds to openid, unionid is present if there are multiple RP apps belong to the same organization;
  # for sina, unionid is always None
  uid,unionid = toolTesting.extractUidfromTrace(json.load(open('aliceA.trace', 'r'))['log']['entries'], idp_name)

  username = toolTesting.extractUsernamefromTrace(json.load(open('aliceA.trace', 'r'))['log']['entries'], idp_name)
  code = toolTesting.extractCodefromTrace(json.load(open('aliceA.trace', 'r'))['log']['entries'], idp_name)

  # response
  for key in rankedUsersKeyPara:
    if 'login' in key.lower() or 'signin' in key.lower() or 'signon' in key.lower() or 'logon' in key.lower():
       for element in rankedUsersKeyPara[key]:
        # element is a list in the form of ["text", "nickname", "Alicesso2"]
        # append a score in the end of list ["text", "nickname", "Alicesso2", {"score": 2}]
        # try:
          element[-1]["score"] += 1
    if 'account' in key.lower() or 'my' in key.lower() or 'connect' in key.lower() or 'third' in key.lower() or 'sso' in key.lower() or 'oauth' in key.lower():
      for element in rankedUsersKeyPara[key]:
        # element is a list in the form of ["text", "nickname", "Alicesso2"]
        # append a score in the end of list ["text", "nickname", "Alicesso2", {"score": 2}]
        try:
          element[-1]["score"] += 1
        except:
          pass
        #   element.append({"score":2})

    for element in rankedUsersKeyPara[key]:
      # element[-2] is the value of the parameter
      if uid != None:
        sim = similarity(uid, element[-2])
        element[-1]['score'] += sim

      if username != None:
        sim = similarity(username, element[-2])
        element[-1]['score'] += sim

      # element[-3] is the key of the parameter
      sim = similarity('userid', element[-3])
      element[-1]['score'] += sim

      sim = similarity('account', element[-3])
      element[-1]['score'] += sim

      sim = similarity('username', element[-3])
      element[-1]['score'] += sim

    # request
    try:
      if key not in referenceNetwork:
        print "cannot find key in referenceNetwork: ", key
        continue
    except:
      print "do no know what happened"
    for paraKey, paraValue in referenceNetwork[key]['post'].iteritems():
      # for paraKey, paraValue in item.iteritems():
        # according to the key to assign score
      sim1 = similarity('access_token', paraValue)
      sim2 = similarity('oauth_token', paraValue)
      maxSimilarity = max(sim1, sim2)

      for element in rankedUsersKeyPara[key]:
        element[-1]["score"] += maxSimilarity

      # according to the access token value to assign score
      if access_token != None:
        sim = similarity(access_token, paraValue)
        if sim != 0:
          for element in rankedUsersKeyPara[key]:
            element[-1]["score"] += sim

      # according to the code value to assign score
      if code != None:
        sim = similarity(code, paraValue)
        if sim != 0:
          for element in rankedUsersKeyPara[key]:
            element[-1]["score"] += sim

      # according to uid value to assign score
      if uid != None:
        sim = similarity(uid, paraValue)
        for element in rankedUsersKeyPara[key]:
          element[-1]["score"] += sim

      # according to unionid value to assign score
      if unionid != None:
        sim = similarity(unionid, paraValue)
        for element in rankedUsersKeyPara[key]:
          element[-1]["score"] += sim
    for paraKey, paraValue in referenceNetwork[key]['get'].iteritems():
      # for paraKey, paraValue in item.iteritems():
        # according to the key to assign score
      sim1 = similarity('access_token', paraValue)
      sim2 = similarity('oauth_token', paraValue)
      maxSimilarity = max(sim1, sim2)
      if maxSimilarity != 0:
        for element in rankedUsersKeyPara[key]:
          element[-1]["score"] += maxSimilarity

      # according to the access token value to assign score
      sim = similarity(access_token, paraValue)
      if sim != 0:
        for element in rankedUsersKeyPara[key]:
          element[-1]["score"] += sim

      # according to uid value to assign score
      sim = similarity(uid, paraValue)
      if sim != 0:
        for element in rankedUsersKeyPara[key]:
          element[-1]["score"] += sim
    
    # # filter out those parameters whose lengths of values are too small
    # for element in rankedUsersKeyPara[key]:
    #   if len(element[-2]) < 3:
    #     rankedUsersKeyPara
  return rankedUsersKeyPara

def similarity(str1, str2, default_threshold = 0.5):
  import alignment
  #pip install python-levenshtein
  import Levenshtein

  # the similarity can only be compared between two str or two unicodes
  if isinstance(str1, unicode):
    str1 = str1.encode('utf-8')
  elif isinstance(str1, int) or isinstance(str1, float):
    str1 = str(str1)
  elif not isinstance(str1, str):
    return 0
  if isinstance(str2, unicode):
    str2 = str2.encode('utf-8')
  elif isinstance(str2, int) or isinstance(str2, float):
    str2 = str(str2)
  elif not isinstance(str2, str):
    return 0

  aligned = list()
  aligned.append(alignment.needle(str1.lower(), str2.lower()))

  # if aligned[0][0] >= default_threshold:
    #similarity = Levenshtein.ratio(aligned[0][1],aligned[0][2])
  similarity = max(Levenshtein.ratio(str1.lower(),str2.lower()),Levenshtein.ratio(aligned[0][1],aligned[0][2]))

  if similarity >= default_threshold:
    return similarity
  # The maximum # of the same characters in these two strings are less than half
  return 0

def userResponsePara(domain, usersKey, devicesKey, sessionsKey, idp_name):
  import extractor
  import copy
  usersKeyVerify = {} 

  IdPUris = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"].values()

  for k in usersKey:  
    # We are only interested in the RP communication
    # In some cases, domain can be the IdP domain due to the uncertainty of getDomains
    uri = k.split('{')[0].rstrip('+')
    if isInIdPUris(uri, IdPUris):
      continue

    # if g_appinfo['appNetloc'] in extractor.extract_netloc('http://'+k).lower():
    if domain in k.lower():
      trueUP = [p['path'] for p in usersKey[k]]
      trueDP = []
      trueTP = []
      if k in devicesKey:
        trueDP = [p['path'][:-1] for p in devicesKey[k]]
      if k in sessionsKey:
        trueTP = [p['path'][:-1] for p in sessionsKey[k]]
      # what if the uri belong to trueTP and trueUP. But some parameters only in trueUP?
      for p in trueUP:
        if p[:-1] not in trueDP and p[:-1] not in trueTP:
          if k not in usersKeyVerify:
            usersKeyVerify[k] = []
          usersKeyVerify[k].append(copy.deepcopy(p))
  return usersKeyVerify

#Compare get post request parameters
def compareGPPara(req1, req2):
  


  paraSet = {'post':[], 'get':[], 'value':{}}
  getEve = {}
  for item in req1['request']['queryString']:
    getEve[item['name']] = item['value']
  getEve2 = {}
  for item in req2['request']['queryString']:
    getEve2[item['name']] = item['value']

  for key in getEve:
    if key in getEve2 and getEve[key] != getEve2[key]:
      paraSet['get'].append(key)
      paraSet['value'][key] = getEve2[key]

  if 'postData' in req1['request'] and 'postData' in req2['request']:
    postEve = {}
    if isJson(req1['request']['postData']['text']):
      postEve = json.loads(req1['request']['postData']['text'])
    else:
      for prt in req1['request']['postData']['text'].split('&'):
        try:
          k, v = prt.split('=')
        except:
          continue
        postEve[k] = v

    postEve2 = {}
    if isJson(req2['request']['postData']['text']):
      postEve2 = json.loads(req2['request']['postData']['text'])
    else:
      for prt in req2['request']['postData']['text'].split('&'):
        try:
          k, v = prt.split('=')
        except:
          continue
        postEve2[k] = v

    for key in postEve:
      if type(key) == dict:
        continue
      if key in postEve2 and postEve[key] != postEve2[key]:
        paraSet['post'].append(key)
        paraSet['value'][key] = postEve2[key]
      if key not in postEve2:
        paraSet['post'].append(key)
        paraSet['value'][key] = postEve[key]
  return paraSet

#attachBValue so that mitmproxy can directly replace the reponse with BValue
def compareJsons(jsonA, jsonB, attachBValue=False, bypassKeys=True):
  from ast import literal_eval
  if bypassKeys:
    ignoredKeys = ['time', 'timing', 'timestamps','remind_in', 'expires_in', 'expire', 'timestamp', 'Date', 'systemdate']
  else:
    ignoredKeys = []
  diffPaths = []
  for k in jsonA:
    if type(k) == dict:
      continue
    if (isinstance(k, str) or isinstance(k, unicode)) and k.lower() in ignoredKeys:
      continue
    if (isinstance(jsonA[k], str) or isinstance(jsonA[k], unicode)) and isHTML(jsonA[k]):
      continue
    try:
      if k == 'scope':
        if 'scope' not in jsonB:
          diffPaths.append([k])
          continue
        if attachBValue:
          diffPaths.append([k, jsonB[k]])
        else:
          diffPaths.append([k])     
        continue
      elif k not in jsonB:
        # ignore if jsonB does not contain the key k 
        continue
      #For str, try to see if it's json str
      elif isinstance(jsonA[k], str) or isinstance(jsonA[k], unicode):
        if isJson(jsonA[k]) and isJson(jsonB[k]):
          try:
            leafJsonA = json.loads(jsonA[k])
          except:
            leafJsonA = json.loads(literal_eval(jsonA[k]))
          try:
            leafJsonB = json.loads(jsonB[k])
          except:
            leafJsonB = json.loads(literal_eval(jsonB[k]))
          leafs = compareJsons(leafJsonA, leafJsonB, attachBValue, bypassKeys)
          for x in range(len(leafs)):
            leafs[x].insert(0, k)
          diffPaths+=leafs

        elif k in jsonB and jsonA[k] != jsonB[k] and not (isTime(jsonA[k]) or isTime(jsonB[k])):
          if attachBValue:
            diffPaths.append([k, jsonB[k]])
          else:
            diffPaths.append([k])

      elif isinstance(jsonA[k], int) or isinstance(jsonA[k], float):
        #if  (similarity(k,'uid') > 0.5 or similarity(k,'userid')>0.5) and k in jsonB and jsonA[k] != jsonB[k]:
        if k in jsonB and jsonA[k] != jsonB[k]:
          if attachBValue:
            diffPaths.append([k, jsonB[k]])
          else:
            diffPaths.append([k])
        elif k in jsonB and jsonA[k] != jsonB[k] and not (isTime(jsonA[k]) or isTime(jsonB[k])):
          if attachBValue:
            diffPaths.append([k, jsonB[k]])
          else:
            diffPaths.append([k])

      elif isinstance(jsonA[k], dict):
        if k not in jsonB or k == 'ori_interceptad':
          continue
        leafs = compareJsons(jsonA[k], jsonB[k], attachBValue, bypassKeys)

        for x in range(len(leafs)):
          leafs[x].insert(0, k)
        diffPaths+=leafs
      elif isinstance(jsonA[k], list):
        if k not in jsonB:
          continue
        if len(jsonA[k]) != len(jsonB[k]):
          if attachBValue:
            diffPaths.append([k, jsonB[k]])
          else:
            diffPaths.append([k])
        else:
          for ele in range(len(jsonA[k])):
            leafs = compareJsons({ele:jsonA[k][ele]}, {ele:jsonB[k][ele]}, attachBValue, bypassKeys)
            for x in range(len(leafs)):
              leafs[x].insert(0, k)
            diffPaths+=leafs
    except TypeError,e:
      running_logger.error(str(e) + " " + k)
    except IndexError, e:
      running_logger.error(str(e) + " " + k)
  return  diffPaths

def isJson(dataStr):
  from ast import literal_eval
  import re
  if not isinstance(dataStr, str) and not isinstance(dataStr, unicode):
    return False
    
  if re.match(r'(\-)?(\d+)', dataStr):
    return False

  if dataStr == 'false' or dataStr == 'true' or dataStr == 'null':
    return False

  try:
    jObj = json.loads(dataStr)
    tmpKeys = jObj.keys()
    return True
  except:
    try:
      jObj = json.loads(literal_eval(dataStr))
      tmpKeys = jObj.keys()
      return True
    except:
      return False

################################################################################

#Analyze relations betweet different requests/ responses
def analyzeTrace():
  import extractor
  import json
  from ast import literal_eval
  g_appinfo = json.load(open('appinfo.json', 'r'))

  #Extract all revelant requests
  rawTrace = json.load(open('eveA.trace', 'r'))
  trace = extractor.clean_trace(rawTrace['log']['entries'], ['api.weibo', g_appinfo['appNetloc']])

  #{'key':{'post':[{'name':'', 'val':'', 'prop':''}], 'get':[]}}
  traceInfo = {}
  hasOauth = False
  #Contorl how many requests are assumed to be sent by RP after OAuth
  postAuthRPReq = 10
  for header in trace:
    wanted = False
    #Check if has obta
    if not hasOauth:
      try:
        respJson = json.loads(header["response"]["content"]["text"])
      except:
        respJson = json.loads(literal_eval(header["response"]["content"]["text"]))
      if extractor.is_Oauth(header['request']['url'], respJson):
        hasOauth = True
    
    if 'api.weibo' in header['request']['url'].lower() or (hasOauth and g_appinfo['appNetloc'] in header['request']['url'].lower() and postAuthRPReq > 0):
      wanted = True
      #In second case, deduct value by 1
      if 'api.weibo' not in header['request']['url'].lower():
        postAuthRPReq -= 1

    if wanted:
      #Get the key to store
      if 'postData' in header['request']:
        (uri, sortedGet, sortedPost) = generateKey(header['request']['url'], header['request']['queryString'], header['request']['postData']['text'])
      else:
        (uri, sortedGet, sortedPost) = generateKey(header['request']['url'], header['request']['queryString'])
      
      #Extract get parameter
      dicKey = uri+sortedGet+sortedPost
      traceInfo[dicKey] = {'post':[], 'get':[]}
      for qdic in header['request']['queryString']:
        traceInfo[dicKey]['get'].append({'name':qdic['name'], 'val':qdic['value'], 'prop':''})

      #Extract post parameter
      if 'postData' in header['request']:
        if 'json' in header['request']['postData']['mimeType']:
          tmpParams = convertJsonToDic(json.loads(header['request']['postData']['text']))
          for k in tmpParams:
            traceInfo[dicKey]['post'].append({'name':k, 'val':tmpParams[k], 'prop':''})
        else:
          for prt in header['request']['postData']['text'].split('&'):
            try:
              traceInfo[dicKey]['post'].append({'name':prt.split('=')[0], 'val':prt.split('=')[1], 'prop':''})
            except:
              continue

  #Compare param values across requests

  return

#This function is used to convert multi-level json object to one level dict.
#If input is {'key1':'abc', 'key2':{'key3':'test', 'key4':'test2'}}
#Output is {'key1':'abc', 'key2|||key3':'test', 'key2|||key4':'test2'}
def convertJsonToDic(jsonObj, output={}, prefix=''):
  for k in jsonObj:
    if isinstance(jsonObj[k], str) or isinstance(jsonObj[k], unicode):
      output[prefix+k] = jsonObj[k] 
    if isinstance(jsonObj[k], int) or isinstance(jsonObj[k], float):
      output[prefix+k] = jsonObj[k]
    if isinstance(jsonObj[k], dict):
      output = convertJsonToDic(jsonObj[k], output, prefix+k+'|||')
    if isinstance(jsonObj[k], list):
      for eleId in range(len(jsonObj[k])):
        output = convertJsonToDic(jsonObj[k][eleId], output, prefix+k+'|||'+str(eleId)+'|||')

  return output

#If only use uri as the key in dict, some uri may appear multiple times with different params.
#So use url+sorted(getParasNames)+sorted(postParasNames) as the key
def generateKey(url, getParams, postParams = None, value2Hash = None):
  import extractor
  import json
  import hashlib

  uri = extractor.extract_uri(url, False)

  getQs = []
  for qdic in getParams:
    getQs.append(qdic['name'])
  getQs = sorted(getQs) 

  postQs = []
  if postParams != None:
    try:
      postQs = postParams.keys()
    except:
      pass
    # if isJson(postParams):
    #   tmpParams = json.loads(postParams)
    #   if isinstance(tmpParams, list):
    #     for ele in tmpParams:
    #       for prt in ele:
    #         if isinstance(ele[prt], dict):
    #           postQs+=ele[prt].keys()
    #         else:
    #           postQs.append(prt)
    #   else:
    #     for prt in tmpParams:
    #       if isinstance(tmpParams[prt], dict):
    #         postQs+=tmpParams[prt].keys()
    #       else:
    #         postQs.append(prt)
    # else:
    #   for prt in postParams.split('&'):
    #     try:
    #       postQs.append(prt.split('=')[0])
    #     except:
    #       continue
    postQs = sorted(postQs)

  m = hashlib.md5()
  m.update(uri)
  try:
    m.update(' '.join(getQs))
  except:
    pass
  try:
    m.update(' '.join(postQs))
  except:
    pass
  if value2Hash != None:
    try:
      m.update(' '.join(value2Hash))
    except:
      pass
  keyhash = m.hexdigest()
  return keyhash
  #return (uri, ' '.join(getQs), ' '.join(postQs))

################################################################################

def checkTested(url = None, position = None, method = None, name = None, operation = None):
  import os
  import json

  operation = str(operation)

  if not os.path.exists('tested.json'):
    json.dump({}, open('tested.json', 'w'))   
  pool = None
  with open('tested.json', 'r') as f:
    pool = json.load(f)
  if url not in pool:
    return False
  if position not in pool[url]:
    return False
  if position == 'request':
    if method not in pool[url][position]:
      return False
    else:
      if name not in pool[url][position][method] or operation not in pool[url][position][method][name]:
        return False
  else:
    if name not in pool[url][position] or operation not in pool[url][position][name]:
      return False
  return True

def writeTested(url = None, position = None, method = None, name = None, operation = None, last=True):
  import os
  import json

  operation = str(operation)

  if not os.path.exists('tested.json'):
    json.dump({}, open('tested.json', 'w'))
  pool = None
  with open('tested.json', 'r') as f:
    pool = json.load(f) 
  if url not in pool.keys():
    pool[url] = {}
  if position not in pool[url]:
    pool[url][position] = {}
  if position == 'request':
    if method not in pool[url][position]:
      pool[url][position][method] = {}
    if name not in pool[url][position][method]:
      pool[url][position][method][name] = []
    if operation not in pool[url][position][method][name]:
      pool[url][position][method][name].append(operation)
  else:
    if name not in pool[url][position]:
      pool[url][position][name] = []
    if operation not in pool[url][position][name]:
      pool[url][position][name].append(operation)
  json.dump(pool, open('tested.json', 'w'))
  if last:
    writeLast(url,position,method,name,operation)

def writeRedundant(url = None, position = None, method = None, name = None, operation = None):
  import os
  import json

  operation = str(operation)

  if not os.path.exists('redundant.json'):
    json.dump({}, open('redundant.json', 'w'))
  pool = None
  with open('redundant.json', 'r') as f:
    pool = json.load(f) 
  if url not in pool.keys():
    pool[url] = {}
  if position not in pool[url]:
    pool[url][position] = {}
  if position == 'request':
    if method not in pool[url][position]:
      pool[url][position][method] = {}
    if name not in pool[url][position][method]:
      pool[url][position][method][name] = []
    if operation not in pool[url][position][method][name]:
      pool[url][position][method][name].append(operation)
  else:
    if name not in pool[url][position]:
      pool[url][position][name] = []
    if operation not in pool[url][position][name]:
      pool[url][position][name].append(operation)
  json.dump(pool, open('redundant.json', 'w'))

def countFuzzedCases(target=None, part=None):
  import json
  count = 0
  redundant_count = 0
  if not os.path.exists('tested.json'):
    return 0
  else:
    with open('tested.json') as f:
      tested = json.load(f)
      for url in tested:
        if str(url) == 'last' or (target != None and url != target):
          continue
        for position in tested[url]:
          if position == 'request':
            for method in tested[url]['request']:
              for para in tested[url]['request'][method]:
                if part != 'response':
                  count = count + len(tested[url]['request'][method][para])
          else:
            for para in tested[url]['response']:
              if part != 'request':
                count = count + len(tested[url]['response'][para])
  if not os.path.exists('redundant.json'):
    return count
  else:
    with open('redundant.json') as f:
      redundant = json.load(f)
      for url in redundant:
        if target != None and url != target:
          continue
        for position in redundant[url]:
          if position == 'request':
            for method in redundant[url]['request']:
              for para in redundant[url]['request'][method]:
                if part != 'response':
                  redundant_count = redundant_count + len(redundant[url]['request'][method][para])
          else:
            for para in redundant[url]['response']:
              if part != 'request':
                redundant_count = redundant_count + len(redundant[url]['response'][para])
    return (count - redundant_count)

def countCases(fileName='tested.json'):
  import json
  count = 0
  if not os.path.exists(fileName):
    return 0
  else:
    with open(fileName) as f:
      tested = json.load(f)
      for url in tested:
        if str(url) == 'last':
          continue
        for position in tested[url]:
          if position == 'request':
            for method in tested[url]['request']:
              for para in tested[url]['request'][method]:
                count = count + len(tested[url]['request'][method][para])
          else:
            for para in tested[url]['response']:
              count = count + len(tested[url]['response'][para])
  return count

def writeLast(url = None, position = None, method = None, name = None, operation = None):
  import os
  import json

  if not os.path.exists('tested.json'):
    json.dump({}, open('tested.json', 'w'))
  pool = None
  with open('tested.json', 'r') as f:
    pool = json.load(f) 
  if 'last' not in pool:
    pool['last'] = {'url':'', 'position':'', 'method':'', 'name':'', 'operation':''}
  pool['last']['url'] = str(url)
  pool['last']['position'] = str(position)
  if position == 'request':
    pool['last']['method'] = str(method)
  else:
    pool['last']['method'] = ''
  pool['last']['name'] = str(name)
  pool['last']['operation'] = str(operation)
  json.dump(pool, open('tested.json', 'w'))

def removeLast():
  import os
  import json
  if not os.path.exists('tested.json'):
    json.dump({}, open('tested.json', 'w'))
  pool = None
  with open('tested.json', 'r') as f:
    pool = json.load(f) 
  if 'last' not in pool:  
    return
  url = pool['last']['url']
  position = pool['last']['position']
  method = pool['last']['method']
  name = pool['last']['name']
  operation = pool['last']['operation']
  try:
    if position == 'request':
      pool[url][position][method][name].remove(operation)
    else:
      pool[url][position][name].remove(operation)
  except:
    pass
  pool['last']['url'] = ''
  pool['last']['position'] = ''
  pool['last']['method'] = ''
  pool['last']['name'] = ''
  pool['last']['operation'] = ''     
  json.dump(pool, open('tested.json', 'w'))

def getLast():
  import os
  import json
  if not os.path.exists('tested.json'):
    json.dump({}, open('tested.json', 'w'))
  pool = None
  with open('tested.json', 'r') as f:
    pool = json.load(f) 
  if 'last' not in pool:  
    return
  url = pool['last']['url']
  position = pool['last']['position']
  method = pool['last']['method']
  name = pool['last']['name']
  operation = pool['last']['operation']
  return [url, position, method, name, operation]

def removeTested(url = None, position = None, method = None, name = None, operation = None):
  import os
  import json
 
  if not os.path.exists('tested.json'):
    json.dump({}, open('tested.json', 'w'))
  pool = None
  with open('tested.json', 'r') as f:
    pool = json.load(f) 
  if position == 'request':
    pool[url][position][method][name].remove(operation)
  else:
    pool[url][position][name].remove(operation)
  json.dump(pool, open('tested.json', 'w'))
 
def removeLastTested():
  removeTested(getLast()[0], getLast()[1], getLast()[2], getLast()[3], getLast()[4])

################################################################################

def listFiles(curr_dir = '.', ext = '*.lock'):
  import glob
  import os
  for i in glob.glob(os.path.join(curr_dir, ext)):
    yield i
 
def removeLockFiles(rootdir = '.', ext = '*.lock', show = False):
  import glob
  import os
  for i in listFiles(rootdir, ext):
    if show:
      print i
    os.remove(i)

def checkLockFiles():
  import os.path
  if not os.path.isfile('lock.txt'):
    open('lock.txt', 'a').close()
  if not os.path.isfile('result.txt'):
    open('result.txt', 'a').close()

################################################################################
def isHTML(dataStr):
  from bs4 import BeautifulSoup
  import warnings
  warnings.filterwarnings("ignore", category=UserWarning, module='bs4')
  return bool(BeautifulSoup(dataStr, "html.parser").find())

################################################################################

def refineURL(url):
  if '{' in url:
    HASH = url.split('{')[1]
    url = url.split('{')[0]
  else:
    HASH = ''
  count = 1
  while url[-1] == '+':
    count += 1
    url = url[0: len(url) - 1]
  return (HASH, count, url)
  
################################################################################

def getBooleanInJson(content):
  if content == 'True':
    return True
  else:
    return False

def writeState(access_token,initialized, Eve_state, IdP_App_Installed, IdP_Name, Eve_Auth_RP, doubleRequests, fuzzIdPAuthIdPApp, fuzzIdPShowRPAppInfo, fuzzEveIdP_Auth, fuzzIdPAuthIdPApp1, fuzzIdPShowRPAppInfo1, fuzzEveIdP_Auth1, fuzzRPAppHandshakeRPServ, fuzzGetUid, fuzzShowUserInfo, fuzzShowMoreUserInfo, fuzzShowExtraUserInfo, fuzzGetAT, fuzzRefreshAT, fuzzGetUid1, fuzzShowUserInfo1, fuzzShowMoreUserInfo1, fuzzShowExtraUserInfo1, finishIdPAuthIdPApp, finishIdPShowRPAppInfo, finishEveIdP_Auth, finishIdPAuthIdPApp1, finishIdPShowRPAppInfo1, finishEveIdP_Auth1, finishRPAppHandshakeRPServ, finishGetUid, finishShowUserInfo, finishShowMoreUserInfo, finishShowExtraUserInfo, finishGetAT, finishRefreshAT, finishGetUid1, finishShowUserInfo1, finishShowMoreUserInfo1, finishShowExtraUserInfo1, traceOneFinished, traceTwoFinished):
  stateVariables = {}
  stateVariables['access_token'] = access_token
  stateVariables['initialized'] = str(initialized)
  stateVariables['Eve_state'] = str(Eve_state)
  stateVariables['IdP_App_Installed'] = str(IdP_App_Installed)
  stateVariables['IdP_Name'] = str(IdP_Name)
  stateVariables['Eve_Auth_RP'] = str(Eve_Auth_RP)
  stateVariables['doubleRequests'] = str(doubleRequests)
  stateVariables['fuzzIdPAuthIdPApp'] = str(fuzzIdPAuthIdPApp)
  stateVariables['fuzzIdPShowRPAppInfo'] = str(fuzzIdPShowRPAppInfo)
  stateVariables['fuzzEveIdP_Auth'] = str(fuzzEveIdP_Auth)
  stateVariables['fuzzIdPAuthIdPApp1'] = str(fuzzIdPAuthIdPApp1)
  stateVariables['fuzzIdPShowRPAppInfo1'] = str(fuzzIdPShowRPAppInfo1)
  stateVariables['fuzzEveIdP_Auth1'] = str(fuzzEveIdP_Auth1)
  stateVariables['fuzzRPAppHandshakeRPServ'] = str(fuzzRPAppHandshakeRPServ)
  stateVariables['fuzzGetUid'] = str(fuzzGetUid)
  stateVariables['fuzzShowUserInfo'] = str(fuzzShowUserInfo)
  stateVariables['fuzzShowMoreUserInfo'] = str(fuzzShowMoreUserInfo)
  stateVariables['fuzzShowExtraUserInfo'] = str(fuzzShowExtraUserInfo)
  stateVariables['fuzzGetUid1'] = str(fuzzGetUid1)
  stateVariables['fuzzShowUserInfo1'] = str(fuzzShowUserInfo1)
  stateVariables['fuzzShowMoreUserInfo1'] = str(fuzzShowMoreUserInfo1)
  stateVariables['fuzzShowExtraUserInfo1'] = str(fuzzShowExtraUserInfo1)  
  stateVariables['fuzzGetAT'] = str(fuzzGetAT)
  stateVariables['fuzzRefreshAT'] = str(fuzzRefreshAT)
  stateVariables['finishIdPAuthIdPApp'] = str(finishIdPAuthIdPApp)
  stateVariables['finishIdPShowRPAppInfo'] = str(finishIdPShowRPAppInfo)
  stateVariables['finishEveIdP_Auth'] = str(finishEveIdP_Auth)
  stateVariables['finishIdPAuthIdPApp1'] = str(finishIdPAuthIdPApp1)
  stateVariables['finishIdPShowRPAppInfo1'] = str(finishIdPShowRPAppInfo1)
  stateVariables['finishEveIdP_Auth1'] = str(finishEveIdP_Auth1)
  stateVariables['finishRPAppHandshakeRPServ'] = str(finishRPAppHandshakeRPServ)
  stateVariables['finishGetUid'] = str(finishGetUid)
  stateVariables['finishShowUserInfo'] = str(finishShowUserInfo)
  stateVariables['finishShowMoreUserInfo'] = str(finishShowMoreUserInfo)
  stateVariables['finishShowExtraUserInfo'] = str(finishShowExtraUserInfo)
  stateVariables['finishGetUid1'] = str(finishGetUid1)
  stateVariables['finishShowUserInfo1'] = str(finishShowUserInfo1)
  stateVariables['finishShowMoreUserInfo1'] = str(finishShowMoreUserInfo1)
  stateVariables['finishShowExtraUserInfo1'] = str(finishShowExtraUserInfo1)  
  stateVariables['finishGetAT'] = str(finishGetAT)
  stateVariables['finishRefreshAT'] = str(finishRefreshAT)
  stateVariables['traceOneFinished'] = str(traceOneFinished)
  stateVariables['traceTwoFinished'] = str(traceTwoFinished)  
  '''
  stateVariables['fuzzRPAppHandshakeRPServ1'] = str(fuzzRPAppHandshakeRPServ1)
  stateVariables['finishRPAppHandshakeRPServ1'] = str(finishRPAppHandshakeRPServ1)
  '''                   
  json.dump(stateVariables, open('state.json', 'w+'))

################################################################################

def updateDomainName(domainName):
  g_appinfo = json.load(open('appinfo.json', 'r'))
  g_appinfo['appNetloc'] = domainName
  g_appinfo['appDomain'] = [str(domainName).split('.')[0]]
  g_appinfo['appName'] = str(domainName).split('.')[0]
  json.dump(g_appinfo, open('appinfo.json', 'w'))

################################################################################
 
def loadRef():
  ui_support = False
  url = ''
  location = []
  aliceValue = ''
  eveValue = ''
 
  rawTrace = json.load(open('config.json', 'r'))
  if rawTrace['ui_support'] == 'False':
    ui_support = False
  else:
    ui_support = True
 
  if not ui_support: 
    rawTrace = json.load(open('user_para', 'r'))
    aliceValue = rawTrace['userIdentifier']['Alice'][0]
    eveValue = rawTrace['userIdentifier']['Eve'][0]
    for key in rawTrace['userIdentifier'].keys():
      if key != 'Alice' and key != 'Eve':
        url = key
        break
    location = rawTrace['userIdentifier'][url]
    location.pop(0)
 
  return [ui_support, str(url).encode('UTF8'), location, str(aliceValue).encode('UTF8'), str(eveValue).encode('UTF8')]
 
def extractValue(paths, data):
  for pid in range(len(paths)):
    if paths[pid] not in data and type(data) is dict:
      break
    elif type(data) is list and paths[pid] >= len(data):
      break
    elif type(data) is str or type(data) is unicode:
      data = json.loads(data)
    if pid == len(paths)-1:
      result = data[paths[pid]]
      if isinstance(result, int):
        return str(result)
      elif isinstance(result, unicode):
        return result.encode('UTF8')
      else:
        return result      
    else:
      data = data[paths[pid]]
  return None

################################################################################

def decoupleFBResponse(input):
  prefix = input.split('#')[0]
  suffix = (input.split('#')[1]).split('"')[1]
  paraList = (input.split('#')[1]).split('"')[0]
  result = {}
  order = []
  for item in paraList.split('&'):
    key = item.split('=')[0]
    value = item.split('=')[1]
    result[key] = value
    order.append(key)
  paraList = result
  return [prefix, paraList, suffix, order]

def constructFBResponse(prefix, paraList, suffix, order):
  result = ''
  for item in order:
    if item in paraList:
     result = result + item + '=' + paraList[item] + '&'
  result = prefix + '#' + result[:-1] + '"' + suffix
  return result

def getFBResponseValue(input, key):
  try:
    return decoupleFBResponse(input)[1][key]
  except:
    print 'Variable not found in the response!'
    return None

def checkFBAuthorized(input):
  import re

  for item in input:
    if re.search('m.facebook.com/v(.*)/dialog/oauth/confirm', item['request']['url']):
      return True
  return False

def countURL(input, pattern, regular=False):
  import re

  count = 0
  trace = False
  if isinstance(input, list):
    trace = True
  if trace:
    for item in input:
      if regular:
        if re.search(pattern, item['request']['url']):
          count = count + 1
      else:
        if pattern in item['request']['url']:
          count = count + 1
  else:
    for item in input.keys():
      if regular:
        if re.search(pattern, item):
          count = count + 1
      else:
        if pattern in item:
          count = count + 1
  return count

def extractFBURL(input, pattern, corner1='', corner2=''):
  import re

  for item in input.keys():
    if re.search(pattern, item) and (not re.search(corner1, item) or corner1 == '') and (not re.search(corner2, item) or corner2 == ''):
      return item
  return None

def getFBGraphHash(flow):
  if 'fields' in flow.request.query: 
    return RequestIndex(flow, True, sorted(flow.request.query['fields'].split(',')))
  else:
    return RequestIndex(flow, True, [""])

def processFBURL(paraPool, pair=2):
  import re

  if pair == 2:
    equal = None
    URL1 = None
    URL2 = None
    URL3 = None
    URL4 = None
    if countURL(paraPool, 'graph.facebook.com/v(.*)/me\+', True) - countURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+\+', True) == 1:
      equal = True
    else:
      equal = False
    if equal:
      URL1 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me', 'graph.facebook.com/v(.*)/me\+')
      URL2 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+', 'graph.facebook.com/v(.*)/me\+\+\+')
      URL3 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+\+', 'graph.facebook.com/v(.*)/me\+\+\+\+')
      URL4 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+\+\+')
    else:
      for item in paraPool.keys():
        if re.search('graph.facebook.com/v(.*)/me', item) and not re.search('graph.facebook.com/v(.*)/me\+\+\+', item):
          if URL1 == None:
            URL1 = item
          else:
            URL2 = item
        if re.search('graph.facebook.com/v(.*)/me\+\+\+', item):
          if URL3 == None:
            URL3 = item
          else:
            URL4 = item 
    return [URL1, URL2, URL3, URL4]   
  elif pair == 3:
    URL1 = None
    URL2 = None
    URL3 = None
    URL4 = None
    URL5 = None
    URL6 = None
    if countURL(paraPool, 'graph.facebook.com/v(.*)/me\+', True) - countURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+\+', True) == 0:
      for item in paraPool.keys():
        if re.search('graph.facebook.com/v(.*)/me', item) and not re.search('graph.facebook.com/v(.*)/me\+\+\+', item):
          if URL1 == None:
            URL1 = item
          elif URL2 == None:
            URL2 = item
          else:
            URL3 = item
        if re.search('graph.facebook.com/v(.*)/me\+\+\+', item):
          if URL4 == None:
            URL4 = item
          elif URL5 == None:
            URL5 = item
          else:
            URL6 = item
    elif countURL(paraPool, 'graph.facebook.com/v(.*)/me\+', True) - countURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+\+', True) == 1:
      URL2 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+', 'graph.facebook.com/v(.*)/me\+\+\+')
      URL5 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+\+\+')
      for item in paraPool.keys():
        if re.search('graph.facebook.com/v(.*)/me', item) and not re.search('graph.facebook.com/v(.*)/me\+\+\+', item) and item != URL2:
          if URL1 == None:
            URL1 = item
          else:
            URL3 = item
        if re.search('graph.facebook.com/v(.*)/me\+\+\+', item) and item != URL5:
          if URL4 == None:
            URL4 = item
          else:
            URL6 = item
    else:
      URL1 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me', 'graph.facebook.com/v(.*)/me\+')
      URL2 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+', 'graph.facebook.com/v(.*)/me\+\+')
      URL3 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+', 'graph.facebook.com/v(.*)/me\+\+\+')
      URL4 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+\+', 'graph.facebook.com/v(.*)/me\+\+\+\+')
      URL5 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+\+\+', 'graph.facebook.com/v(.*)/me\+\+\+\+\+')
      URL6 = extractFBURL(paraPool, 'graph.facebook.com/v(.*)/me\+\+\+\+\+\+')

    return [URL1, URL2, URL3, URL4, URL5, URL6]        

################################################################################

#Process User parameter pool to generate two para combination
def processJson(fileName, fileType, dimension=2, opt=None, switchCH=True):
  if dimension < 2:
    return

  paraJson = json.load(open(fileName))
  
  if fileType == 'request':
    for url in paraJson:
      insertedVals = []
      paraJson[url]['hybrid'] = []
      
      #Later can easily add header and cookie here
      combMths = ['post', 'get', 'header', 'cookie']
      if not switchCH:
        combMths = ['post', 'get']
      candidates = []
      for mth in combMths:
        if mth not in paraJson[url]:
          continue
        for keyidx in range(len(paraJson[url][mth])):
          varName = paraJson[url][mth][keyidx].keys()[0]
          if varName == 'replacedValue':
            varName = paraJson[url][mth][keyidx].keys()[1]
          oprs = paraJson[url][mth][keyidx][varName]
          if mth == 'post':
            varName += '^_^'
          elif mth == 'header':
            varName += '=_='
          elif mth == 'cookie':
            varName += '-=-'
          repVal = ''
          if 'replacedValue' in paraJson[url][mth][keyidx]:
            repVal = paraJson[url][mth][keyidx]['replacedValue']
          candidates.append({'name':varName, 'oprs':oprs, 'replacedValue':repVal})

      if len(candidates) < 2:
        continue
      for paraLen in range(2, min(dimension,len(candidates))+1):
        for comb in itertools.permutations(candidates, paraLen):
          try:
            allOprs = [ele['oprs'] for ele in comb]
            allNames = [str(ele['name']) for ele in comb]
            if '>_<'.join(sorted(allNames)) in insertedVals:
              continue
            insertedVals.append('>_<'.join(sorted(allNames)))
            allRepVals = [str(ele['replacedValue']) for ele in comb]
            opr = []
            for combmth in itertools.product(*allOprs):
              if opt == 'onlyRep' and ('rm' in combmth or 'ran' in combmth):
                continue
              elif opt == 'noRan' and ('ran' in combmth):
                continue
              else:
                opr.append(combmth)
            paraJson[url]['hybrid'].append({'^v^'.join(allNames):opr, 'replacedValue':'^v^'.join(allRepVals)})
          except:
            pass

  elif fileType == 'response':
    for url in paraJson:
      insertedVals = []
      oldPara = copy.deepcopy(paraJson[url])
      if len(oldPara) < 2:
        continue
      for paraLen in range(2, min(dimension,len(oldPara))+1):
        for comb in itertools.permutations(oldPara, paraLen):
          allMths = [ele['path'][0] for ele in comb]
          if ('header' in allMths or 'cookie' in allMths) and not switchCH:
            continue
          allOprs = [ele['operation'] for ele in comb]
          allPaths = ['hybrid']+[ele['path'] for ele in comb]
          if '>_<'.join(sorted(['>_<'.join(map(repr, ele['path'])) for ele in comb])) in insertedVals:
            continue
          insertedVals.append('>_<'.join(sorted(['>_<'.join(map(repr, ele['path'])) for ele in comb])))
          opr = []
          for combmth in itertools.product(*allOprs):
            if opt == 'onlyRep' and ('rm' in combmth or 'ran' in combmth):
              continue
            elif opt == 'noRan' and ('ran' in combmth):
              continue
            else:
              opr.append(combmth) 
          paraJson[url].append({'operation':opr, 'path':allPaths})

  json.dump(paraJson, open(fileName, 'w'))
  return

def getUiautomatorConfig():
  with open('config.json', 'r') as fh:
    conf = json.load(fh)
    if conf["uiautomator2"] == 'True':
      return True
    else:
      return False
################################################################################

#Get same parameters across urls
def extractSamePara(fileNames, fileTypes, scope=['header', 'cookie', 'post', 'get', 'text'], valEqual=True, keyEqual=True):
  if not valEqual and not keyEqual:
    print "valEqual and keyEqual should at least have one to be True"
    return

  dbset = {}
  for fileName, fileType in zip(fileNames, fileTypes):
    paraJson = json.load(open(fileName))
    if fileType == 'request':
      for url in paraJson:
        for rType in paraJson[url]:
          if rType not in scope:
            continue
          for cell in paraJson[url][rType]:
            paraName = [k for k in cell.keys() if k !='replacedValue'][0]
            paraVal = ''
            if 'replacedValue' in cell:
              paraVal = cell['replacedValue']
            newkey = []
            if keyEqual:
              newkey.append(paraName)
            if valEqual:
              newkey.append(repr(paraVal))
            newkey = '^v^'.join(newkey)

            if newkey not in dbset:
              dbset[newkey] = [[], []]
            dbset[newkey][0].append(url)
            dbset[newkey][1].append('request')
    elif fileType == 'response':
      for url in paraJson:
        for cell in paraJson[url]:
          if cell['path'][0] not in scope:
            continue
          paraName = '^_^'.join([str(v) for v in cell['path'][1:-1]])
          paraVal = cell['path'][-1]
          newkey = []
          if keyEqual:
            newkey.append(paraName)
          if valEqual:
            newkey.append(repr(paraVal))
          newkey = '^v^'.join(newkey)
          
          if newkey not in dbset:
            dbset[newkey] = [[],[]]
          dbset[newkey][0].append(url)
          dbset[newkey][1].append('response')

  #Filter 
  for para in dbset:
    if len(dbset[para][0]) < 2:
      continue
    if keyEqual:
      print 'Parameter:', para.split('^v^')[0].replace('^_^', ',')
    if valEqual:
      print 'Value:', para.split('^v^')[-1]
    print '\n'.join([u+', '+pos for u, pos in zip(dbset[para][0], dbset[para][1])])
    print '\n'

  return

################################################################################  

#Clean log
def cleanLog(logFolder):
  from os.path import isfile, join, isdir
  from os import listdir, walk, mkdir
  import os
  import urlparse

  allLogs = [join(dp, f) for dp, dn, filenames in walk(logFolder) for f in filenames if f == 'result.log']
  
  if not isdir('success'):
    mkdir('success')
  if not isdir('failure'):
    mkdir('failure')

  for logFile in allLogs:
    filePath, fileName = os.path.split(logFile)
    filePath, appName = os.path.split(filePath)
    while True:
      filePath, dateFolder = os.path.split(filePath)
      if filePath == logFolder:
        break

    outputFolder = 'success'
    
    if 'failed_log' in logFile:
      outputFolder = 'failure'
    elif 'success_log' in logFile:
      outputFolder = 'success'
    output = open(join(outputFolder, appName+'_'+dateFolder+'_result.log'), 'w')
    logUniqData = []
    with open(logFile) as f:
      for line in f.readlines():
        if '[ERROR]: ' not in line:
          continue
        errUri = line.strip().split(' ')[-1]
        errUriPath = urlparse.urlparse(errUri).path
        errExt = os.path.splitext(errUriPath)[1]
        if errExt.lower() in ['.js', '.css', '.jpg', '.png', '.jpeg', '.cgi', '.gif', '.xml']:
          continue
        #Remove time
        info = line.split(' ', 3)[-1]
        if info in logUniqData:
          continue
        output.write(line+'\n')
        logUniqData.append(info)
    output.close()
  return

################################################################################  

#Handle Google User Identify
def extractGoogleUser(eveAFileName, aliceAFileName, folderLocation):
  IdPDomain = json.load(open('config.json', 'r'))['IdPInfo']['fb']['domain']
  g_appinfo = json.load(open('appinfo.json', 'r'))

  with open(eveAFileName) as f:
    rawTrace = json.load(f)
    eveAraw = extractor.clean_trace(rawTrace['log']['entries'], [IdPDomain, g_appinfo['appNetloc'], 'googleapis'], False, 'fb')

  with open(aliceAFileName) as f:
    rawTrace = json.load(f)
    aliceAraw = extractor.clean_trace(rawTrace['log']['entries'], [IdPDomain, g_appinfo['appNetloc'], 'googleapis'], False, 'fb')

    userPara = {'userIdentifier':{}}
    for header in eveAraw:
      uri = header['request']['url']
      if '//www.googleapis.com/identitytoolkit/v3/relyingparty/verifyAssertion' in uri:
        try:
          rawContent = re.search(r"([{\[].*?[}\]])$", header['response']['content']['text']).group(1)
          rawJson = json.loads(rawContent)
        
          userPara['userIdentifier'][uri.split('?')[0]] = ['text', 'email']
          userPara['userIdentifier']['Eve'] = rawJson['email']
        except:
          pass
        break

    for header in aliceAraw:
      uri = header['request']['url']
      if '//www.googleapis.com/identitytoolkit/v3/relyingparty/verifyAssertion' in uri:
        try:
          rawContent = re.search(r"([{\[].*?[}\]])$", header['response']['content']['text']).group(1)
          rawJson = json.loads(rawContent)
          userPara['userIdentifier']['Alice'] = rawJson['email']
        except:
          pass
        break

    if 'Alice' in userPara['userIdentifier'] and 'Eve' in userPara['userIdentifier']:
      json.dump(userPara, open(os.path.join(folderLocation, 'user_para'), 'w'))
      return True
    else:
      return False

################################################################################

def checkAppiumError():
  import json
  import os

  result = []
  if not os.path.exists('appiumError.log'):
    return None
  else:
    errorLog = json.load(open('appiumError.log', 'r+'))
    errorItems = errorLog.keys()
    for item in errorItems:
      if checkTested(eval(item)[0], eval(item)[1], eval(item)[2], eval(item)[3], eval(item)[4]):
        continue
      else:
        result.append(eval(item))
    return result 

################################################################################

def extractToy(reqPoolName, respPoolName, toyTraceFile, idp_name):
  g_appinfo = json.load(open('appinfo.json', 'r'))
  #domainName = g_appinfo['appNetloc']
  IdPUris = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"].values()
  #IdPReturnUri = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"]['EveIdP_Auth'] 
  IdPDomain = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]['domain']
  #fuzzyHC = json.load(open('config.json', 'r'))['fuzzy_headercookie']

  with open(toyTraceFile, 'r') as f:
    rawTrace = json.load(f)
    eveToyraw = extractor.clean_trace(rawTrace['log']['entries'], [IdPDomain, g_appinfo['appNetloc']], False, idp_name)

  reqPool = json.load(open(reqPoolName, 'r'))
  respPool = json.load(open(respPoolName, 'r'))
  sinaSsoCounter = 0
  #fbDialogCounter = 0
  for header in eveToyraw:
    uri = extractor.extract_uri(header['request']['url'])
    uri = extractor.remove_http_scheme(uri)
    if uri == 'api.weibo.com/oauth2/sso_authorize':
      sinaSsoCounter += 1
    #elif re.search('m.facebook.com/v(.*)/dialog/oauth$', uri):
     # fbDialogCounter += 1

    if isInIdPUrisForExtra(extractor.remove_http_scheme(header['request']['url']), IdPUris):
      #Request
      justUris = {'request':reqPool.keys(), 'response':respPool.keys()}
      candidates = {'request':[], 'response':[]}
      for traceType in justUris:
        for traceUri in justUris[traceType]:
          if idp_name == 'wechat':
            if uri == traceUri or (uri[:3] == 'sz.' and uri[3:] == traceUri) or (uri[:3] != 'sz.' and 'sz.'+uri == traceUri):
              candidates[traceType].append(traceUri)
              break
          elif idp_name == 'fb':
            #ignore all ended with +
            if traceUri.split('{')[0][-1] == '+':
              continue
            for IdPUrilong in IdPUris:
              for IdPUri in IdPUrilong.split('|'):
                IdPUri = IdPUri.replace('\\?', '')
                if IdPUri == 'm.facebook.com/v(.*)/dialog/oauth':
                  IdPUri = 'm.facebook.com/v(.*)/dialog/oauth$'
                if re.search(IdPUri, uri) != None and re.search(IdPUri, uri).start() < 18 and re.search(IdPUri, traceUri) != None and re.search(IdPUri, traceUri).start() < 18:
                  if IdPUri == 'm.facebook.com/v(.*)/dialog/oauth$':
                    if traceUri[-1] != '+':
                      candidates[traceType].append(traceUri)
                  else:
                    candidates[traceType].append(traceUri)
          elif idp_name == 'sina':
            if sinaSsoCounter == 2 and uri == 'api.weibo.com/oauth2/sso_authorize':
              if traceUri == uri+'+':
                candidates[traceType].append(traceUri)
                break
            elif uri == traceUri:
              candidates[traceType].append(traceUri)
              break

      for traceType in candidates:
        for traceUri in candidates[traceType]:
          extraFound = False
          if traceType == 'request':
            toyReqComb = []
            for mth in reqPool[traceUri]:
              if mth == 'hybrid':
                continue
              extraAppend = []
              for paraID in range(len(reqPool[traceUri][mth])):
                paraDict = reqPool[traceUri][mth][paraID]
                if 'replacedValue' not in paraDict:
                  continue
                paraName = [k for k in paraDict if k != 'replacedValue'][0]
                if mth == 'get':
                  jsonQuery = jsonizeQuerydata(header['request']['queryString'])
                  if paraName in jsonQuery:
                    extraAppend.append({paraName:['rep1'], 'replacedValue':jsonQuery[paraName]})
                    toyReqComb.append({paraName:['rep1'], 'replacedValue':jsonQuery[paraName]})
                elif mth == 'post':
                  if 'postData' in header['request']:
                    jsonQuery = jsonizeQuerydata(header['request']['postData']['params'])
                    if paraName in jsonQuery:
                      extraAppend.append({paraName:['rep1'], 'replacedValue':jsonQuery[paraName]})
                      tempKey = paraName + '^_^'
                      toyReqComb.append({tempKey:['rep1'], 'replacedValue':jsonQuery[paraName]})
                elif mth == 'header':
                  pass
                  # jsonQuery = jsonizeHeader(header['request']['headers'])
                  # if paraName in jsonQuery:
                  #   extraAppend.append({paraName:['rep1'], 'replacedValue':jsonQuery[paraName]})
                elif mth == 'cookie':
                  pass
                  # jsonQuery = jsonizeHeader(header['request']['cookies'])
                  # if paraName in jsonQuery:
                  #   extraAppend.append({paraName:['rep1'], 'replacedValue':jsonQuery[paraName]})
              if len(extraAppend) > 0:
                reqPool[traceUri][mth] += extraAppend
                extraFound = True
            
            if extraFound:
              insertedVals = []
              for comb in itertools.permutations(toyReqComb, 2):
                allOprs = [['rep1', 'rep1']]
                allNames = []
                for ele in comb:
                  for keyName in ele.keys():
                    if keyName != 'replacedValue':
                      allNames.append(keyName)
                if '>_<'.join(sorted(allNames)) in insertedVals:
                  continue
                insertedVals.append('>_<'.join(sorted(allNames)))
                allRepVals = [str(ele['replacedValue']) for ele in comb]
                if 'hybrid' not in reqPool[traceUri]:
                  reqPool[traceUri]['hybrid'] = []
                reqPool[traceUri]['hybrid'].append({'^v^'.join(allNames):allOprs, 'replacedValue':'^v^'.join(allRepVals)})
              break
          elif traceType == 'response':
            extraAppend = []
            accessTkn = []
            toyResComb = []
            hybridStart = None
            for paraID in range(len(respPool[traceUri])):
              paraDict = respPool[traceUri][paraID]
              if paraDict['path'][0] == 'hybrid' or paraDict['path'][0] == "cookie" or paraDict['path'][0] == "header" or 'rep' not in paraDict['operation']:
                if (paraDict['path'][0] == 'hybrid' or paraDict['path'][0] == "cookie" or paraDict['path'][0] == "header") and hybridStart == None:
                  hybridStart = paraID
                continue

              #Get replaced value
              paths =copy.deepcopy(paraDict['path'])
              startPos = 0
              if paths[0] == 'cookie':
                pass
                # tmpD = jsonizeHeader(header['response']['cookies'])
                # startPos = 1
              elif paths[0] == 'header':
                pass
                # tmpD = jsonizeHeader(header['response']['headers'])
                # startPos = 1
              else:
                tmpD = header['response']['content']
              paraExist = True
              for pid in range(startPos, len(paths)-1):
                if paths[pid] not in tmpD and type(tmpD) is dict:
                  paraExist = False
                  break
                elif type(tmpD) is list and paths[pid] >= len(tmpD):
                  paraExist = False
                  break
                
                try:
                  tmpD = tmpD[paths[pid]]
                except:
                  pass
                
                if idp_name == 'fb':
                  try:
                    if tmpD.index('for (;;);') == 0:
                      tmpD = tmpD[9:]
                  except:
                    pass

                if paths[0] == 'header' and paths[pid].lower() == 'location' and idp_name == 'wechat' and 'connect/oauth2/authorize_reply' in uri:
                  tmpD = {'code':tmpD.split('?')[1].split('code=')[1].split('&')[0], 'state':tmpD.split('?')[1].split('state=')[1].split('&')[0]}
                elif isJson(tmpD):
                  tmpD = json.loads(tmpD)
                

              if paraExist:
                paths[-1] = tmpD
              else:
                continue
              if 'access_token' == paths[-2] and (('api.weibo.com/oauth2/sso_authorize+' in traceUri) or ('api.weixin.qq.com/sns/oauth2/access_token' in traceUri) or ('dialog/oauth/read' in traceUri)):
                if idp_name == 'fb' and 'dialog/oauth/read' in traceUri:
                  paths[-1] = getFBResponseValue(header['response']['content']['text'], 'access_token')
                accessTkn.append({'path':paths, 'operation':['rep']})
                toyResComb.append({'path':paths, 'operation':['rep1']})
              else:
                if idp_name == 'fb' and 'dialog/oauth/read' in traceUri:
                  paths[-1] = getFBResponseValue(header['response']['content']['text'], paths[-2])
                extraAppend.append({'path':paths, 'operation':['rep1']})
                toyResComb.append({'path':paths, 'operation':['rep1']})
            
            insertedVals = []
            for comb in itertools.permutations(toyResComb, 2):
              allPaths = ['hybrid']+[ele['path'] for ele in comb]
              if '>_<'.join(sorted(['>_<'.join(map(repr, ele['path'])) for ele in comb])) in insertedVals:
                continue
              insertedVals.append('>_<'.join(sorted(['>_<'.join(map(repr, ele['path'])) for ele in comb])))
              opr = [['rep1', 'rep1']]
              extraAppend.append({'operation':opr, 'path':allPaths})

            if hybridStart == None:
              respPool[traceUri] += extraAppend
            else:
              respPool[traceUri][hybridStart:hybridStart] = extraAppend
            respPool[traceUri] += accessTkn
            if len(extraAppend) > 0 or len(accessTkn) > 0:
              extraFound = True

            if extraFound:
              break

  json.dump(reqPool, open(reqPoolName, 'w'))
  json.dump(respPool, open(respPoolName, 'w'))
  return

################################################################################

def prioritizeCombinationinRes(resPoolName):
  respPool = json.load(open(resPoolName, 'r'))
  for url in respPool:
    startPos = 0
    endPos = 0
    for i in range(len(respPool[url])):
      if (respPool[url][i]["path"][0] == 'header' or respPool[url][i]["path"][0] == 'cookie') and startPos == 0:
        startPos = i
      if (respPool[url][i]["path"][0] == 'header' or respPool[url][i]["path"][0] == 'cookie') and (i != (len(respPool[url]) - 1) and respPool[url][i + 1]["path"][0] == 'hybrid') and endPos == 0:
        endPos = i
        break
    if startPos != 0 and endPos != 0:
      if 'access_token' in str(respPool[url][-1]) and respPool[url][-1]['operation'] == ['rep']:
        extraATCase = respPool[url][-1]
        combination = respPool[url][(endPos + 1):-1]
        respPool[url] = respPool[url][0:(endPos + 1)]
        respPool[url][startPos:startPos] = combination
        respPool[url].append(extraATCase)
      else:
        combination = respPool[url][(endPos + 1):]
        respPool[url] = respPool[url][0:(endPos + 1)]
        respPool[url][startPos:startPos] = combination
  json.dump(respPool, open(resPoolName, 'w'))


################################################################################

if __name__ == '__main__':
  import extractor
  import json
  from ast import literal_eval
  import toolTesting
  import os

  idp_name = 'wechat'
  folder_location = '../networkTraceResult/cc.iriding.mobile_4.4.1_wechat/'
  # g_appinfo = json.load(open('appinfo.json', 'r'))
  
  # domainName = g_appinfo['appNetloc']
  domainNames = toolTesting.getDomain('eveA.trace', 'eveA.trace', 'aliceA.trace', 'eveA2.trace', None, idp_name)
  print domainNames
  # domainNames = ['sina.cn', 'baidu.com','nowscore.com', 'win007.com', 'qq.com']
  #Init key response param set
  filter_subsequent = True
  for domainName in domainNames:
    print domainName
    updateDomainName(domainName)
    g_appinfo = json.load(open('appinfo.json', 'r'))
    if getUDKeys('eveA.trace', 'eveA.trace', 'aliceA.trace', 'eveA2.trace', '', folder_location, idp_name):
      break
    # raw_input()
  else:
    filter_subsequent = False
  # getUDKeys('eveA+.trace', 'eveA+.trace', 'aliceA+.trace', 'eveA+.trace', appendix='+', folder_location=folder_location, idp_name=idp_name)
      # json.dump('appinfo.json', 'r')
  # getUDKeys('eveA+.trace', 'eveA+.trace', 'aliceA+.trace', 'eveA+.trace', '+', '../networkTraceResult/shanbay.com')
  
  # try:
  #   userIdentifier = json.load(open(os.path.join(folder_location, 'user_para'), 'r'))
  #   print userIdentifier
  # except ValueError, e:
  #   print e
  #   exit()
  
  permunateUrl(g_appinfo, folder_location, idp_name, filter_subsequent)

  #extractSamePara(['result/request_para', 'result/response_para'], ['request', 'response'])

  '''
  #Permunate multiple parameters
  fileLists = {'request':['request_para', 'request_para+'], 'response':['response_para', 'response_para+']}
  for ftype in fileLists:
    for fname in fileLists[ftype]:
      processJson(os.path.join(folder_location, fname), ftype, dimension=2)
  '''
  #Init key request param set
  # rawTrace = json.load(open('eveA.trace', 'r'))
  # trace = extractor.clean_trace(rawTrace['log']['entries'], ['api.weibo', g_appinfo['appNetloc']])

  # hasOauth = False
  # for header in trace:
  #   pData = None
  #   if 'postData' in header['request']:
  #     pData = header['request']['postData']['text']

  #   permunateUrl(header['request']['url'], header['request']['queryString'], pData, header['response'])




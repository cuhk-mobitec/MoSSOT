import json
import requests
import conf
import extractor
import urllib
from tools import isJson
from tools import toServer
from tools import decoupleFBResponse
import os
from urlparse import *
import logging
import re
from logger import MyLogger
# from urlparse 

running_logger = MyLogger(__name__).get_logger()
result_logger = logging.getLogger('result')
g_conf = conf.g_config
#g_appinfo = json.load(open('appinfo.json', 'r'))

def checkWebViewer(input):
	for item in input:
		if 'weibo' in item['request']['url'] and 'oauth2' in item['request']['url'] and 'response_type=code' in item['request']['url']:
			return True
	return False

def getAuthFlowType(input):
	for item in input:
		if 'access_token' in str(item):
			return 'token'
	return 'code'

def extractCodefromTrace(input, idp_name = "sina"):
	redirect_uri = None
	code = None
	if idp_name == "sina":
		for item in input:
			if 'weibo' in item['request']['url'] and 'oauth2' in item['request']['url'] and 'response_type=code' in item['request']['url']:
				for element in item['request']['queryString']:
					if element['name'] == 'redirect_uri':
						redirect_uri = element['value']
						break

		if redirect_uri == None:
			return None

		for item in input:
			# print item['request']['url']
			if redirect_uri in item['request']['url']:
				for element in item['request']['queryString']:
					if element['name'] == 'code':
						code = element['value']
						return code


	elif idp_name == "wechat":
		for item in input:
			if "open.weixin.qq.com/connect/oauth2/authorize_reply" in item['request']['url'] and "code=" in item['response']['redirectURL']:
				parsed = urlparse(item['response']['redirectURL'])
				code = parse_qs(parsed.query)['code']
				return code
	elif idp_name == "fb":
		IdPReturnUri = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"]['EveIdP_Auth']	
		for item in input:
			if re.search(IdPReturnUri, item['request']['url']):
				response_text = item['response']['content']['text']
				access_token = getFBResponseField(response_text, 'code')
				return code
	return code

def checkCodeDisclosure(input, code):
	for item in input:
		if code in str(item['request']) or code in str(item['response']):
			if 'https' in item['request']['url']:
				pass
			else:
				result_logger.error('Authorization code disclosure in uri '+ item['request']['url'])
				return True
	return False

def checkATDisclosure(input, AT):
	for item in input:
		if AT in str(item['request']) or AT in str(item['response']):
			if 'https' in item['request']['url']:
				pass
			else:
				result_logger.error('Access Token disclosure in uri '+ item['request']['url'])
				return True
	return False

def extractATfromTrace(input, idp_name="sina"):
	access_token = None
	if idp_name == "sina":
		for item in input:
			if 'https://api.weibo.com/oauth2/sso_authorize' in item['request']['url'] and 'access_token' in item['response']['content']['text']:
				response_text = json.loads(item['response']['content']['text'])
				if response_text['access_token'] != None:
					access_token = response_text['access_token']
					break
				# for element in str(item['response']['content']['text']).split(','):
				# 	if 'access_token' in element:
				# 		access_token = element.split('"')[-2]
				# 		return access_tokent 
			elif 'https://open.weibo.cn/oauth2/authorize' in item['request']['url'] and 'access_token' in item['response']['redirectURL']:
				for element in str(item['response']['redirectURL']).split('&'):
					if 'access_token' in element:
						access_token = str(element).split('=')[-1]
						break

	elif idp_name == "wechat":
		for item in input:
			if ("api.weixin.qq.com/sns/oauth2/access_token" in item['request']['url'] or "api.weixin.qq.com/sns/oauth2/refresh_token" in item['request']['url']) and 'access_token' in item['response']['content']['text']:
				response_text = json.loads(item['response']['content']['text'])
				return response_text['access_token']
	elif idp_name == "fb":
		IdPReturnUri = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"]['EveIdP_Auth']	
		for item in input:
			if re.search(IdPReturnUri, item['request']['url']):
				response_text = item['response']['content']['text']
				access_token = getFBResponseField(response_text, 'access_token')
				return access_token
	return access_token

def getFBResponseField(response_text, field):
	magic_number = '<script type=\"text/javascript\">window.location.href=\"fbconnect:\\/\\/success#'
	if magic_number not in response_text:
		return None
	else:
		response_text = response_text.replace(magic_number,'')
		response_text = response_text.replace('\";</script>','')
		fields = response_text.split('&')
		for item in fields:
			key,value = item.split('=')
			if key == field:
				return value
	return None


def extractUidfromTrace(input, idp_name="sina"):
	uid = None
	app_scoped_uid = None

	if idp_name == "sina":
		for item in input:
			if 'https://api.weibo.com/oauth2/sso_authorize' in item['request']['url'] and 'access_token' in item['response']['content']['text']:
				response_text = json.loads(item['response']['content']['text'])
				return response_text['uid'], None

				# for element in str(item['response']['content']['text']).split(','):
				# 	if 'access_token' in element:
				# 		access_token = element.split('"')[-2]
				# 		return access_tokent 
			elif 'https://open.weibo.cn/oauth2/authorize' in item['request']['url'] and 'uid' in item['response']['redirectURL']:
				for element in str(item['response']['redirectURL']).split('&'):
					if 'uid' in element:
						uid = str(element).split('=')[-1]
						return uid, None

	elif idp_name == "wechat":
		for item in input:
			if ("api.weixin.qq.com/sns/oauth2/access_token" in item['request']['url'] or "api.weixin.qq.com/sns/oauth2/refresh_token" in item['request']['url'] or "api.weixin.qq.com/sns/userinfo" in item['request']['url']) and 'openid' in item['response']['content']['text']:
				response_text = json.loads(item['response']['content']['text'])
				# unionid = None
				if 'unionid' in response_text:
					app_scoped_uid = response_text['unionid']
				return response_text['openid'], app_scoped_uid

	elif idp_name == "fb":
		IdPShowRPAppInfo = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"]['IdPShowRPAppInfo']
		ShowUserInfo = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"]['ShowUserInfo']

		for item in input:
			if uid == None and re.search(IdPShowRPAppInfo, item['request']['url']) != None:
				# get uid
				response_text = item['response']['content']['text']
				if len(response_text) == 0:
					continue
				try:
					start_index = response_text.index('\"USER_ID\":"')+ len('\"USER_ID\":"')
					end_index = response_text.index('\",\"ACCOUNT_ID\"')
					uid = response_text[start_index:end_index]
				except ValueError, e:
					print e
					continue
			if app_scoped_uid == None and re.search(ShowUserInfo, item['request']['url']) != None:
				try:
					response_text = json.loads(item['response']['content']['text'])
				except:
					continue
				app_scoped_uid = response_text['id']
			if app_scoped_uid != None and uid != None:
				return uid, app_scoped_uid

			#get app_scoped_uid
	return uid, app_scoped_uid

def extractUsernamefromTrace(input, idp_name="sina"):
	username = None
	if idp_name == "sina":
		for item in input:
			if 'https://api.weibo.cn/2/account/login' in item['request']['url'] and 'screen_name' in item['response']['content']['text']:
				response_text = json.loads(item['response']['content']['text'])
				return response_text['screen_name']
				# for element in str(item['response']['content']['text']).split(','):
				# 	if 'access_token' in element:
				# 		access_token = element.split('"')[-2]
				# 		return access_tokent 
			elif 'https://api.weibo.cn/2/account/login' in item['request']['url'] and 'screen_name' in item['response']['redirectURL']:
				for element in str(item['response']['redirectURL']).split('&'):
					if 'screen_name' in element:
						username = str(element).split('=')[-1]
						return username
	elif idp_name == "wechat":
		for item in input:
			if "api.weixin.qq.com/sns/userinfo" in item['request']['url'] and "nickname" in item['response']['content']['text']:
				response_text = json.loads(item['response']['content']['text'])
				return response_text['nickname'] 
	elif idp_name == "fb":
		IdPShowRPAppInfo = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"]['IdPShowRPAppInfo']
		for item in input:
			if re.search(IdPShowRPAppInfo, item['request']['url']) != None:
				response_text = item['response']['content']['text']
				if len(response_text) == 0:
					continue
				try:
					start_index = response_text.index('\"NAME\":\"')+ len('\"NAME\":\"')
					end_index = response_text.index('\",\"SHORT_NAME\":')
					return response_text[start_index:end_index]
				except ValueError, e:
					print e
					continue
	return username

def extractPackageNamefromTrace(input, idp_name='sina'):
	packageName = None
	if idp_name == 'sina':
		for item in input:
			if 'https://api.weibo.com/oauth2/sso_authorize' in item['request']['url']:
				params = item['request']['postData']['params']
				for element in params:
					if element['name'] == 'packagename':
						return element['value']
	elif idp_name == 'fb':
		IdPShowRPAppInfo = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"]['IdPShowRPAppInfo']
		for item in input:
			if re.search(IdPShowRPAppInfo, item['request']['url']) != None:
				headers = item['request']['headers']
				for element in headers:
					if element['name'] == 'X-Requested-With':
						return element['value']
	else:
		return packageName

def checkRevocation(idp, AT):
	if idp == 'sina':
		resp = requests.get('https://api.weibo.com/oauth2/revokeoauth2?access_token='+ AT, timeout = 1200)
		if 'error' in resp.text:
			print 'Fail to revoke'
			return
		else:
			result_logger.error('Warning: Failure of revocation!')
			return
	elif idp == 'fb':
		resp = requests.get('https://graph.facebook.com/me/permissions?method=delete&access_token='+access_token, timeout = 1200)
		if '"success":true' not in resp.text:
			print 'Fail to revoke'
			return
		else:
			result_logger.error('Warning: Failure of revocation!')
			return		

def checkReturnOfAT(idp, AT, input):
	for item in input:
		if AT in str(item['request']) and str(idp) not in item['request']['url']:
			return True
	result_logger.error('Alert: the app does not return access_token to its server!')
	return False

def searchElement(item, element):
	for term in item:
		if term['name'] == element:
			return term['value']

def extractStatefromTrace(input, idp='sina'):
	state = None
	if idp == 'sina':
		for item in input:
			if 'weibo' in item['request']['url'] and 'oauth2' in item['request']['url']:
				state = searchElement(item['request']['queryString'],'state')
				if state != None:
					return state
				state = searchElement(item['request']['cookies'],'state')
				if state != None:
					return state
				state = searchElement(item['request']['headers'],'state')
				if state != None:
					return state
				if 'postData' in item['request']:
					state = searchElement(item['request']['postData']['params'],'state')
					if state != None:
						return state
	elif idp == 'fb':
		IdPReturnUri = json.load(open('config.json', 'r'))['IdPInfo'][idp]["url"]['EveIdP_Auth']	
		for item in input:
			if re.search(IdPReturnUri, item['request']['url']):
				response_text = item['response']['content']['text']
				state = decoupleFBResponse(response_text)[1]['state']
				return state		
	return state
			
def checkStateMissing(input, idp='sina'):
	if idp == 'sina':
		if extractStatefromTrace(input) == None:
			result_logger.error('Error: STATE variable is missing in the webviewer case!')
	elif idp == 'fb':
		if extractStatefromTrace(input, 'fb') == None:
			result_logger.error('Error: STATE variable is missing!')

def checkStateUsage(input1, input2, idp='sina'):
	state1 = extractStatefromTrace(input1, idp)
	state2 = extractStatefromTrace(input2, idp)
	if state1 == state2:
		result_logger.error('Error: STATE variable is misused in the webviewer case!')

def checkCovert_Rediret(input):
	for item in input:
		if 'weibo' in item['request']['url'] and ('oauth2' in item['request']['url'] or 'login' in item['request']['url']):
			if 'redirect_uri' in item['request']['url']:
				uri = extractor.extract_uri(item['request']['url'])
				tmpQuery = {}
				for term in item['request']['queryString']:
					if term['name'] != 'redirect_uri':
						tmpQuery[term['name']] = term['value']
					else:
						tmpQuery[term['name']] = 'https://www.baidu.com/'
				queryString = urllib.urlencode(tmpQuery)	
				params = None
				if 'postData' in item['request']:
					tmpParams = {}
					for prt in item['request']['postData']['text'].split('&'):
						try:
							k, v = prt.split('=')
						except:
							continue
						tmpParams[k] = v
					params = tmpParams
				method = None
				if params != None:
					method = 'POST'
				else:
					method = 'GET'
				resp = toServer(uri+'?'+queryString, method, params)
				if 'error' not in resp.text:
					result_logger.error('Warning: covert redirect is possible!')		
			elif 'postData' in item['request'] and 'redirect_uri' in item['request']['postData']['text']:
				uri = extractor.extract_uri(item['request']['url'])
				tmpQuery = {}
				for term in item['request']['queryString']:
					tmpQuery[term['name']] = term['value']
				queryString = urllib.urlencode(tmpQuery)	
				params = None
				tmpParams = {}
				for prt in item['request']['postData']['text'].split('&'):
					try:
						k, v = prt.split('=')
					except:
						continue
					tmpParams[k] = v
					if k == 'redirect_uri':
						tmpParams[k] = 'https://www.baidu.com/'
				params = tmpParams
				method = 'POST'
				resp = toServer(uri+'?'+queryString, method, params)					
				if 'error' not in resp.text:
					result_logger.error('Warning: covert redirect is possible!')	

def checkTrace(input, idp_name = 'sina'):
	import re

	result = 0
	if idp_name == 'sina':
		for item in input:
			if 'api.weibo.cn/2/account/login' in item['request']['url'] and item['response']['status']==200:
				result += 1
			if 'api.weibo.com/oauth2/sso_authorize' in item['request']['url'] and item['response']['status']==200 and (not "error_code" in item['response']['content']['text']):
				result += 1
	elif idp_name == 'wechat':
		for item in input:
			if 'open.weixin.qq.com/connect/oauth2/authorize?' in item['request']['url'] and item['response']['status']==200:
				result += 1
			if 'open.weixin.qq.com/connect/oauth2/authorize_reply' in item['request']['url'] and item['response']['status']==301 and (not "error_code" in item['response']['content']['text']):
				result += 1
	elif idp_name == 'fb':
		for item in input:
			if 'm.facebook.com/login/async' in item['request']['url'] and item['response']['status']==200:
				result += 1
			elif re.search('m.facebook.com/v(.*)/dialog/oauth\\?', item['request']['url']) and item['response']['status']==200:
				result += 1
			elif re.search('m.facebook.com/v(.*)/dialog/oauth/confirm', item['request']['url']) and item['response']['status']==200:
				result += 1
			elif re.search('m.facebook.com/v(.*)/dialog/oauth/read', item['request']['url']) and item['response']['status']==200:
				result += 1
	return result

def getDomain(input1, input2, input3, input4, package, idp_name='sina'):
	from tools import similarity
	# unrelatedWeiboDomain = ['api.weibo.cn/2/account/login', 'api.weibo.com/oauth2/sso_authorize',  'api.weibo.com/2/users/show.json', 'api.weibo.com/2/account/get_uid.json', 'api.weibo.cn/2/push', 'api.weibo.cn/2/client/', 'api.weibo.cn/2/remind/unread_count', 'api.weibo.cn/2/push/active','open.weixin.qq.com/connect/oauth2/authorize','open.weixin.qq.com/connect/oauth2/authorize_reply','api.weixin.qq.com/sns/userinfo','api.weixin.qq.com/sns/oauth2/access_token','api.weixin.qq.com/sns/oauth2/refresh_token']
	IdPOAuthDomains = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"].values()
	IdPDomain = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]['domain']

	size1 = os.path.getsize(input1)
	size2 = os.path.getsize(input2)
	size3 = os.path.getsize(input3)
	size4 = os.path.getsize(input4)
	rawTrace = None
	if size1 < size2 and size1 < size3 and size1 < size4:
		rawTrace = json.load(open(input1, 'r'))['log']['entries']
	elif size2 < size1 and size2 < size3 and size2 < size4:
		rawTrace = json.load(open(input2, 'r'))['log']['entries']
	elif size3 < size1 and size3 < size2 and size3 < size4:
		rawTrace = json.load(open(input3, 'r'))['log']['entries']
	else:
		rawTrace = json.load(open(input4, 'r'))['log']['entries']

	rawTrace = extractor.clean_trace(rawTrace, [IdPDomain], True, idp_name)
	access_token = extractATfromTrace(rawTrace,idp_name)
	uid = extractUidfromTrace(rawTrace, idp_name)
	username = extractUsernamefromTrace(rawTrace, idp_name)
	packageName = extractPackageNamefromTrace(rawTrace, idp_name)
	if packageName == None:
		# package is obtained by reverse engineering
		packageName = package

	score = dict()	#{domain, score}
	for item in rawTrace:
		url = item['request']['url'].lower()
		# print url
		para = convertReq2Json(item)
		score[url] = 0

		if 'login' in url or 'signin' in url or 'signon' in url or 'logon' in url:
			score[url] +=1
		if 'account' in url or 'my' in url or 'user' in url:
			score[url] +=1
		if 'token' in url or 'callback' in url or 'third' in url or 'sso' in url:
			score[url] +=1
		if packageName != None:
			score[url] += similarity(packageName,urlparse(url).hostname, 0.3) * 5
		if not isinstance(para, dict):
			continue

		for key,value in para.iteritems():
			sim = similarity(key, 'access_token')
			score[url] += sim * 2
			sim = similarity(value, access_token)
			score[url]+= sim * 5 # access_token is the most important para

			sim = similarity(key, 'uid')
			score[url] += sim

			sim = similarity(value, uid)
			score[url] += sim *2

	# we do not count those IdP domains
	for url in score.keys():
		for IdPDomain in IdPOAuthDomains:
			if re.search(IdPDomain, url) != None:
				score.pop(url, None)
				break

	mergedScore = dict()

	for domain, score in score.iteritems():
		domain = str(urlparse(domain).hostname).split('.')[-2] + '.' + str(urlparse(domain).hostname).split('.')[-1]
		if domain in mergedScore:
			mergedScore[domain] += score
		else:
			mergedScore[domain] = score

	sorted_score = sorted(mergedScore.items(), key=lambda x: x[1])
	# This may be a third-party proxy
	whiteList = ['umsns.com']
	domains = []
	# for element in reversed(sorted_score):
	# 	print element[0]
	for element in reversed(sorted_score):
		if element[0] not in whiteList:
			# sorted_score.remove(element)
			domains.append(element[0])

	return domains

def checkStateDisclosure(input, state):
	for item in input:
		if state in str(item['request']) or state in str(item['response']):
			if 'https' in item['request']['url']:
				pass
			else:
				result_logger.error('State disclosure in uri '+ item['request']['url'])
				return True
	return False	

def convertReq2Json(req):
	para = dict()

	for item in req['request']['queryString']:
		para[item['name']] = item['value']

	if 'postData' in req['request']:
		if isJson(req['request']['postData']['text']):
			new_para = json.loads(req['request']['postData']['text'])
			while type(new_para) is list:
 				new_para = new_para[0]
			if isJson(new_para):
				new_para = json.loads(new_para)
			try:
				para = dict(para.items() + new_para.items())
			except:
				running_logger.debug('exception in handling parameter: {}'.format(new_para))
		else:
			for prt in req['request']['postData']['text'].split('&'):
				try:
					k, v = prt.split('=')
				except:
					continue
				para[k] = v
	return para

#print getDomain('aliceA.trace', 'eveA.trace', 'eveA2.trace', 'eveB.trace')
#rawTrace = json.load(open('network.trace', 'r'))['log']['entries']
#print checkTrace(rawTrace)
if __name__ == '__main__':	
	#print getDomain('aliceA.trace', 'aliceA.trace', 'aliceA.trace', 'aliceA.trace', None, 'fb')
	# response_text = "<script type=\"text/javascript\">window.location.href=\"fbconnect:\\/\\/success#granted_scopes=public_profile&denied_scopes=&signed_request=CE5ODMQoxu7FJ_Sy_h4lJYFwROn7JemeADGooQMzFGs.eyJhbGdvcml0aG0iOiJITUFDLVNIQTI1NiIsImNvZGUiOiJBUUNIWE1VaXUySExDeUFiVVFQelBxRWIzX0k2VkVoeHZxUWhkZ19XWWdmRWJMRXFHM1dlb3JhWkcxNXgyT1JfVDk4TkI5dTcyTlZaT1ZwOHl2QlJtN0FyTGh1MW14eW9YTXNiNlQ0WEp0WWloNU5RbUc4R29TV3dLWi1NbkVqeXpkbm10TUR0ZmdjdGdSMUJGYWMtc0Mxbk9ydjdXbDFJQ2lHbzIzVFdQeXp6cGxxeDBmM3ZBZFY1Q3k0RF92WVBmMG9wMFVXWHVhM1NZU2hNWEtVX3E3ZmRYc0xjVWdHTFVmUEtYUnBhazJIRENNU0NmX1Rqa0hJUENPNGtKZERIY1Z6ZVNPWmVnUk5sTE5icF9Xb0JaSFpvTVgzdkJ6Q3MxakkyNldvNHFvQzZ1QmpodWViNTdYZzg2bWVfYzlfU0x1anU2S1Yzak1WaUNUbHF0Y21sVnkwciIsImlzc3VlZF9hdCI6MTUxMTI1MzY2MywidXNlcl9pZCI6IjE3MzgxMDI2OTMxNDMwOTkifQ&access_token=EAAIxvL80bSUBAL1c5DqTRnXkp1UwHfumybeUZC9yc9mnW1BSYpQ3gLE5PgBz8d6jvSIoemwPSNRtN088IaVNwK5HIMDuq0JV6TUOO9OfPOf3HZCNynOMFvN94ZBcdbRZAbOzNhK02Gx6hZBZB2MeS9H7ndOujRpSZAf6uwdCf0mWvpi7GzXpSLX&expires_in=0\";</script>"
	# print getFBResponseField(response_text, 'access_token')
	# print getFBResponseField(response_text, 'signed_request')
	# print getFBResponseField(response_text, 'code')
	# # import pdb; pdb.set_trace()
	AT = extractUidfromTrace(rawTrace, 'fb')
	# print AT
	# print checkATDisclosure(rawTrace, AT)
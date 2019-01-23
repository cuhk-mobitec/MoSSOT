import json
import urllib
import urlparse
import Cookie
import conf
import logging
import re

from ast import literal_eval

g_config = conf.g_config
running_logger = logging.getLogger(__name__)
running_logger.setLevel(logging.DEBUG)

usual_domins = ['com', 'cn', 'hk', 'edu', 'gov', 'net', 'org','au']
file_format = ['.jpg', '.png', '.gif', '.css', '.js', '.ico']
idpPush = {'sina':['api.weibo.cn/2/push', 'api.weibo.cn/2/client/', 'api.weibo.cn/2/remind/unread_count', 'api.weibo.cn/2/push/active'], 'wechat':[]}

def clean_trace(trace, domains=[], beforeGetDomain = False, idp_name = 'sina'): 
	#ignore RP packets before final response from the IdP server
	# Oauth_url = {'sina':['api.weibo.com/oauth2/sso_authorize', 'api.weibo.cn/2/account/login', 'api.weibo.com/2/users/show.json', 'api.weibo.com/2/account/get_uid.json'], 'wechat':['open.weixin.qq.com/connect/oauth2/authorize', 'api.weixin.qq.com/sns/oauth2/access_token', 'api.weixin.qq.com/sns/userinfo', 'api.weixin.qq.com/sns/oauth2/refresh_token']}
	Oauth_url = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]["url"]
	IdPShowRPAppInfoUrl = Oauth_url['IdPShowRPAppInfo']
	Oauth_url = Oauth_url.values()

	g_appinfo = json.load(open('appinfo.json', 'r'))
  	# if idp_name == 'fb':

	cleaned = []
	for header in trace:
		need_del = False
		content_type = extract_response(header, 'Content-Type')
		if content_type is not None and content_type.find('image') >= 0:
			need_del = True

		uri = extract_uri(header['request']['url'])
		# if beforeGetDomain == False and  "https://m.facebook.com/v2.8/dialog/oauth" in uri:
		# # if u'https://static.xx.fbcdn.net' in uri:
		#  	import pdb; pdb.set_trace()
		#  	print uri
		#  	print header['response']['status']
		if uri.find('localhost') >= 0:
			need_del = True
		# for idpp in idpPush[idp_name]:
		# 	if idpp in uri:
		# 		need_del = True
		# 		break

		# delete all request to IdP api but not oauth related 
		if '.weibo.' in uri and idp_name == 'sina':
			need_del = True
			try:
				for url in Oauth_url:
					if url in uri:
						need_del = False
			except:
				import pdb; pdb.set_trace()

		elif '.weixin.' in uri and idp_name == 'wechat':
			if 'open.weixin.qq.com/connect/authreport' not in uri:
				need_del = False
			else:
				need_del = True
		elif idp_name == "fb" and "facebook.com" in uri:
			for pattern in Oauth_url:
				try:
					if re.search(pattern, header['request']['url']) != None:
						# special case to filter out the first uri of "m.facebook.com/v(...)/dialog/oauth"
						if re.search(IdPShowRPAppInfoUrl, header['request']['url']) != None and header['response']['status'] == 302:
							need_del = True
							break
						else:
							need_del = False
							break
					else:
						need_del = True
				except:
					import pdb; pdb.set_trace()
					print uri

		if beforeGetDomain == False:
			chk = 0
			# if the url does not belong to domains, then we delete this url
			for dm in domains:
				if dm.lower() not in extract_netloc(header['request']['url']).lower():
					chk+=1
			if chk == len(domains) and chk != 0:
				need_del = True

			for ff in file_format:
				if uri.lower().find(ff)+len(ff) == len(uri) and '.json' not in uri.lower():
					need_del = True

		# if uri.find('.php') >= 0:
		#			need_del = True
		# if uri.find('.aspx') >= 0:
		#			need_del = True
		#if uri.find('img') >= 0:
		#	need_del = True
		#if uri.find('.png') >= 0:
		#	need_del = True
		# print uri, need_del
		if need_del is False:
			cleaned.append(header)

	#Extract oauth related requests only
	#Delete all RPapp-RPServer requests before oauth
	#Keep 20 RPapp-RPServer requests after oauth
	oauthRelated = []
	hasOauth = False
	cntPostOauth = 30 #upper bound of the number of RP resquests
	for header in cleaned:
		#Check if has gone through oauth 
		if not hasOauth:
			try:
				respJson = json.loads(header["response"]["content"]["text"])
			except:
				try:
					respJson = json.loads(literal_eval(header["response"]["content"]["text"]))
				except:
					respJson = header["response"]["content"]["text"], '----'
			if is_Oauth(header['request']['url'], respJson, idp_name):
				hasOauth = True

		if beforeGetDomain == False and g_appinfo['appNetloc'] in extract_netloc(header['request']['url']).lower():
			if not hasOauth:
				continue
			else:
				cntPostOauth-=1
			if cntPostOauth <=0:
				continue
		oauthRelated.append(header)
		#print header['request']['url']
	return oauthRelated


def extract_parameters(url):
	url = urllib.unquote(url)
	url_parsed = urlparse.urlparse(url)
	rst = urlparse.parse_qs(url_parsed.query)
	for key in rst.keys():
		rst[key] = rst[key][0]
	return rst

#http://api.weibo.com/2/sso_authorize
def extract_uri(url, withProt = True):
	url = urllib.unquote(url)
	url_parsed = urlparse.urlparse(url)
	if withProt:
		rst = url_parsed.scheme+'://'+url_parsed.netloc.split(':')[0]+url_parsed.path
	else:
		rst = url_parsed.netloc.split(':')[0]+url_parsed.path
	return rst

#api.weibo.com
def extract_netloc(url):
	url = urllib.unquote(url)
	url_parsed = urlparse.urlparse(url)
	return url_parsed.netloc.split(':')[0]

def extract_path(url):
	url = urllib.unquote(url)
	url_parsed = urlparse.urlparse(url)
	return url_parsed.path


def remove_http_scheme(url):
	import re
	return re.sub(r'^https?:\/\/', '', url, flags=re.MULTILINE)
#weibo
def extract_domain(url):
	url = urllib.unquote(url)
	url_parsed = urlparse.urlparse(url)
	domans = url_parsed.netloc.split(':')[0].split('.')
	rst = None
	for item in domans:
		if item not in usual_domins:
			rst = item
	return rst


def extract_response(header, domain=None):
	if domain is None:
		return header['response']
	if domain=='Content-Type':
		return header['response']['content']['mimeType']
	return header['response'][domain]


def extract_request(header, domain=None):
	if domain is None:
		return header['request']
	return header['request'][domain]


#Check if a request is happened after oauth
def is_rp_after_oauth(targetUrl, hasOauth = False):
	g_appinfo = json.load(open('appinfo.json', 'r'))	
	if hasOauth and g_appinfo['appNetloc'] in extract_netloc(targetUrl):
		return True
	else:
		return False

#resp refers to response.text and should convert to dict format
def is_Oauth(url, resp, idp_name = 'sina'):
	if idp_name == 'sina':
		if extract_uri(url, False) == 'api.weibo.com/oauth2/sso_authorize' and 'access_token' in resp:
			return True
		elif extract_uri(url, False) == 'api.weibo.cn/2/account/login' and 'oauth2.0' in resp and 'access_token' in resp['oauth2.0']:
			return True
		else:
			return False
	elif idp_name == 'wechat':
		if  'open.weixin.qq.com/connect/oauth2/authorize_reply' in extract_uri(url, False) or 'api.weixin.qq.com/sns/oauth2/access_token' in extract_uri(url, False):
			return True
		else:
			return False
	elif idp_name == 'fb':
		EveIdP_Auth = json.load(open('config.json', 'r'))['IdPInfo'][idp_name]['url']['EveIdP_Auth']
		if  re.search(EveIdP_Auth, extract_uri(url, False)):
			return True
		else:
			return False
	# if extract_uri(url, False) != 'api.weibo.com/oauth2/sso_authorize' or extract_uri(url, False) != 'api.weibo.cn/2/account/login':
	# 	return False
	# if 'oauth2.0' in resp and 'access_token' in resp['oauth2.0']:
	# 	return True
	# return False

def is_IdPReq(url):
	if 'oauth2' not in extract_uri(url, False):
		return False
	elif 'api.weixin.qq.com/sns/userinfo' in extract_uri(url, False) or 'api.weibo.cn/2/account/login' in extract_uri(url, False) or 'api.weibo.com/2/users/show' in extract_uri(url, False) or 'api.weibo.com/2/account/get_uid' in extract_uri(url, False):
		return True
	else:
		return True

#def is_OAuthUrl(url, domain, para):
#		if extract_doman(url) not in g_config['IdPconfig']:
#				return False
#		if 'oauth' not in extract_uri(url):
#				return False
#		if 'redirect_uri' not in para:
#				return False
#		if 'response_type' not in para:
#				 return False
#		if 'scope' not in para:
#				 return False
#		if domain not in url:
#				return False
#		return True


#def is_logoutUrl(url):
#		uri = extract_uri(url)
#		if 'https' in url:
#				return False
#		if uri.find('logout') >= 0:
#				return True
#		return False	


def is_sensitiveHeader(header):
		if header['statusCode'] != 302:
				return False
		location_url = extract_response(header, 'Location')
		from_doman = extract_doman(header['url'])
		location_doman = extract_doman(location_url)
		if from_doman == location_doman:
				return False
		para = extract_parameters(location_url)
		if 'client_id' not in para or 'redirect_uri' not in para:
				return False
		return True


def fill_in_app(app, para):
		for key in para:
				if key == 'client_id':
						app.client_id.append(para[key])
				if key == 'scope':
						app.scope.append(para[key])
				if key == 'app_secret':
						app.app_secret.append(para[key])
				if key == 'redirect_uri':
						app.redirect_uri.append(para[key])
				if key == 'access_token':
						app.access_token.append(para[key])
				if key == 'response_type':
						app.response_type.append(para[key])
				if key == 'state':
						app.state.append(para[key])
				if key == 'appid':
						app.appid = para[key]


def extract_cookie(header):
	cookie = {}
	for item in header['request']['cookies']:
		cookie[item['name']] = item['value']
	for item in header['response']['cookies']:
		cookie[item['name']] = item['value']
	return cookie


def extract_from_trace(trace):
	g_appinfo = json.load(open('appinfo.json', 'r'))
	trace = clean_trace(trace)
	#init_domain = extract_doman(knowledge.init_login_url)
	#knowledge.App.App_name = init_domain
	idp_name = None
	authenticate_uri = None

	for header in trace:
		url = header['request']['url']
		para = extract_parameters(url)
		if idp_name is None and ('api.weibo' in extract_netloc(url) or extract_domain(url) in g_appinfo['appDomain']):
			print header['request']['method'], url
			if 'post' in header['request']['method'].lower():
				print 'Post Data:'
				for k in header['request']['postData']['params']:
					print k['name'], k['value']
			print 'Query Data:'
			for k in header['request']['queryString']:
				print k['name'], k['value']
			print '\n'

def extract_from_tracefile(trace_path):
	global running_logger
	try:
		ori = json.load(open(trace_path, 'r'))
	except Exception, e:
		running_logger.error('could not open this trace %s', trace_path)
	extract_from_trace(ori['log']['entries'])


if __name__ == '__main__':
	extract_from_tracefile('alice_login_auth_logout.trace')



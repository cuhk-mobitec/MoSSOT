"""
This is a model file
Single Sign On, based on specification of OAuth 2.0

Some Step number refer to Figure 1(implicit flow of Oauth2.0) in paper 'Breaking and Fixing...' 
"""
import urllib
import random
from conf import g_config
#To do
#1. Enable condition of some states need to revised
#2. Webview may need to add more states

initialized = False

#Describe eve state in RP app
#possible values: login, logout
Eve_state = False

IdP_App_Installed = True
#need to be set after both use login via IdP app and user login via RPapp webview

IdP_Name = 'fb'

Eve_Auth_RP = False

doubleRequests = True

access_token = ''
finishIdPAuthIdPApp = False
finishIdPAuthIdPApp1 = False
finishIdPShowRPAppInfo = False
finishIdPShowRPAppInfo1 = False
finishEveIdP_Auth = False
finishEveIdP_Auth1 = False
finishRPAppHandshakeRPServ = False
finishShowUserInfo = False
finishShowMoreUserInfo = False
finishShowExtraUserInfo = False
finishGetUid = False
finishShowUserInfo1 = False
finishShowMoreUserInfo1 = False
finishShowExtraUserInfo1 = False
finishGetUid1 = False
finishGetAT = False
finishRefreshAT = False

traceOneFinished = False
traceTwoFinished = False
# configuration for different fuzzing action 
# 0: test known bugs
# 1: testing only includes idp 
# 2: testing include both idp and rp
# level 0: fuzzEveIdP_Auth, fuzzGetUid, fuzzShowUserInfo True, other False
# level 1: fuzzEveIdP_Auth, fuzzGetUid, fuzzShowUserInfo, fuzzIdPShowRPAppInfo, fuzzIdPAuthIdPApp True, other False
fuzzIdPAuthIdPApp = True
fuzzIdPAuthIdPApp1 = True
fuzzIdPShowRPAppInfo = True
fuzzIdPShowRPAppInfo1 = True
fuzzEveIdP_Auth = True
fuzzEveIdP_Auth1 = True
fuzzRPAppHandshakeRPServ = True
fuzzShowUserInfo = True
fuzzShowMoreUserInfo = True
fuzzShowExtraUserInfo = True
fuzzShowUserInfo1 = True
fuzzShowMoreUserInfo1 = True
fuzzShowExtraUserInfo1 = True
fuzzGetUid = False
fuzzGetUid1 = False
fuzzGetAT = False
fuzzRefreshAT = False

#Eve click login with IdP in RP App
def Initialize():
	pass

def InitializeEnabled():
	return not initialized

#Some IdP need to auth its own App. Like Sina and Google
def IdPAuthIdPApp():
	pass

def IdPAuthIdPAppEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and not Eve_Auth_RP and not Eve_state and fuzzIdPAuthIdPApp and not finishIdPAuthIdPApp and (IdP_Name == 'fb' or IdP_Name == 'sina')

#IdP verify RP App and show RP App info to let Eve click auth
def IdPShowRPAppInfo():
	pass

def IdPShowRPAppInfoEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and not Eve_Auth_RP and not Eve_state and fuzzIdPShowRPAppInfo and not finishIdPShowRPAppInfo and (finishIdPAuthIdPApp or not fuzzIdPAuthIdPApp)

#Eve auth IdP, refer to Step 2
def EveIdP_Auth():
	#Eve_state = 'login'
	pass

def EveIdP_AuthEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and not Eve_Auth_RP and not Eve_state and not finishEveIdP_Auth and (finishIdPAuthIdPApp or not fuzzIdPAuthIdPApp) and (finishIdPShowRPAppInfo or not fuzzIdPShowRPAppInfo)

#RP App send user info back to RP server. Refer to Step 5 in the flow.
def RPAppHandshakeRPServ():
	pass

def RPAppHandshakeRPServEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzRPAppHandshakeRPServ and not finishRPAppHandshakeRPServ

def ShowUserInfo():
	pass

def ShowUserInfoEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzShowUserInfo and not finishShowUserInfo

def ShowMoreUserInfo():
	pass

def ShowMoreUserInfoEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzShowMoreUserInfo and not finishShowMoreUserInfo

def ShowExtraUserInfo():
	pass

def ShowExtraUserInfoEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzShowExtraUserInfo and not finishShowExtraUserInfo

def GetUid():
	pass

def GetUidEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzGetUid and not finishGetUid

def GetAT():
	pass

def GetATEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzGetAT and not finishGetAT

def RefreshAT():
	pass

def RefreshATEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzRefreshAT and not finishRefreshAT	

def EveLoggedoutApp():
	pass

def EveLoggedoutAppEnabled():
	return not traceOneFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and (finishRPAppHandshakeRPServ or not fuzzRPAppHandshakeRPServ) and (finishShowUserInfo or not fuzzShowUserInfo) and (finishShowMoreUserInfo or not fuzzShowMoreUserInfo) and (finishShowExtraUserInfo or not fuzzShowExtraUserInfo) and (finishGetUid or not fuzzGetUid) and (finishGetAT or not fuzzGetAT) and (finishRefreshAT or not fuzzRefreshAT) 

def IdPAuthIdPApp1():
	pass

def IdPAuthIdPApp1Enabled():
	return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and not Eve_state and fuzzIdPAuthIdPApp1 and not finishIdPAuthIdPApp1 and (IdP_Name == 'fb' or IdP_Name == 'sina')

def IdPShowRPAppInfo1():
	pass

def IdPShowRPAppInfo1Enabled():
	if doubleRequests:
		return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and not Eve_state and fuzzIdPShowRPAppInfo1 and not finishIdPShowRPAppInfo1 and (finishIdPAuthIdPApp1 or not fuzzIdPAuthIdPApp1)
	else:
		return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and not Eve_state and not finishIdPShowRPAppInfo1 and (finishIdPAuthIdPApp1 or not fuzzIdPAuthIdPApp1)

def EveIdP_Auth1():
	#Eve_state = 'login'
	pass

def EveIdP_Auth1Enabled():
	return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and not Eve_state and not finishEveIdP_Auth1 and (finishIdPAuthIdPApp1 or not fuzzIdPAuthIdPApp1) and (finishIdPShowRPAppInfo1 or not fuzzIdPShowRPAppInfo1) and doubleRequests

'''
def RPAppHandshakeRPServ1():
	pass

def RPAppHandshakeRPServ1Enabled():
	return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzRPAppHandshakeRPServ1 and not finishRPAppHandshakeRPServ1
'''

def ShowUserInfo1():
	pass

def ShowUserInfo1Enabled():
	return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzShowUserInfo1 and not finishShowUserInfo1

def ShowMoreUserInfo1():
	pass

def ShowMoreUserInfo1Enabled():
	return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzShowMoreUserInfo1 and not finishShowMoreUserInfo1

def ShowExtraUserInfo1():
	pass

def ShowExtraUserInfo1Enabled():
	return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzShowExtraUserInfo1 and not finishShowExtraUserInfo1

def GetUid1():
	pass

def GetUid1Enabled():
	return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and fuzzGetUid1 and not finishGetUid1

def EveLoggedoutApp1():
	pass

def EveLoggedoutApp1Enabled():
	return traceOneFinished and not traceTwoFinished and initialized and IdP_App_Installed and Eve_Auth_RP and Eve_state and (finishShowUserInfo1 or not fuzzShowUserInfo1) and (finishShowMoreUserInfo1 or not fuzzShowMoreUserInfo1) and (finishShowExtraUserInfo1 or not fuzzShowExtraUserInfo1) and (finishGetUid1 or not fuzzGetUid1)

def Game_Over():
	pass

def Game_OverEnabled(): 
	return traceOneFinished and traceTwoFinished

# # Metadata
state = ('initialized', 'Eve_state', 'IdP_App_Installed', 'IdP_Name', 'Eve_Auth_RP', 'doubleRequests', 'fuzzIdPAuthIdPApp', 'fuzzIdPShowRPAppInfo', 'fuzzEveIdP_Auth','fuzzIdPAuthIdPApp1', 'fuzzIdPShowRPAppInfo1', 'fuzzEveIdP_Auth1', 'fuzzRPAppHandshakeRPServ', 'fuzzGetUid', 'fuzzShowUserInfo', 'fuzzShowMoreUserInfo', 'fuzzShowExtraUserInfo', 'fuzzGetUid1', 'fuzzShowUserInfo1', 'fuzzShowMoreUserInfo1', 'fuzzShowExtraUserInfo1', 'fuzzGetAT', 'fuzzRefreshAT', 'finishIdPAuthIdPApp', 'finishIdPShowRPAppInfo', 'finishEveIdP_Auth','finishIdPAuthIdPApp1', 'finishIdPShowRPAppInfo1', 'finishEveIdP_Auth1', 'finishRPAppHandshakeRPServ', 'finishGetUid', 'finishShowUserInfo', 'finishShowMoreUserInfo', 'finishShowExtraUserInfo', 'finishGetUid1', 'finishShowUserInfo1', 'finishShowMoreUserInfo1', 'finishShowExtraUserInfo1', 'finishGetAT', 'finishRefreshAT', 'traceOneFinished', 'traceTwoFinished',)

actions = (Initialize, IdPAuthIdPApp, IdPShowRPAppInfo, EveIdP_Auth, IdPAuthIdPApp1, IdPShowRPAppInfo1, EveIdP_Auth1, RPAppHandshakeRPServ, EveLoggedoutApp, EveLoggedoutApp1, ShowUserInfo, ShowMoreUserInfo, ShowExtraUserInfo, GetUid, ShowUserInfo1, ShowMoreUserInfo1, ShowExtraUserInfo1, GetUid1, GetAT, RefreshAT, Game_Over)

domains = {Initialize:{},
					IdPAuthIdPApp:{},
					IdPShowRPAppInfo:{},
					EveIdP_Auth:{},
					IdPAuthIdPApp1:{},
					IdPShowRPAppInfo1:{},
					EveIdP_Auth1:{},					
					RPAppHandshakeRPServ:{},				
					EveLoggedoutApp:{},
					EveLoggedoutApp1:{},
					ShowUserInfo:{},
					ShowMoreUserInfo:{},
					ShowExtraUserInfo:{},
					GetUid:{},	
					ShowUserInfo1:{},
					ShowMoreUserInfo1:{},
					ShowExtraUserInfo1:{},
					GetUid1:{},
					GetAT:{},
					RefreshAT:{},						
					Game_Over:{},							
					 }					 

enablers={Initialize:(InitializeEnabled,),
					IdPAuthIdPApp:(IdPAuthIdPAppEnabled,),IdPShowRPAppInfo:(IdPShowRPAppInfoEnabled,),
					EveIdP_Auth:(EveIdP_AuthEnabled,),IdPAuthIdPApp1:(IdPAuthIdPApp1Enabled,),IdPShowRPAppInfo1:(IdPShowRPAppInfo1Enabled,),
					EveIdP_Auth1:(EveIdP_Auth1Enabled,),RPAppHandshakeRPServ:(RPAppHandshakeRPServEnabled,),
					EveLoggedoutApp:(EveLoggedoutAppEnabled,), EveLoggedoutApp1:(EveLoggedoutApp1Enabled,),
					Game_Over:(Game_OverEnabled,),ShowUserInfo:(ShowUserInfoEnabled,),ShowMoreUserInfo:(ShowMoreUserInfoEnabled,),ShowExtraUserInfo:(ShowExtraUserInfoEnabled,),GetUid:(GetUidEnabled,),ShowUserInfo1:(ShowUserInfo1Enabled,),ShowMoreUserInfo1:(ShowMoreUserInfo1Enabled,),ShowExtraUserInfo1:(ShowExtraUserInfo1Enabled,),GetUid1:(GetUid1Enabled,),GetAT:(GetATEnabled,),RefreshAT:(RefreshATEnabled,),}

def Reset():	
		print 'reset in SSO'
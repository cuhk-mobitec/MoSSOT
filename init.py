"""
script to initialise test environment
"""
import os
import re
import glob
import json
import time
import random
import string
import shutil
import logging

import argparse
import colorlog

from uiauto.manifest import Manifest
from logger import MyLogger
from util import setup_custom_logger, revoke_at, start_android_emulator, term_by_port, fetch_uiaction, launch_appium, launch_mitmdump
from UI_controller import UI_controller

import conf
import toolTesting
from tools import getUDKeys, permunateUrl, updateDomainName,\
        checkFBAuthorized, processJson, extractGoogleUser,\
        extractToy, prioritizeCombinationinRes, refineURL


running_logger = MyLogger('Init').get_logger()

def get_single_trace(proxy_port, tracefile, port, system_port, uiconfig, package_name, launcher_activity, emulator_name, snapshot_tag, idp_name, reset, user, with_access_token, version, revoke_access_token):
    """
    Try to get network trace for one time
    """
    success = False
    # remove network trace file
    running_logger.debug("Starting recording network trace ...")
    uiact = UI_controller(port, system_port=system_port, config_file=uiconfig, package_name=package_name, activity_name=launcher_activity, emulator_name=emulator_name, tag=snapshot_tag)

    # try to login rp
    term_by_port(proxy_port)
    running_logger.debug("Logining RP ...")
    mitmdump = launch_mitmdump(proxy_port, extra_cmd=['-s', 'proxy/har_dump.py {}'.format(tracefile)])
    uiact.rp_login(package_name, version, idp_name, reset=reset, user=user)
    mitmdump.terminate()
    running_logger.debug("Login RP finished!")

    # wait for trace file dumped by mitmdump
    for _ in range(10):
        if os.path.isfile(tracefile):
            rawTrace = json.load(open(tracefile, 'r'))['log']['entries']
            break
        time.sleep(1)
    else:
        running_logger.debug("Cannot get network trace file %s, retry...", tracefile)
        return False

    # analyse trace file
    key_url_number = toolTesting.checkTrace(rawTrace, idp_name)
    running_logger.info("checking trace key url number...")
    running_logger.debug("idp name: %s", idp_name)
    running_logger.debug("key url number: %s", key_url_number)
    running_logger.debug("with_access_token: %s", with_access_token)
    if idp_name == 'sina':
        if with_access_token and (key_url_number == 2 or key_url_number == 3):
            success = True
        elif (not with_access_token) and key_url_number == 3:
            success = True
        else:
            success = False
    elif idp_name == 'wechat':
        if key_url_number == 2:
            success = True
        else:
            success = False
    elif idp_name == 'fb':
        authorize = checkFBAuthorized(rawTrace)
        running_logger.info('fb authorized: %s', authorize)
        if key_url_number == 3:
            if with_access_token and authorize:
                success = True
            elif (not with_access_token) and (not authorize):
                success = True
            else:
                success = False
        else:
            success = False

    if (not success and not with_access_token) or (success and revoke_access_token):
        revoke_at(idp_name, toolTesting.extractATfromTrace(rawTrace, idp_name))

    # logout if not using snapshot
    if emulator_name is None or snapshot_tag is None:
        mitmdump = launch_mitmdump(proxy_port)
        UI_controller(port, system_port=system_port, config_file=uiconfig, package_name=package_name, activity_name=launcher_activity, emulator_name=emulator_name, tag=snapshot_tag).rp_logout(package_name, version, idp_name, user=user, reset=reset)
        mitmdump.terminate()

    if success and os.path.exists(tracefile):
        return True
    else:
        archive_name = ''.join(random.choice(string.lowercase) for i in range(5))+'.trace'
        running_logger.debug("Archive wrong trace with name: %s", archive_name)
        shutil.move(tracefile, archive_name)
        return False
    return False

def GetTrace(idp_name, package_name, version, launcher_activity, proxy_port, \
    change_account=True, with_access_token=True, revoke_access_token=True, reset=False, \
    uiconfig='uiaction.json', user='Eve1', port='4723', system_port=8200, tracefile='eveA.trace', \
    emulator_name=None, snapshot_tag=None):
    """
    Prepare network trace for further testing
    """
    running_logger.debug("Recording tracefile %s", tracefile)

    # init
    rawTrace = None
    idpPackageName = None
    idpActivityName = None
    if idp_name == 'sina':
        idpPackageName = 'com.sina.weibo'
        idpActivityName = 'com.sina.weibo.SplashActivity'
    elif idp_name == 'wechat':
        idpPackageName = 'com.tencent.mm'
        idpActivityName = 'com.tencent.mm.ui.LauncherUI'

    # change account for twice
    if change_account and (emulator_name is None or snapshot_tag is None):
        mitmdump = launch_mitmdump(proxy_port)
        uictrl = UI_controller(port, system_port=system_port, package_name=idpPackageName, activity_name=idpActivityName, emulator_name=emulator_name)
        running_logger.debug('Try to change account')
        for _ in range(3):
            try:
                if uictrl.idp_login(user, idp_name):
                    break
            except Exception as e:
                running_logger.warn(e)
                continue
        else:
            mitmdump.terminate()
            raise Exception("Unable to login idp")
        mitmdump.terminate()

    # try to get trace for 5 times
    for _ in range(5):
        try:
            if get_single_trace(proxy_port, tracefile, port, system_port, uiconfig, package_name, launcher_activity, emulator_name, snapshot_tag, idp_name, reset, user, with_access_token, version, revoke_access_token):
                break
        except AssertionError:
            running_logger.warn('Wait too long for status change')
            continue
        except Exception as e:
            running_logger.exception(e)
            continue
    else:
        raise Exception("Cannot get network trace file in package: {}, trace file: {}".format(package_name, tracefile))

    return rawTrace

def revise_parameter_pool(level=1, folder_location="./", idp_name='sina'):
    try:
        requParaPool = None
        respParaPool = None
        if idp_name == 'sina':
            running_logger.info("revising parameter pool, level: %s", level)
            if level == 0:
                for f in ['request_para', 'request_para+']:
                    file_path = os.path.join(folder_location, f)
                    with open(file_path) as fh:
                        request_para = json.load(fh)
                        for url in request_para:
                            for item in request_para[url]['post']:
                                if not ("uid" in item or "access_token" in item):
                                    request_para[url]['post'].remove(item)
                            for item in request_para[url]['get']:
                                if not ("uid" in item or "access_token" in item):
                                    request_para[url]['get'].remove(item)
                        json.dump(request_para, open(file_path, 'w'))

                for f in ['response_para', 'response_para+']:
                    file_path = os.path.join(folder_location, f)
                    with open(file_path) as fh:
                        response_para = json.load(fh)
                        for url in response_para['usersKey']:
                            for item in response_para['usersKey'][url]:
                                if not ("access_token" in item["path"] or "uid" in item["path"]):
                                    response_para['usersKey'][url].remove(item)
                        json.dump(response_para, open(file_path, 'w'))

            idp_related_urls = ['api.weibo.com/oauth2/sso_authorize', 'api.weibo.cn/2/account/login', 'api.weibo.com/2/account/get_uid.json', 'api.weibo.com/2/users/show.json']
            if level == 1:
                for f in ['request_para', 'request_para+']:
                    file_path = os.path.join(folder_location, f)
                    with open(file_path, "r") as fh:
                        request_para = json.load(fh)
                        deleted_urls = []
                        for url in request_para:
                            if [(idp_url in url) for idp_url in idp_related_urls].count(True) == 0:
                                deleted_urls.append(url)
                        for url in deleted_urls:
                            del request_para[url]
                        json.dump(request_para, open(file_path, 'w'))

                for f in ['response_para', 'response_para+']:
                    file_path = os.path.join(folder_location, f)
                    with open(file_path, "r") as fh:
                        response_para = json.load(fh)
                        deleted_urls = []
                        for url in response_para['usersKey']:
                            if [(idp_url in url) for idp_url in idp_related_urls].count(True) == 0:
                                deleted_urls.append(url)
                        for url in deleted_urls:
                            del response_para['usersKey'][url]
                        json.dump(response_para, open(file_path, 'w'))

            # combine two files into one
            respParaPool = json.load(open(os.path.join(folder_location, 'response_para'), 'r'))['usersKey']
            requParaPool = json.load(open(os.path.join(folder_location, 'request_para'), 'r'))
            respParaPool1 = json.load(open(os.path.join(folder_location, 'response_para+'), 'r'))['usersKey']
            requParaPool1 = json.load(open(os.path.join(folder_location, 'request_para+'), 'r'))
            if 'api.weibo.com/oauth2/sso_authorize+' in requParaPool1:
                requParaPool['api.weibo.com/oauth2/sso_authorize+++'] = requParaPool1['api.weibo.com/oauth2/sso_authorize+']
            else:
                requParaPool['api.weibo.com/oauth2/sso_authorize+++'] = {}
            if 'api.weibo.com/oauth2/sso_authorize+' in respParaPool1:
                respParaPool['api.weibo.com/oauth2/sso_authorize+++'] = respParaPool1['api.weibo.com/oauth2/sso_authorize+']
            else:
                respParaPool['api.weibo.com/oauth2/sso_authorize+++'] = []
            requParaPool['api.weibo.cn/2/account/login+'] = requParaPool1['api.weibo.cn/2/account/login']
            respParaPool['api.weibo.cn/2/account/login+'] = respParaPool1['api.weibo.cn/2/account/login']
            requParaPool['api.weibo.com/oauth2/sso_authorize++'] = requParaPool1['api.weibo.com/oauth2/sso_authorize']
            respParaPool['api.weibo.com/oauth2/sso_authorize++'] = respParaPool1['api.weibo.com/oauth2/sso_authorize']
            if 'api.weibo.com/2/users/show.json' in requParaPool or 'api.weibo.com/2/users/show.json' in respParaPool:
                try:
                    requParaPool['api.weibo.com/2/users/show.json+'] = requParaPool1['api.weibo.com/2/users/show.json']
                    respParaPool['api.weibo.com/2/users/show.json+'] = respParaPool1['api.weibo.com/2/users/show.json']
                except Exception:
                    requParaPool['api.weibo.com/2/users/show.json+'] = {}
                    respParaPool['api.weibo.com/2/users/show.json+'] = []
            if 'api.weibo.com/2/account/get_uid.json' in requParaPool or 'api.weibo.com/2/account/get_uid.json' in respParaPool:
                try:
                    requParaPool['api.weibo.com/2/account/get_uid.json+'] = requParaPool1['api.weibo.com/2/account/get_uid.json']
                    respParaPool['api.weibo.com/2/account/get_uid.json+'] = respParaPool1['api.weibo.com/2/account/get_uid.json']
                except Exception:
                    requParaPool['api.weibo.com/2/account/get_uid.json+'] = {}
                    respParaPool['api.weibo.com/2/account/get_uid.json+'] = []
        elif idp_name == 'wechat':
            # todo: currently wechat does not define different level
            requParaPool = json.load(open(os.path.join(folder_location, 'request_para'), 'r'))
            respParaPool = json.load(open(os.path.join(folder_location, 'response_para'), 'r'))['usersKey']
        elif idp_name == 'fb':

            respParaPool = json.load(open(os.path.join(folder_location, 'response_para'), 'r'))['usersKey']
            requParaPool = json.load(open(os.path.join(folder_location, 'request_para'), 'r'))
            respParaPool1 = json.load(open(os.path.join(folder_location, 'response_para+'), 'r'))['usersKey']
            requParaPool1 = json.load(open(os.path.join(folder_location, 'request_para+'), 'r'))
            for item in requParaPool1.keys():
                if 'm.facebook.com/login/async' in item:
                    requParaPool[item + '+'] = requParaPool1[item]
                elif re.search('m.facebook.com/v(.*)/dialog/oauth', item) and not re.search('m.facebook.com/v(.*)/dialog/oauth/confirm', item):
                    requParaPool[item + '+'] = requParaPool1[item]
                elif re.search('m.facebook.com/v(.*)/dialog/oauth/confirm', item):
                    requParaPool[item] = requParaPool1[item]
                elif re.search('graph.facebook.com/v(.*)/me', item):
                    if '{' not in item:
                        requParaPool[item + '+++'] = requParaPool1[item]
                    else:
                        requParaPool[item.split('{')[0] + '+++{' + item.split('{')[1]] = requParaPool1[item]

            for item in respParaPool1.keys():
                if 'm.facebook.com/login/async' in item:
                    respParaPool[item + '+'] = respParaPool1[item]
                elif re.search('m.facebook.com/v(.*)/dialog/oauth', item) and not re.search('m.facebook.com/v(.*)/dialog/oauth/confirm', item):
                    respParaPool[item + '+'] = respParaPool1[item]
                elif re.search('m.facebook.com/v(.*)/dialog/oauth/confirm', item):
                    respParaPool[item] = respParaPool1[item]
                elif re.search('graph.facebook.com/v(.*)/me', item):
                    if '{' not in item:
                        respParaPool[item + '+++'] = respParaPool1[item]
                    else:
                        respParaPool[item.split('{')[0] + '+++{' + item.split('{')[1]] = respParaPool1[item]

            # alignment
            for item in requParaPool.keys():
                if re.search('graph.facebook.com/v(.*)/me', item):
                    if item not in respParaPool.keys():
                        respParaPool[item] = {}

            for item in respParaPool.keys():
                if re.search('graph.facebook.com/v(.*)/me', item):
                    if item not in requParaPool.keys():
                        requParaPool[item] = {}

        # remove "rm" operation from the identifier url in the parameter pool due to
        userIdentifierUrl = ''
        if os.path.exists(os.path.join(folder_location, 'user_para')):
            with open(os.path.join(folder_location, 'user_para'), 'r') as fh:
                user_para = json.load(fh)
                for key in user_para['userIdentifier'].keys():
                    if key != 'Alice' and key != 'Eve':
                        userIdentifierUrl = key
                        break
            for key in requParaPool:
                if refineURL(userIdentifierUrl)[2] in key and refineURL(userIdentifierUrl)[0] in key:
                    for item in requParaPool[key]['post']:
                        for item2 in item:
                            if item2 != 'replacedValue' and 'rm' in item[item2]:
                                item[item2].remove('rm')
                    for item in requParaPool[key]['get']:
                        for item2 in item:
                            if item2 != 'replacedValue' and 'rm' in item[item2]:
                                item[item2].remove('rm')

        json.dump(requParaPool, open(os.path.join(folder_location, 'request_para'), 'w'))
        json.dump(respParaPool, open(os.path.join(folder_location, 'response_para'), 'w'))

        processJson(os.path.join(folder_location, 'request_para'), 'request', dimension=2, opt='onlyRep', switchCH=False)
        processJson(os.path.join(folder_location, 'response_para'), 'response', dimension=2, opt='onlyRep', switchCH=False)

        # comment out toy app testing
        if os.path.exists('extra.trace'):
            extractToy(os.path.join(folder_location, 'request_para'), os.path.join(folder_location, 'response_para'), 'extra.trace', idp_name)

        prioritizeCombinationinRes(os.path.join(folder_location, 'response_para'))
    except Exception:
        running_logger.exception("exception in revise parameter pool")

def network_trace_record(args, package_name, launcher_activity, version):
    running_logger.debug("start network_trace_record, package: %s, launcher_activity: %s, version: %s", package_name, launcher_activity, version)

    if args.idp_name == 'sina':
        # alice trace
        GetTrace('sina', package_name, version, launcher_activity, args.proxy_port, True, False, False, reset=args.reset, user='Alice', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='aliceA.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # alice trace withat
        GetTrace('sina', package_name, version, launcher_activity, args.proxy_port, False, True, False, reset=args.reset, user='Alice', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='aliceA+.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # extra trace
        GetTrace('sina', "com.gift.android", None, "com.lvmama.account.login.LoginActivity", args.proxy_port, False, False, False, reset=args.reset, uiconfig=None, user='Alice', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='extra.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # eve trace 1
        GetTrace('sina', package_name, version, launcher_activity, args.proxy_port, True, False, False, reset=args.reset, user='Eve', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='eveA.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # eve trace withat
        GetTrace('sina', package_name, version, launcher_activity, args.proxy_port, False, True, True, reset=args.reset, user='Eve', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='eveA+.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # eve trace 2
        GetTrace('sina', package_name, version, launcher_activity, args.proxy_port, False, False, True, reset=args.reset, user='Eve', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='eveA2.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)

    elif args.idp_name == 'wechat':
        # alice trace
        GetTrace('wechat', package_name, version, launcher_activity, args.proxy_port, True, False, False, reset=args.reset, user='Alice', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='aliceA.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # extra trace
        GetTrace('wechat', "com.gift.android", None, "com.lvmama.account.login.LoginActivity", args.proxy_port, False, False, False, reset=args.reset, uiconfig=None, user='Alice', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='extra.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # eve trace 1
        GetTrace('wechat', package_name, version, launcher_activity, args.proxy_port, True, False, False, reset=args.reset, user='Eve', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='eveA.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # eve trace 2
        GetTrace('wechat', package_name, version, launcher_activity, args.proxy_port, False, False, False, reset=args.reset, user='Eve', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='eveA2.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)

    elif args.idp_name == 'fb':
        # alice trace
        GetTrace('fb', package_name, version, launcher_activity, args.proxy_port, False, False, False, reset=args.reset, user='Alice', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='aliceA.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # alice trace withat
        GetTrace('fb', package_name, version, launcher_activity, args.proxy_port, False, True, False, reset=args.reset, user='Alice', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='aliceA+.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # extra trace
        GetTrace('fb', "com.booking", None, ".login.LoginActivity", args.proxy_port, False, False, False, reset=args.reset, uiconfig=None, user='Alice', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='extra.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # eve trace 1
        GetTrace('fb', package_name, version, launcher_activity, args.proxy_port, False, False, False, reset=args.reset, user='Eve', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='eveA.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # eve trace 1 withat
        GetTrace('fb', package_name, version, launcher_activity, args.proxy_port, False, True, True, reset=args.reset, user='Eve', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='eveA+.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)
        # eve trace 2
        GetTrace('fb', package_name, version, launcher_activity, args.proxy_port, False, False, False, reset=args.reset, user='Eve', port=str(args.appium_port), system_port=args.appium_system_port, tracefile='eveA2.trace', emulator_name=args.device_name, snapshot_tag=args.snapshot_tag)

def parameter_extraction(domainNames, folder_location="../networkTraceResult/", idp_name='sina'):
    """extract fuzzing url parameters"""
    running_logger.info("extract parameter from network trace files")
    g_conf = conf.g_config
    # g_appinfo = json.load(open('appinfo.json', 'r'))
    #Init key response param set
    running_logger.info("Response key parameters extraction from network trace files, writing to response_para...")
    filter_subsequent = True
    for domainName in domainNames:
        updateDomainName(domainName)
        g_appinfo = json.load(open('appinfo.json', 'r'))
        if getUDKeys('eveA.trace', 'eveA.trace', 'aliceA.trace', 'eveA2.trace', appendix='', folder_location=folder_location, idp_name=idp_name):
            break
    else:
        filter_subsequent = False

    g_appinfo = json.load(open('appinfo.json', 'r'))
    if idp_name == 'sina' or idp_name == 'fb':
        running_logger.info("Response key parameters extraction from network trace files, writing to response_para+...")
        getUDKeys('eveA+.trace', 'eveA+.trace', 'aliceA+.trace', 'eveA+.trace', appendix='+', folder_location=folder_location, idp_name=idp_name)

    permunateUrl(g_appinfo, folder_location, idp_name, filter_subsequent)

    revise_parameter_pool(g_conf['policy']['level'], folder_location=folder_location, idp_name=idp_name)
    return folder_location

def main(args):
    """
    initialisation main logic
    """

    info = setup_env(args)

    # init
    finished = False
    Appium = None
    idp = args.idp_name
    snapshot_tag = args.snapshot_tag
    version = info['version']
    package_name = info['package_name']
    launcher_activity = info['launcher_activity']
    para_folder = info['para_folder']
    config = info['config']

    running_logger.info("Testing with apk: %s", args.apk_file)

    if args.config:
        running_logger.info('Try to load customized path config')
        # make sure config file exists
        if not os.path.exists(args.config):
            running_logger.exception('Cannot find the path config file')
            return False, para_folder
        shutil.copyfile(args.config, 'uiaction.json')
    else:
        # get the uiaction.json file from database
        running_logger.debug("fetching ui config from oauth server")
        try:
            fetch_uiaction(package_name, version, snapshot_tag, idp)
        except Exception:
            running_logger.exception('Cannot fetch ui config from database')
            return False, para_folder

    # set up environment for initialisation
    running_logger.debug("starting emulator device %s", args.device_name)
    emulator = start_android_emulator(args.apk_file, args)

    # launch appium if noappium is not specified
    if not args.noappium:
        Appium = launch_appium(args, emulator)
        if not Appium:
            return False, para_folder

    running_logger.info("Set up environment finished!")
    running_logger.info("appium port: %d", args.appium_port)
    running_logger.info("appium back port: %d", args.appium_back_port)
    running_logger.info("device name: %s", args.device_name)
    running_logger.info("emulator port: %d", emulator.port)

    try:
        running_logger.info("Start initialisation process!")

        # make sure network traces are well recorded
        network_trace_record(args, package_name, launcher_activity, version)
        expected_files = None
        if args.idp_name == 'sina':
            expected_files = ["aliceA.trace", "eveA2.trace", "aliceA+.trace", "eveA.trace", "eveA+.trace", "extra.trace"]
        elif args.idp_name == 'wechat':
            expected_files = ["aliceA.trace", "eveA2.trace", "eveA.trace", "extra.trace"]
        elif args.idp_name == 'fb':
            expected_files = ["aliceA.trace", "eveA2.trace", "aliceA+.trace", "eveA.trace", "eveA+.trace", "extra.trace"]
        if not all([os.path.isfile(f) for f in expected_files]):
            raise Exception("Cannot finish network trace recording of app {}".format(args.apk_file))

        # get a list of candidate rp domain
        domainNames = toolTesting.getDomain('aliceA.trace', 'eveA.trace', 'eveA2.trace', 'eveA.trace', package_name, args.idp_name)
        expected_files = None
        if args.idp_name == 'sina' or args.idp_name == 'fb':
            expected_files = ["request_para", "response_para", "request_para+", "response_para+"]
        elif args.idp_name == 'wechat':
            expected_files = ["request_para", "response_para"]
        parameter_extraction(domainNames, para_folder, args.idp_name)
        if not all([os.path.isfile(os.path.join(para_folder, f)) for f in expected_files]):
            raise Exception("cannot finish parameter extraction {}".format(args.apk_file))

        # copy files into folder
        config = json.load(open('./config.json', 'r'))
        if os.path.exists(os.path.join(para_folder, 'user_para')):
            config['ui_support'] = 'False'
        elif args.idp_name == 'fb':
            config['ui_support'] = 'False' if extractGoogleUser('eveA.trace', 'aliceA.trace', para_folder) else 'True'
        else:
            config['ui_support'] = 'True'
        uiconfig = json.load(open('uiaction.json', 'r'))
        if ('user_info' not in uiconfig['paths'] or not uiconfig['paths']['user_info']) and config['ui_support'] == 'True':
            finished = None
            running_logger.debug("no ui action for user info for %s", args.apk_file)
        else:
            finished = True
            running_logger.info("finish initialisation phase of app %s", args.apk_file)

    except Exception:
        running_logger.exception("Exception in initialisation of %s", args.apk_file)
    except KeyboardInterrupt as e:
        running_logger.exception(e)
    finally:
        # copy files to folder
        json.dump(config, open(os.path.join(para_folder, 'config.json'), 'w+'))
        shutil.copyfile(args.apk_file, os.path.join(".", para_folder, "test.apk"))
        for filename in glob.glob("./*trace"):
            shutil.move(filename, os.path.join(".", para_folder, filename))
        shutil.copyfile("./appinfo.json", os.path.join(".", para_folder, "appinfo.json"))

        # clean up the enviornment
        if Appium:
            Appium.terminate()
        if args.snapshot_tag != None:
            running_logger.debug("loading snapshot %s for emulator device %s with gpu host", args.snapshot_tag, args.device_name)
            emulator.load_snapshot(args.snapshot_tag)
        elif args.gpu == 'host':
            running_logger.debug("loading snapshot init-gpu for emulator device %s with gpu host", args.device_name)
            emulator.load_snapshot('init-gpu')
        else:
            running_logger.debug("loading snapshot init-off for emulator device %s with gpu off", args.device_name)
            emulator.load_snapshot('init-off')
        cleanup_leftover(args)
        running_logger.info("initialisation finished: %s, para_folder: %s", finished, para_folder)
    return finished, para_folder

def setup_env(args):
    """
    setting up environment before initialisation
    """

    running_logger.info('Setting up environment before init')

    # cleanup working environment
    cleanup_leftover(args)

    # extract package information from apk file
    manifest = Manifest(args.apk_file)
    package_name = manifest.get_package_name()
    launcher_activity = manifest.get_launcher_activity()
    version = manifest.get_version_name()

    # initialise working dirs
    para_folder = os.path.join(args.result_folder, package_name+'_'+version+'_'+args.idp_name)
    if not os.path.exists(args.result_folder):
        os.mkdir(args.result_folder, 0755)
    if not os.path.exists(para_folder):
        os.mkdir(para_folder, 0755)

    # write config into the config.json// such a bad implementation
    config = json.load(open('./config.json', 'r'))
    config['idp'] = args.idp_name
    config['snapshot'] = True if args.snapshot_tag else False
    json.dump(config, open('./config.json', 'w'))

    # dump activity and package into appinfo.json// bad implementation again..
    g_appinfo = {}
    g_appinfo['activity'] = launcher_activity
    g_appinfo['view'] = package_name
    g_appinfo['version'] = version
    json.dump(g_appinfo, open('appinfo.json', 'w'))

    # set up logger handlers to init.log
    logging.root.handlers = []
    formatter = colorlog.ColoredFormatter(
        '[%(name)s][%(levelname)s]%(asctime)s %(log_color)s%(message)s',
        datefmt='%m-%d %H:%M')
    handler = logging.FileHandler(os.path.join(para_folder, "init.log"), mode='w')
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)

    # create result_logger
    setup_custom_logger('result', path=os.path.join(para_folder, "result.log"))

    info = {
        'package_name': package_name,
        'version': version,
        'para_folder': para_folder,
        'launcher_activity': launcher_activity,
        'config': config
    }
    return info

#TODO: mess cleanup should not be inside init.py
def cleanup_leftover(args):
    """
    clean up left over files, proxies from last init
    very very bad implementation
    """
    running_logger.info('Clean up leftover files and proxies')

    # clean up files
    for f in os.listdir('./'):
        if re.search(r'para|.*trace', f):
            os.remove(os.path.join('./', f))

    # clean up proxies
    if not args.noappium:
        term_by_port(args.appium_port)
        term_by_port(args.appium_back_port)
        term_by_port(args.appium_system_port)
    term_by_port(args.proxy_port)

    logging.root.handlers = []

if __name__ == '__main__':

    # parse arguments
    parser = argparse.ArgumentParser(description='Initialisation for model testing.')
    parser.add_argument('-f', action='store', dest='apk_file', type=str,
                        help='testing apk folder', required=True)
    parser.add_argument('-a', action='store', dest='appium_port', type=int,
                        help='appium server port', default=4723)
    parser.add_argument('-sp', action='store', dest='appium_system_port', type=int,
                        help='appium system port', default=8200)
    parser.add_argument('-bp', action='store', dest='appium_back_port', type=int,
                        help='appium back port', default=2530)
    parser.add_argument('-p', action='store', dest='proxy_port', type=int,
                        help='mitmdump proxy port', default=8080)
    parser.add_argument('--gpu', action='store', dest='gpu', type=str,
                        choices=['off', 'host', 'shaderswift_indirect'],
                        help='gpu acceleration options', default='host')
    parser.add_argument('--no-window', action='store_true', dest='no-window',
                        help='whether there is window for android emulator')
    parser.add_argument('--qemu', action='store', dest='qemu', help='extra qemu arguments')
    parser.add_argument('-r', action='store', dest='result_folder', type=str,
                        help='customised result path', default="../networkTraceResult/")
    parser.add_argument('-i', action='store', dest='idp_name', type=str,
                        help='target IdP', choices=['fb', 'sina', 'wechat'], required=True)
    parser.add_argument('--conf', action='store', dest='config', type=str,
                        help='path config file')
    parser.add_argument('-d', action='store', dest='device_name', type=str,
                        help='dedicated machine name', default=None, required=True)
    parser.add_argument('--tag', action='store', dest='snapshot_tag', type=str,
                        help='snapshot tag used to login rp', default=None)
    parser.add_argument('--reset', action='store_true', dest='reset',
                        help='use reset function if this flag is set')
    parser.add_argument('--noappium', action='store_true', dest='noappium',
                        help='do not start appium and new device in this program,\
                            environment has been set up by default')
    args = parser.parse_args()

    # check working dir// because brother wolf hardcoded something
    if os.path.basename(os.getcwd()) != 'tool_testing':
        running_logger.error('Working dir must be tool_testing')
        running_logger.error('exit!')
        exit(-1)

    # make sure apk exists
    if not os.path.isfile(args.apk_file):
        running_logger.error("Cannot find the apk file")
        running_logger.error("exit!")
        exit(-1)

    # logging
    running_logger.info('Initialisation starts')
    running_logger.info('apk:\t\t\t%s', args.apk_file)
    running_logger.info('appium port:\t\t%s', args.appium_port)
    running_logger.info('appium back port:\t%s', args.appium_back_port)
    running_logger.info('proxy port:\t\t%s', args.proxy_port)
    running_logger.info('system port:\t\t%s', args.appium_system_port)

    # start main func
    main(args)

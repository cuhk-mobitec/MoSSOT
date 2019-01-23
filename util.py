#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
Utitities
"""
import os
import signal
import json
import re
import time
import logging
import subprocess

import psutil
import requests
import mechanize

from logger import MyLogger
from uiauto.db import DB
from uiauto.emulator import AndroidEmulator
from uiauto.manifest import Manifest

running_logger = MyLogger('Util').get_logger()

def setup_custom_logger(name, level='DEBUG', path='running.log'):
    """
    set up file handler for logger
    """
    handler = logging.FileHandler(path)
    formatter = logging.Formatter(
        '[%(levelname)s]: %(asctime)s - %(name)s -- %(message)s',
        datefmt='%m-%d %H:%M')
    handler.setFormatter(formatter)
    handler.setLevel(level)
    logger = logging.getLogger(name)
    logger.handlers = []
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return logger

def revoke_at(idp, access_token):
    """
    function to revoke a access_token
    """
    running_logger.debug('access_token: %s', access_token)
    if access_token is None or access_token == '':
        running_logger.warn('access token is empty, could not revoke access token')
        return False
    if idp == 'sina':
        try:
            resp = requests.get('https://api.weibo.com/oauth2/revokeoauth2?access_token='+access_token, timeout=1200)
            if 'error' in resp.text:
                running_logger.warn('Fail to revoke access token, response text: %s', resp.text)
            else:
                running_logger.debug('Access token revoked')
        except Exception:
            running_logger.exception('Fail to revoke access token')
    elif idp == 'wechat':
        running_logger.debug('skip revoking access token, not applicable to wechat!')
    elif idp == 'fb':
        try:
            resp = requests.get('https://graph.facebook.com/me/permissions?method=delete&access_token='+access_token, timeout=1200)
            if '"success":true' not in resp.text:
                running_logger.error('Fail to revoke access token, response text: %s', resp.text)
            else:
                running_logger.debug('Access token revoked')
        except Exception:
            running_logger.exception('Fail to revoke access token')
    else:
        running_logger.debug('skip, unknown idp')
    return True

def start_android_emulator(apk_file, args):
    """
    prepare snapshot and safely start android emulator
    """
    emulator = None
    manifest = Manifest(apk_file)
    package_name = manifest.get_package_name()
    package_version = manifest.get_version_name()
    try:
        args.http_proxy = 'http://127.0.0.1:{}'.format(args.proxy_port)
        if not args.device_name in AndroidEmulator._get_names_in_use():
            running_logger.debug('cloning device %s', args.device_name)
            AndroidEmulator.clone('TEMPLATE', args.device_name)

        emulator = AndroidEmulator(device_name=args.device_name, options=args)
        emulator.restart()
        snapshot_list = emulator.list_snapshot()

        if args.gpu == 'host' and not any([x['tag'] == 'init-gpu' for x in snapshot_list]):
            running_logger.debug("saving snapshot for emulator device %s with gpu host", args.device_name)
            emulator.save_snapshot('init-gpu')

        if args.gpu == 'off' and not any([x['tag'] == 'init-off' for x in snapshot_list]):
            running_logger.debug("saving snapshot for emulator device %s with gpu off", args.device_name)
            emulator.save_snapshot('init-off')

        if emulator.status != 'On':
            running_logger.warn("start emulator fail! exit!")
            exit()

        if args.snapshot_tag is None:
            if args.gpu == 'host':
                running_logger.debug("loading snapshot for emulator device %s with gpu host", args.device_name)
                emulator.load_snapshot('init-gpu')
            else:
                running_logger.debug("loading snapshot for emulator device %s with gpu off", args.device_name)
                emulator.load_snapshot('init-off')
        else:
            running_logger.debug("loading snapshot for emulator device %s with tag %s", args.device_name, args.snapshot_tag)
            emulator.load_snapshot(args.snapshot_tag)

        # version check
        installed_version = emulator.current_version(package_name)
        if installed_version != package_version:
            running_logger.warning('Different version - Installed: %s, Provided: %s. Installing package...', installed_version, package_version)
            emulator.install_package(apk_file)
    except Exception:
        running_logger.exception("Exception in starting android emulator")
        raise Exception('Exception in starting android emulator')
    return emulator

def teardownFBSessions():
    """
    Log out all facebook sessions
    """
    data = json.load(open('config.json', 'r'))
    try:
        username, password = None, None
        if data["user"] == 'Eve':
            username = data["config"]["user"]["eve"]["facebook"]["name"]
            password = data["config"]["user"]["eve"]["facebook"]["password"]
        elif data["user"] == 'Alice':
            username = data["config"]["user"]["alice"]["facebook"]["name"]
            password = data["config"]["user"]["alice"]["facebook"]["password"]
        else:
            raise Exception("The user specified is not implemented yet.")
        if not username or not password:
            raise Exception("Either username or password is not set")

        browser = mechanize.Browser()
        browser.set_handle_robots(False)
        cookies = mechanize.CookieJar()
        browser.set_cookiejar(cookies)
        browser.addheaders = [('User-agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.517.41 Safari/534.7')]
        browser.set_handle_refresh(False)

        url = 'https://www.facebook.com/login.php'
        browser.open(url)
        browser.select_form(nr=0)       #This is login-password form -> nr = number = 0
        browser.form['email'] = username
        browser.form['pass'] = password
        response = browser.submit()

        # get fb_dtsg
        for cookie in cookies:
            if cookie.name == 'c_user':
                user = cookie.value
            break
        url = 'https://www.facebook.com/settings/security/password/?recommended=false&dpr=2&__user={}&__a=1'.format(user)
        response = browser.open(url)
        body = response.read().decode('string_escape')
        fb_dtsg = re.search('fb_dtsg\" value=\"([a-zA-Z:_0-9]*)', body).group(1)

        # logout all sessions
        url = 'https://www.facebook.com/security/settings/sessions/log_out_all/?dpr='
        requests.post(url, cookies=cookies, data={'__user':user, 'fb_dtsg':fb_dtsg})
    except Exception:
        running_logger.exception('Exception in teardownFBSessions()')

def term_by_port(port):
    """
    terminate a process taken up a port
    """
    user = os.environ['USER']
    for proc in psutil.process_iter():
        procinfo = proc.as_dict(attrs=['name', 'username', 'cmdline'])
        if procinfo['username'] != user or not procinfo['cmdline']:
            continue

        # try to close the process if port matches
        try:
            for conns in proc.connections(kind='inet'):
                if conns.laddr.port != port:
                    continue
                running_logger.warn('Try to terminate %s with port %d open', procinfo['name'], port)
                proc.send_signal(signal.SIGTERM)
                count = 0
                while proc.is_running() and proc.status() != 'zombie':
                    if count >= 10:
                        running_logger.warn('fail to terminate %s', procinfo['name'])
                        running_logger.warn('Kill %s', procinfo['name'])
                        proc.send_signal(signal.SIGKILL)
                    time.sleep(1)
                    count += 1
                return True
        except psutil.AccessDenied:
            continue
        except psutil.NoSuchProcess:
            continue

def fetch_uiaction(package_name, version, snapshot_tag, idp):
    """
    fetch uiaction path config file from server
    uiaction.json is used for navigating to click idp confirm button after loading snapshot
    """
    ui_config = DB().fetch_config(package_name, version=version, idp=idp,
                                  snapshot=(snapshot_tag != None and idp != 'fb'))
    filtered_config = {key: ui_config[key] for key in ui_config if key in \
                       ['paths', 'package', 'idp', 'version', 'home_activity', 'status']}
    json.dump(filtered_config, open('uiaction.json', 'w'))

def launch_appium(args, emulator):
    """
    function to launch appium
    """
    # prepare cmd
    cmd = ['appium', '--no-reset', '-p', str(args.appium_port), '-U', emulator.serial,
           '--session-override', '--log-level', 'info', '-bp', str(args.appium_back_port)]
    Appium = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # wait for listener binding result
    line = Appium.stdout.readline()
    while 'listener' not in line:
        line = Appium.stdout.readline()
    if 'Could not start' in line:
        running_logger.error('Could not start appium')
        running_logger.error(' '.join(cmd))
        return None
    return Appium

def launch_mitmdump(port, extra_cmd=None):
    """
    function to launch mitmdump
    """
    # prepare cmd
    cmd = ['mitmdump', '--host', '--raw-tcp', '-p', str(port)]
    if extra_cmd:
        cmd += extra_cmd
    mitmdump = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # wait for listener binding result
    line = mitmdump.stdout.readline()
    while mitmdump.poll() is None and 'server' not in line:
        line = mitmdump.stdout.readline()
    if mitmdump.poll() is not None:
        running_logger.error('Could not start mitmdump')
        running_logger.error(line)
        running_logger.error(mitmdump.communicate()[0])
        return None
    if 'Error starting proxy' in line:
        running_logger.error('Could not start mitmdump')
        running_logger.error(line)
        return None
    running_logger.debug('mitmdump starts on port %d', port)
    return mitmdump

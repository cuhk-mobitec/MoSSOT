#!/usr/bin/python
# -*- coding: utf-8 -*-

# this script is used to control ui action, and it also include automatic recovery mechanism
# by default it assumes the idp is sina, later it should support more idps
import re
import logging
from time import sleep
import requests
import mechanize

from appium import webdriver

from uiauto.uiaction import UIAction
from uiauto.smartmonkey import SmartMonkey
from uiauto.emulator import AndroidEmulator
from uiauto.myexceptions import EmulatorActionException
from conf import g_config
from tools import getUiautomatorConfig
from logger import MyLogger

running_logger = MyLogger('UIController').get_logger()
result_logger = logging.getLogger('result')

class UI_controller(object):
    def __init__(self, portNum, system_port=8200, config_file='uiaction.json', package_name='com.sina.weibo', activity_name='com.sina.weibo.SplashActivity', emulator_name=None, tag=None):

        # very very bad practice of parameter passing
        # so here I have to create emulator instance first to get emulator serial number
        self.emulator = AndroidEmulator(emulator_name) if emulator_name else None
        self.tag = tag

        desired_caps = {}
        desired_caps['platformName'] = 'Android'
        desired_caps['platformVersion'] = '6.0'
        desired_caps['deviceName'] = 'emulator'
        desired_caps['appPackage'] = package_name
        desired_caps['appActivity'] = activity_name
        desired_caps['disableWindowAnimation'] = True
        desired_caps['autoGrantPermissions'] = True
        desired_caps['systemPort'] = system_port
        desired_caps['noReset'] = True
        desired_caps['udid'] = self.emulator.serial

        if tag:
            desired_caps['autoLaunch'] = False
        if getUiautomatorConfig():
            desired_caps['automationName'] = 'UiAutomator2'
        appium_port = 'http://localhost:' + str(portNum) + '/wd/hub'
        self.config_file = config_file
        # load snapshot file when init UI controller
        try:
            if self.emulator != None and tag != None:
                tags_in_use = [x['tag'] for x in self.emulator.list_snapshot()]
                if tag not in tags_in_use:
                    raise EmulatorActionException('No snapshot with tag {}'.format(tag))
                if not self.emulator.load_snapshot(tag):
                    raise EmulatorActionException('Fail to load snapshot {}'.format(tag))
            self.driver = webdriver.Remote(appium_port, desired_caps)
        except:
            running_logger.exception('Driver init error')
            raise Exception('Driver init error')

    def check_rp_status(self, package, version):
        return UIAction(self.driver, config_file=self.config_file, package=package, version=version).user_info()

    # check idp status by checking keywork element in the first page in idp app
    def check_idp_status(self, idp='sina'):
        running_logger.debug('Check idp status')
        sm = SmartMonkey(self.driver)
        if idp == 'sina':
            try:
                self.driver.start_activity('com.sina.weibo', '.account.AccountManagerActivity', app_wait_activity=".account.AccountManagerActivity, .account.SwitchUser")
                if self.driver.current_activity == '.account.AccountManagerActivity':
                    return True
                elif self.driver.current_activity == '.account.SwitchUser':
                    return False
            except:
                raise Exception("Unknown activity when checking idp status: {}".format(self.driver.current_activity))
        elif idp == 'wechat':
            try:
                self.driver.start_activity('com.tencent.mm', '.ui.LauncherUI',
                                           app_wait_activity='.ui.LauncherUI, .ui.account.LoginPasswordUI')
                keyword = sm.wait_for_keyword2(u'通讯录|联系人|找回密码', timeout=60)
                if keyword:
                    if keyword == u'通讯录' or keyword == u'联系人':
                        return True
                    elif keyword == u'找回密码':
                        return False
                    else:
                        return False
                else:
                    return False
            except:
                raise Exception("Unknown activity when checking idp status: {}".format(self.driver.current_activity))
        else:
            raise Exception('IdP {} not supported'.format(idp))

    def idp_login(self, user, idp='sina'):
        """idp login function"""

        def typeinfo(un_box, pwd_box, username, pwd):
            """method to simply"""
            un_box.clear()
            un_box.send_keys(username)
            pwd_box.clear()
            pwd_box.send_keys(pwd)

        if self.check_idp_status(idp=idp):
            running_logger.debug("idp has already login, try to logout")
            self.idp_logout(idp=idp)

        running_logger.debug('Perform idp login')
        sm = SmartMonkey(self.driver)
        if idp == 'sina':
            try:
                self.driver.start_activity('com.sina.weibo', '.account.SwitchUser')
            except Exception:
                running_logger.debug("Enter activity %s", self.driver.current_activity)
            username_box = sm.find_elements_by_keyword("etLoginUsername")[0]
            password_box = sm.find_elements_by_keyword("etPwd")[0]
            if user == 'Alice':
                account_info = g_config['config']['user']['alice']['weibo']
                typeinfo(username_box, password_box, account_info['name'], account_info['password'])
            elif user == 'Eve':
                account_info = g_config['config']['user']['eve']['weibo']
                typeinfo(username_box, password_box, account_info['name'], account_info['password'])
            elif user == 'Eve1':
                account_info = g_config['config']['user']['eve1']['weibo']
                typeinfo(username_box, password_box, account_info['name'], account_info['password'])
            else:
                raise Exception("unimplemented username, exit!")
            sm.tap_keyword(u'登录')
            sm.wait_for_keyword(u'微博', timeout=60)
        elif idp == 'wechat':
            account_info = g_config['config']['user'][user.lower()]['wechat']

            # launch login activity
            try:
                self.driver.start_activity('com.tencent.mm', '.ui.account.LoginUI')
            except Exception:
                running_logger.debug("Enter activity %s", self.driver.current_activity)
                return self.check_idp_status(idp='wechat')

            # wait for username/password input box to appear
            sm.wait_for_destination(u'密码')
            count = 0
            while not self.driver.find_elements_by_class_name('android.widget.EditText'):
                assert count <= 10
                count += 1
                sleep(1)
            username_box = self.driver.find_elements_by_class_name('android.widget.EditText')[0]
            password_box = self.driver.find_elements_by_class_name('android.widget.EditText')[1]

            # input username/password and perform login
            typeinfo(username_box, password_box, account_info['name'], account_info['password'])
            sm.tap_keyword(u'登录')
            sm.wait_for_keyword(u'通讯录|联系人', timeout=60)
        else:
            raise Exception('IdP {} not supported'.format(idp))

        return self.check_idp_status(idp)

    def idp_logout(self, idp='sina'):
        sm = SmartMonkey(self.driver)
        if idp == 'sina':
            try:
                self.driver.start_activity('com.sina.weibo', '.account.AccountManagerActivity', app_wait_activity=".account.AccountManagerActivity, .account.SwitchUser")
            except Exception:
                running_logger.debug("Enter activity %s", self.driver.current_activity)
                running_logger.debug("idp has already logout")
                return True
            # here we hardcode the keyword for sina, may change later
            sm.tap_keyword(u'退出当前帐号')
            return sm.tap_keyword(u'确定')
        if idp == 'wechat':
            try:
                self.driver.start_activity('com.tencent.mm', '.ui.LauncherUI',
                                           app_wait_activity='.ui.LauncherUI, .ui.account.LoginPasswordUI')
            except Exception:
                running_logger.debug("Enter activity %s", self.driver.current_activity)
            if sm.wait_for_destination(u'通讯录'):
                sm.tap_keyword(u'我')
                sm.tap_keyword(u'设置')
                sm.tap_keyword(u'退出')
                sm.tap_keyword(u'退出')
                return sm.wait_for_destination(u'用短信验证码登录', timeout=10)
            else:
                running_logger.debug("idp has already logout")
                return True
        else:
            raise Exception('IdP {} not supported'.format(idp))

    def rp_login(self, package, version, idp='sina', reset=False, user='Alice'):
        """function to complete rp login"""
        uiact = UIAction(self.driver, idp=idp, config_file=self.config_file, package=package, version=version)
        username, password = None, None

        if self.tag is None:
            result = uiact.login()
        elif idp == 'fb':
            result = 'IdpNeedLogin'
        elif idp == 'sina':
            if user == 'Eve':
                uiact.idp_set_session(idp, g_config["config"]["user"]["eve"]["weibo"]["session_file"])
            elif user == 'Alice':
                uiact.idp_set_session(idp, g_config["config"]["user"]["alice"]["weibo"]["session_file"])
            else:
                raise Exception("The user specified is not implemented yet.")
            result = uiact.login()
        elif idp == 'wechat':
            if user == 'Eve':
                uiact.idp_set_session(idp, g_config["config"]["user"]["eve"]["wechat"]["session_file"])
            elif user == 'Alice':
                uiact.idp_set_session(idp, g_config["config"]["user"]["alice"]["wechat"]["session_file"])
            else:
                raise Exception("The user specified is not implemented yet.")
            result = uiact.login()

        running_logger.info(u"RP login result: %s", result)
        if idp == 'fb':
            if user == 'Eve':
                username = g_config["config"]["user"]["eve"]["facebook"]["name"]
                password = g_config["config"]["user"]["eve"]["facebook"]["password"]
            elif user == 'Alice':
                username = g_config["config"]["user"]["alice"]["facebook"]["name"]
                password = g_config["config"]["user"]["alice"]["facebook"]["password"]
            else:
                raise Exception("The user specified is not implemented yet.")

        uiact.idp_handler(result, username, password)
        if reset:
            return None
        else:
            uiact.user_info()

    def rp_logout(self, package, version, idp='sina', user='Alice', reset=False):
        # clear fb session when logout
        if idp == 'fb':
            username, password = None, None
            if user == 'Eve':
                username = g_config["config"]["user"]["eve"]["facebook"]["name"]
                password = g_config["config"]["user"]["eve"]["facebook"]["password"]
            elif user == 'Alice':
                username = g_config["config"]["user"]["alice"]["facebook"]["name"]
                password = g_config["config"]["user"]["alice"]["facebook"]["password"]
            else:
                raise Exception("The user specified is not implemented yet.")

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
            node = re.search('fb_dtsg\" value=\"([a-zA-Z:_0-9]*)', body)
            if not node:
                running_logger.warn(body)
                raise Exception('can not find fb_dtsg')
            fb_dtsg = node.group(1)

            # logout all sessions
            url = 'https://www.facebook.com/security/settings/sessions/log_out_all/?dpr='
            requests.post(url, cookies=cookies, data={'__user':user, 'fb_dtsg':fb_dtsg})

        if reset:
            retVal = UIAction(self.driver, idp=idp, config_file=self.config_file, package=package, version=version).logout(reset=reset)
            return retVal
        else:
            if self.check_rp_status(package, version) == 'Guest':
                running_logger.debug("rp has already logout")
                return True
            return UIAction(self.driver, idp=idp, config_file=self.config_file, package=package, version=version).logout(reset=reset)

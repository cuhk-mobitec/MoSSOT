# -*- coding: utf-8 -*-
"""
module to do uiauto
"""

import json
import re
import codecs
import time
from urllib2 import URLError

from appium import webdriver
from selenium.common.exceptions import WebDriverException

from logger import logger
from emulator import ADB
from db import DB
from smartmonkey import Navigator, Stabilizer
from myexceptions import PathNotDefinedInConfig, IdPHandlingException, EmulatorActionException,\
                            TestInitException

RP_REQUEST_TIMEOUT = 20
IDP_STATUS_TIMEOUT = 20

class UIAction(object):
    """class to simplify ui action process"""
    def __init__(self, driver, emulator=None, idp=None, config_file=None, package=None, version=None):

        if 'udid' in driver.desired_capabilities and driver.desired_capabilities['udid']:
            self.adb = ADB(serial=driver.desired_capabilities['udid'])
        elif emulator and emulator.serial:
            self.adb = ADB(serial=emulator.serial)
        else:
            self.adb = ADB()

        if not package:
            package = self.adb.current_package()
            version = self.adb.current_version(package)

        self.emulator = emulator
        self.package = package
        self.driver = driver
        self.idp = idp
        self.app_style = 'international' if self.idp == 'fb' else 'chinese'

        self.config_file = config_file
        self.config = {}
        if config_file:
            self.loaded = self.load_config_from_file(config_file)
        else:
            if not idp:
                raise Exception("IdP not specified")
            self.loaded = self.load_config_from_db(package, idp, version=version)
        if self.loaded:
            if 'home_activity' in self.config and self.config['home_activity']:
                self.has_home_activity = True
            else:
                self.has_home_activity = False
        self.stabilizer = Stabilizer(self.driver, package=self.package, app_style=self.app_style)

    def load_config_from_db(self, package, idp, version=None):
        """load configuration from database"""
        config = DB().fetch_config(package, idp, version=version)
        if not config:
            return False
        else:
            logger.debug(u'Config for %s loaded from DB', package)
            return self.set_config(config)

    def load_config_from_file(self, filename):
        """load configuration from config file"""
        try:
            with open(filename, 'r') as config_f:
                result = self.set_config(config_f.read())
                logger.debug(u'Config for %s loaded from %s', self.config['package'], filename)
                return result
        except EnvironmentError:
            logger.error(u'Read file error: %s', filename)
            return False

    def set_config(self, config):
        """initialize configuration from json"""
        try:
            if isinstance(config, str):
                config = json.loads(config)
            # check required objects
            package_name = config['package']
            package_version = config['version']

            installed_version = self.adb.current_version(package_name)
            config_version = package_version
            if installed_version != config_version:
                logger.warning(u'Version inconsistent - Installed: %s, Config: %s',\
                            installed_version, config_version)

            self.config = config
            return True
        except ValueError:
            logger.error(u'Invalid path format')
            raise

    def login(self):
        """perform navigation to get to login page"""
        assert self.loaded
        login_path = self.path_for('login')
        origin = self.origin_for('login')
        if origin:
            self.stabilizer.better_start_activity(origin)
        else:
            self.start_home_activity()
        logger.info(u"[+] Navigate for login")
        loginer = Navigator(self.driver, path=login_path, package=self.config['package'],\
                            app_style=self.app_style)
        return loginer.navigate()

    def login_from_snapshot(self, tag):
        """restore session from snapshot"""
        # check emulator
        if not self.emulator:
            raise EmulatorActionException('No emulator instance is specified')
        # check snapshot
        tags_in_use = [ x['tag'] for x in self.emulator.list_snapshot()]
        if tag not in tags_in_use:
            raise EmulatorActionException('No snapshot with tag {}'.format(tag))
        # try to load snapshot
        if not self.emulator.load_snapshot(tag):
            raise EmulatorActionException('Fail to load snapshot {}'.format(tag))
        # try to restore appium session
        desired_caps = self.driver.capabilities
        desired_caps['autoLaunch'] = False
        try:
            self.driver = webdriver.Remote(self.driver.command_executor._url, desired_caps)
        except URLError:
            raise TestInitException('appium is not running')

        # try to login
        if self.idp == 'fb':
            status = 'IdpNeedLogin'
        return status

    def logout(self, reset=False):
        """perform logout action"""
        assert self.loaded
        self.clear_sdcard()
        if reset:
            logger.info(u"[+] App reset")
            return self.driver.reset()
        else:
            logout_path = self.path_for('logout')
            origin = self.origin_for('logout')
            if origin:
                self.stabilizer.better_start_activity(origin)
            else:
                self.start_home_activity()
            logger.info(u"[+] Navigate for logout")
            logoutter = Navigator(self.driver, path=logout_path, package=self.config['package'],\
                                  app_style=self.app_style)
            return logoutter.navigate()

    def clear_sdcard(self):
        """clear sdcard and keep only essential files"""
        files = self.adb.ls('/sdcard/')
        files_reserved = ['Android', 'DCIM', 'Download', 'Movies', 'Music', 'Notifications', 'Pictures',
                          'Podcasts', 'Ringtones', 'UxinSDK', 'backups', 'sina', 'tencent']
        for fname in files:
            if fname in files_reserved:
                continue
            self.adb.rm('/sdcard/{}'.format(fname))

    def user_info(self):
        """retrieve user info"""
        assert self.loaded
        info_path = self.path_for('user_info')
        origin = self.origin_for('user_info')
        if origin:
            self.stabilizer.better_start_activity(origin)
        else:
            self.start_home_activity()
        logger.info(u"[+] Navigate for user info")
        user_getter = Navigator(self.driver, path=info_path, package=self.config['package'],\
                                app_style=self.app_style)
        status = user_getter.navigate()
        if status == 'LoggedIn':
            identities = self.config['paths']['user_info']['identities']
            for (k, val) in identities.items():
                if re.search(val, self.page_source, re.I):
                    return k
            return 'Others'
        else:
            return status

        # ----------------- Single Destination -------------------
        # match = re.search(self.config['paths']['user_info']['identity_regex'],
        #                   self.page_source)
        # if len(match.groups()) > 0:
        #     return match.group(1)
        # else:
        #     return match.group(0)
        # [ example_regex: "(?=<[^<]*user_name[^<]*>)<.*?text=\"(.*?)\".*?>" ]

    def landing(self):
        """land on home activity"""
        home_activity = self.stabilizer.get_home_activity()
        if self.loaded:
            if self.has_home_activity and self.config['home_activity'] != home_activity:
                logger.warning(u'home_activity already exists in config, skip record update\n'
                               u'\tstored: %s， new: %s', self.config['home_activity'],\
                               home_activity)
            else:
                self.has_home_activity = True
                self.config['home_activity'] = home_activity
                if self.config_file:
                    self.config['home_activity'] = home_activity
                    with open(self.config_file, 'wb') as config_f:
                        config_f = codecs.getwriter('utf-8')(config_f)
                        json.dump(self.config, config_f, indent=4, sort_keys=True,\
                                  ensure_ascii=False)
                else:
                    result = DB().update_config(self.config['package'], self.config['idp'],\
                                {'home_activity': home_activity}, version=self.config['version'])
                    if result:
                        logger.info(u'home_activity:%s stored into config', home_activity)
        else:
            logger.info(u'Landed on %s', home_activity)
        return home_activity

    def start_home_activity(self, is_retry=False):
        """better start home activity"""
        if self.loaded and self.has_home_activity:
            home_activity = self.config['home_activity']
        else:
            logger.debug(u'home_activity not defined in DB')
            home_activity = self.landing()
        if self.stabilizer.better_start_activity(home_activity):
            return True
        else:
            if is_retry:
                logger.warning('uiaction: start_home_activity mismatch')
                return False
            else:
                self.stabilizer.skip_irrelevant()
                if self.driver.current_activity == home_activity:
                    return True
                else:
                    return self.start_home_activity(is_retry=True)

    def origin_for(self, action):
        """find origin of the action"""
        if action not in self.config['paths']:
            return False
        if 'origin' in self.config['paths'][action]:
            return self.config['paths'][action]['origin']
        else:
            return False

    def path_for(self, action):
        """find path to the action"""
        if action in self.config['paths'] and self.config['paths'][action]:
            return json.dumps(self.config['paths'][action])
        else:
            raise PathNotDefinedInConfig(u"%s not configured for %s - %s"
                                         % (action, self.config['package'], self.config['version']))

    def fblite_login_handler(self, stab, account=None, password=None):
        """handler for fblite login"""
        if not account or not password:
            account = "evesingsignon@gmail.com"
            password = "evessotest"

        # very ugly wait for status change
        logger.debug(u'Wait for status change')
        time.sleep(IDP_STATUS_TIMEOUT)

        # if session is stored
        if self.driver.current_activity != 'com.facebook.browser.lite.BrowserLiteActivity':
            logger.debug(u'Session is stored')
            return True

        # click continue
        logger.debug(u'Try to click continue')
        stab.find_elements_by_keyword(u'Continue', clickable_only=True,\
                                                exact=False)[-1].click()

        # wait for getting out of fblite
        count = 0
        while self.driver.current_activity == 'com.facebook.browser.lite.BrowserLiteActivity':
            time.sleep(1)
            count += 1
            assert count <= IDP_STATUS_TIMEOUT

        logger.debug(u'Get out of fblite')
        return True

    def fb_login_handler(self, stab, account=None, password=None):
        """handler for facebook webview login"""
        if not account or not password:
            account = "evesingsignon@gmail.com"
            password = "evessotest"
        keywords = [u"Enter email", u"请输入邮箱", u"輸入電郵"]
        err_keywords = [u'Error', u'Invalid', u'应用编号无效']
        block_keywords = [u'Secure Account']

        # wait for correct activity
        logger.debug(u'Wait for facebook login activity')
        count = 0
        activity = self.driver.current_activity
        while activity != 'com.facebook.FacebookActivity' and activity != 'com.facebook.LoginActivity':
            count += 1
            activity = self.driver.current_activity
            assert count <= IDP_STATUS_TIMEOUT

        # wait for input boxes appear
        logger.debug(u'Wait for input boxes appear')
        count = 0
        while not self.driver.find_elements_by_class_name('android.widget.EditText'):
            # in case app does not support fb login at all
            if any(kw in self.page_source for kw in err_keywords):
                raise IdPHandlingException('This app does not support facebook login')
            time.sleep(1)
            count += 1
            assert count <= IDP_STATUS_TIMEOUT

        # input email and password
        source = self.page_source
        logger.debug(u'Try to input email and password')
        if any(kw in source for kw in keywords):
            self.driver.find_elements_by_class_name('android.widget.EditText')[0]\
                                .set_text(account)
            self.driver.find_elements_by_class_name('android.widget.Button')[-1].click()
            self.driver.find_elements_by_class_name('android.widget.EditText')[-1]\
                                .set_text(password)
            self.driver.find_elements_by_class_name('android.widget.Button')[-1].click()
        elif any(kw in source for kw in err_keywords):
            raise IdPHandlingException('This app does not support facebook login')
        else:
            inputs = self.driver.find_elements_by_class_name('android.widget.EditText')
            inputs[0].set_text(account)
            inputs[-1].set_text(password)
            self.driver.find_elements_by_class_name('android.widget.Button')[-1].click()

        # wait for status change
        logger.debug(u'Wait for status change')
        status_keywords = [u'身分繼續', u'Continue', u'would like to'] + err_keywords + block_keywords
        count = 0
        while not any(kw in self.page_source for kw in status_keywords):
            time.sleep(1)
            count += 1
            assert count <= IDP_STATUS_TIMEOUT

        # handle pages after status change
        count = 0
        logger.debug(u'Try to handle pages after status change')
        while self.driver.current_activity == 'com.facebook.FacebookActivity'\
                or self.driver.current_activity == 'com.facebook.LoginActivity':
            count += 1

            source = self.page_source
            # in case of any error
            if any(kw in source for kw in err_keywords):
                logger.debug(u'Error keywords received')
                raise IdPHandlingException('This app does not support facebook login')
            # in case of account has been blocked
            elif any(kw in self.page_source for kw in block_keywords):
                raise IdPHandlingException('This account has been blocked!')
            # in case of continue appears
            elif 'Continue' in source:
                logger.debug(u'Try to click Continue')
                stab.find_elements_by_keyword(u'Continue', clickable_only=True,\
                                                exact=False)[-1].click()
            # give all possible permisson to the app
            elif 'would like to' in source:
                logger.debug(u'Try to offer permission by clicking OK')
                stab.find_elements_by_keyword(u'OK', clickable_only=True, exact=True)[-1].click()

            time.sleep(1)
            assert count <= IDP_STATUS_TIMEOUT
        logger.debug(u'Get out of facebook login webview')
        return True

    def idp_handler(self, status, account=None, password=None):
        """handler idp login process"""
        logger.info(u"RP login status: %s, idp: %s", status, self.idp)
        stab = Stabilizer(self.driver)
        if status == "Uncertain":
            if self.idp == 'sina' and stab.wait_for_activities('.SSOAuthorizeActivity'):
                status = "IdpNeedConfirm"
            elif self.idp == 'wechat' and stab.wait_for_keyword(u'微信登录|登录后应用将获得以下权限', timeout=60):
                status = "IdpNeedConfirm"
            elif self.idp == 'fb' and stab.wait_for_keyword(u'登录 Facebook 帐户', timeout=60):
                status = "IdpNeedLogin"
            else:
                return
        if status == "IdpNeedConfirm" and self.idp == 'sina':
            if self.driver.current_activity == '.SSOAuthorizeActivity' and \
                    stab.wait_for_keyword(u'确定', timeout=60):
                stab.tap_keyword(u'确定', siblings_on=False)
        elif status == "IdpNeedConfirm" and self.idp == 'wechat':
            if stab.wait_for_keyword(u'确认登录', timeout=60):
                stab.tap_keyword(u'确认登录', siblings_on=False)
        elif status == "IdpNeedLogin" and self.idp == 'fb':
            self.fb_login_handler(stab, account=account, password=password)
        elif status == "LoggedIn":
            pass
        else:
            logger.warning("Cannot handle: status - %s, IdP - %s", status, self.idp)
        time.sleep(RP_REQUEST_TIMEOUT)

    def idp_set_session(self, idp, path):
        """
        Set IdP to specific user session by file copying
        :param idp: fb, sina or wechat
        :param path: path to the folder or file containing session data.
            For wechat, no coexisting sessions are allowed, and sessions are bind to device information.
        :return: True for success
        """
        # make sure adb has root permission, if not exception will be raised
        self.adb.root()
        # On-device location of session file for different IdP
        PKG = {
            'fb': 'com.facebook.lite',
            'sina': 'com.sina.weibo',
            'wechat': 'com.tencent.mm'
        }
        DST = {
            'fb': '/data/data/com.facebook.lite/shared_prefs/',
            'sina': '/data/data/com.sina.weibo/databases/sina_weibo',
            'wechat': '/data/data/com.tencent.mm/MicroMsg/'
        }
        self.adb.force_stop(PKG[idp])
        self.adb.rm(DST[idp])
        self.adb.push(path, DST[idp])
        self.adb.chmod(DST[idp])

    @property
    def page_source(self):
        """wrapper around appium page_source to catch exception"""
        source = None
        e = None
        for _ in range(3):
            try:
                source = self.driver.page_source
                if source:
                    break
            except WebDriverException as e:
                time.sleep(1)
                continue
        else:
            raise WebDriverException(e)
        return source
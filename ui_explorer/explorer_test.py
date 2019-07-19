# -*- coding: utf-8 -*-
"""scripts used to automatically explore login path"""
import codecs
import os
import json
import unittest
from time import sleep
from ConfigParser import ConfigParser
from urllib2 import URLError
from pygments import highlight, lexers, formatters

from appium import webdriver
from selenium.common.exceptions import WebDriverException

from lib.logger import logger
from lib.manifest import Manifest
from lib.smartmonkey import Explorer, Navigator, Stabilizer
from lib.helper import PathJsonBuilder
from lib.emulator import AndroidEmulator, GenyPlayer
from lib.uiaction import UIAction
import lib.myexceptions as myexceptions


logger.setLevel(5)


class SSOAndroidTests(unittest.TestCase):
    """unit test testcase class for SSO test"""
    # These variables can be passed by setting module properties
    idp = None
    apk = None
    appium_port = None
    sys_port = None
    serial = None
    dfs = False
    explore_logout = False
    no_uninstall = False
    login_twice = True
    emulator = None
    result_folder = None
    use_snapshot = None

    def load_config(self):
        """load configuration from file"""

        script_dir = os.path.dirname(os.path.realpath(__file__))
        general_config_file = os.path.join(script_dir, 'conf/explorer.conf')
        idp_config_file = os.path.join(script_dir, 'conf/explorer.{}.conf'.format(self.idp))

        logger.info(u'[+] Load configuration from file')
        config = ConfigParser()
        config.readfp(codecs.open(general_config_file, 'r', 'utf-8'))

        # parse login-activity section
        self.act_keywords = config.get('login-activity', 'keywords').split('||')
        self.act_blacklist = config.get('login-activity', 'blacklist').split('||')

        # parse login-page section
        self.act_login_kw = config.get('login-page', 'keywords').split('||')

        config.readfp(codecs.open(idp_config_file, 'r', 'utf-8'))

        # parse login-path section
        self.login_dst_kw = []
        self.login_dst_act = None
        if config.has_option('login-path', 'dest_keywords'):
            self.login_dst_kw = config.get('login-path', 'dest_keywords').split('||')
        if config.has_option('login-path', 'dest_activities'):
            self.login_dst_act = config.get('login-path', 'dest_activities').split('||')

        def preprocess(s, section, dfs=False):
            # handle file:// protocol
            if s.startswith('file://'):
                with codecs.open(s[7:], 'r', encoding='utf-8') as f:
                    s = f.read()
            # replace IdP keywords template
            if '{{IdP_KEYWORDS}}' in s:
                assert config.has_option(section, 'idp_keywords'), "idp_keywords not defined in config"
                idp_keywords = config.get(section, 'idp_keywords')
                if dfs:
                    idp_keywords = idp_keywords.replace('||', '|')
                s = s.replace('{{IdP_KEYWORDS}}', idp_keywords)
            return s

        if not self.dfs:
            self.login_scan_kw = []
            scan_keywords = config.get('login-path', 'scan_keywords')
            scan_keywords = preprocess(scan_keywords, 'login-path')
            for line in scan_keywords.splitlines():
                levelkw = []
                for word in line.split('||'):
                    levelkw.append(word)
                self.login_scan_kw.append(levelkw)
        else:
            dfs_weights = config.get('login-path', 'dfs_weights')
            dfs_weights = preprocess(dfs_weights, 'login-path', dfs=True)
            self.login_dfs_weights = json.loads(dfs_weights)

        if self.explore_logout:
            if not self.dfs:
                # parse logout-path section
                self.logout_scan_kw = []
                scan_keywords = config.get('logout-path', 'scan_keywords')
                scan_keywords = preprocess(scan_keywords, 'logout-path')
                for line in scan_keywords.splitlines():
                    levelkw = []
                    for word in line.split('||'):
                        levelkw.append(word)
                    self.logout_scan_kw.append(levelkw)
            else:
                dfs_weights = config.get('logout-path', 'dfs_weights')
                dfs_weights = preprocess(dfs_weights, 'logout-path', dfs=True)
                self.logout_dfs_weights = json.loads(dfs_weights)

    def setUp(self):

        self.driver = None

        self.load_config()

        # initialize emulator
        logger.info(u'[+] Initializing Emulator')
        tags = [x['tag'] for x in self.emulator.list_snapshot()]
        if self.use_snapshot:
            assert self.use_snapshot in tags, 'snapshot not found'
            logger.debug(u'Loading saved snapshot...')
            self.emulator.load_snapshot(self.use_snapshot)
        else:
            gpu_option = self.emulator.options.get('gpu') if self.emulator.options else None
            if gpu_option == 'host':
                if 'clean_gpu' in tags:
                    logger.debug(u'Loading gpu supported snapshot...')
                    self.emulator.load_snapshot('clean_gpu')
                else:
                    logger.debug(u'Saving snapshot...')
                    self.emulator.save_snapshot('clean_gpu')
            elif gpu_option == 'off':
                if 'clean_no_gpu' in tags:
                    logger.debug(u'Loading cpu supported snapshot...')
                    self.emulator.load_snapshot('clean_no_gpu')
                else:
                    logger.debug(u'Saving snapshot...')
                    self.emulator.save_snapshot('clean_no_gpu')

        # extract package, activity from APK
        logger.info(u'[+] Extract info from APK')
        manifest = Manifest(self.apk)
        package_name = manifest.get_package_name()
        version_name = manifest.get_version_name()
        launcher_activity = manifest.get_launcher_activity()
        logger.info(u'Package: %s, Version: %s', package_name, version_name)
        logger.debug(u'Launcher activity: %s', launcher_activity)
        self.package = package_name
        self.version = version_name
        self.launcher_activity = launcher_activity

        # version check
        installed_version = self.emulator.current_version(package_name)
        if installed_version != version_name:
            logger.warning(u'Different version - Installed: %s， Provided: %s',
                           installed_version, version_name)

        # install apk if apk not installed
        if installed_version is None:
            logger.info(u'Installing ...')
            self.emulator.install_package(self.apk)

        # prepare appium settings
        desired_caps = dict()
        desired_caps['platformName'] = 'Android'
        desired_caps['deviceName'] = 'ExplorerDevice'
        desired_caps['automationName'] = 'UiAutomator2'
        desired_caps['platformVersion'] = '6.0'
        desired_caps['appPackage'] = package_name
        desired_caps['appActivity'] = launcher_activity
        desired_caps['newCommandTimeout'] = 9999
        desired_caps['disableWindowAnimation'] = True
        desired_caps['autoGrantPermissions'] = True
        desired_caps['udid'] = self.emulator.serial
        if self.sys_port:
            desired_caps['systemPort'] = self.sys_port
        if self.use_snapshot:
            desired_caps['autoLaunch'] = False
        uiautomator_config = {
            "waitForIdleTimeout": 3000,
            # "waitForSelectorTimeout": 1000
        }

        # launch driver
        try:
            self.driver = webdriver.Remote(
                'http://localhost:{}/wd/hub'.format(self.appium_port), desired_caps)
            self.driver.update_settings(uiautomator_config)
        except URLError:
            raise myexceptions.TestInitException('appium is not running')

    def tearDown(self):
        if not self.no_uninstall:
            logger.info(u'Removing ...')
            self.emulator.remove_package(self.package)
        if self.driver:
            self.driver.quit()

    def safe_get_home_activity(self, stabilizer):
        """
        safe method to find home activity
        handle cases where app crashes
        """
        stabilizer.stabilize()
        activity = stabilizer.driver.current_activity
        logger.debug(u'Testing home_activity')
        try:
            stabilizer.land_on_activity(activity)
            if stabilizer.driver.current_activity == activity:
                stabilizer.home_activity = activity
            else:
                logger.warning(u'home_activity is not stable')
                stabilizer.home_activity = self.launcher_activity
                stabilizer.driver.launch_app()
        except WebDriverException:
            logger.warning(u'Fail to start home_activity')
            stabilizer.driver.launch_app()
            stabilizer.home_activity = self.launcher_activity
        return stabilizer.home_activity

    def test_search_login(self):
        """explore logic"""
        # start testing
        logger.info(u'[+] Start testing')

        # init
        apk_folder = os.path.dirname(os.path.abspath(self.apk))
        log_folder = os.path.join(apk_folder, self.result_folder)
        config_file = os.path.join(log_folder, '{}.json'.format(self.package))
        pathconf = PathJsonBuilder(package=self.package, version=self.version, idp=self.idp)
        if self.idp == 'fb':
            pathconf.update_destination('login', 'IdpNeedLogin', 'android.webkit.WebView')
        if not os.path.exists(log_folder):
            os.mkdir(log_folder)

        if not self.use_snapshot:
            # get home activity
            logger.info(u'[>] Get home activity')
            sleep(5)
            stabilizer = Stabilizer(self.driver, self.package)
            # continue explorer when skip irrelevant exceed limit (cases of login on loading page)
            try:
                home_activity = self.safe_get_home_activity(stabilizer)
            except myexceptions.SkipIrrelevantExceedLimit:
                home_activity = self.driver.current_activity
            logger.info(u"Home activity loaded: %s", home_activity)
            pathconf.update_home_activity(home_activity)

        # explore login path
        logger.info(u"[>] Explore login path")
        explorer = Explorer(self.driver, package=self.package)
        explorer.set_dest_keywords(self.login_dst_kw)
        explorer.set_dest_activities(self.login_dst_act)
        if self.dfs:
            explorer.set_dfs_config(self.login_dfs_weights)
        else:
            explorer.set_scan_keywords(self.login_scan_kw)
        if self.use_snapshot:
            explorer.set_snapshot_info(self.emulator, self.use_snapshot)
        else:
            explorer.set_home_activity(home_activity)
        result = explorer.explore(algorithm='dfs' if self.dfs else 'scan')
        if result['status'] != 'success':
            logger.warning(u'Login path explore unsuccessful\n\tresult: %s', result)
            return False
        pathconf.update_path('login', stops=result['path'])

        # save config
        self.save_config(pathconf, config_file)

        # login process finished
        logger.info(u"[>] Finish login process")

        # perform idp login
        logger.info(u"[>] Perform IdP login")
        try:
            uiact = UIAction(self.driver, idp=self.idp, config_file=config_file)
            if self.idp == 'fb':
                uiact.idp_handler('IdpNeedLogin')
            else:
                uiact.idp_handler('Uncertain')
        except AssertionError:
            pathconf.update_status('fail to handle idp login')
            # save config
            self.save_config(pathconf, config_file)
            return False
        except myexceptions.IdPHandlingException:
            logger.warning('This app does not support %s login', self.idp)
            os.remove(config_file)
            return False
        finally:
            # take a screenshot of status after login
            self.driver.save_screenshot(os.path.join(log_folder, '{}.png'.format(self.package)))
        logger.info(u"[>] Finish IdP login process")

        # perform second time login
        if self.login_twice:
            logger.info(u"[>] Perform second time login")
            try:
                navigator = Navigator(self.driver, self.package, path=json.dumps(pathconf.paths['login']))
                try:
                    if self.use_snapshot:
                        explorer.reload_snapshot()
                    else:
                        stabilizer.land_home()
                except WebDriverException as err:
                    if 'Error occured while starting App' in err.msg:
                        pathconf.update_status('passed')
                if pathconf.status != 'passed':
                    if not navigator.navigate():
                        pathconf.update_status('passed')
                    else:
                        pathconf.update_status('need check')
            except myexceptions.SkipIrrelevantExceedLimit:
                pathconf.update_status('passed')
            except Exception:
                pathconf.update_status('crash in second login')

            # save config
            self.save_config(pathconf, config_file)

            # login process finished
            logger.info(u"[>] Finish second time login process")

        # explore logout path
        if self.explore_logout:
            logger.info(u"[>] Explore logout path")
            stabilizer.land_home()
            if self.dfs:
                explorer.set_dfs_config(self.logout_dfs_weights)
            else:
                explorer.set_scan_keywords(self.logout_scan_kw)
            explorer.set_dest_keywords(None)
            explorer.set_dest_activities(None)
            result = explorer.explore(algorithm='dfs' if self.dfs else 'scan')
            if result['status'] != 'success':
                logger.warning(u'Logout path explore unsuccessful\n\tresult: %s', result)
                return False

            # save config
            pathconf.update_path('logout', stops=result['path'])
            self.save_config(pathconf, config_file)

            logger.info(u"[>] Finish logout exploration process")

        # finished
        return True

    @staticmethod
    def save_config(pathconf, config_file):
        """
        method to save config file
        """
        path_json = pathconf.dump()
        logger.info("Path Config:")
        logger.info(highlight('\x00\n'+path_json, lexers.JsonLexer(), formatters.TerminalFormatter()))
        with codecs.open(config_file, 'w', encoding='utf-8') as config_f:
            config_f.write(path_json)


def main():
    """main script"""

    import argparse

    # parse arguments
    usage = "%(prog)s [options] apk_folder"
    parser = argparse.ArgumentParser(description='Scripts to explore login path for\
                            specific apk and idp', usage=usage)
    parser.add_argument('-i', '--idp', type=str, metavar='<idp>',
                        choices=['fb', 'wechat', 'sina'],
                        help="specify target IdP, current support: sina, wechat, fb", required=True)
    parser.add_argument('apk', type=str, metavar='apk',
                        help='where the apk is located')
    parser.add_argument('--dfs', action="store_true", default=False,
                        help='Use DFS algorithm. By default it will use level-based keyword scan')
    parser.add_argument('-p', '--port', type=int, metavar='<port>', default=4723,
                        help='appium port')
    parser.add_argument('--emulator', type=str, metavar='<emulator>', default='android',
                        help='type of emulator: android or genymotion')
    parser.add_argument('-n', '--name', dest='name', metavar='<name>',
                        help="specify device name of Android device", default=None)
    parser.add_argument('--no-emulator-restart', action="store_true", default=False,
                        help='do not restart emulator before testing')
    parser.add_argument('--no-window', action='store_true',
                        help='for android emulator only: start emulator without window')
    parser.add_argument('--http-proxy', type=str, metavar='<http_proxy>',
                        help='for android emulator only: set proxy for android emulator')
    parser.add_argument('--gpu', type=str, metavar='<gpu>',
                        help='for android emulator only: gpu rendering: \
                                auto, host, off, shaderswift-indirect')
    parser.add_argument('--use-snapshot', type=str, metavar='<snapshot_name>',
                        help='for android emulator only: use snapshot as starting point')
    parser.add_argument('--logout', action="store_true", default=False,
                        help='Explore logout path as well')
    parser.add_argument('--no-uninstall', action="store_true", default=False,
                        help='Don\'t uninstall app after test')
    parser.add_argument('--no-login-twice', action="store_true", default=False,
                        help='login twice to distinguish passed app or app need configuration')
    parser.add_argument('--result-folder', type=str, metavar='<result_folder>', default='explorer_log',
                        help='result folder for recording explorer log')
    args = parser.parse_args()

    # start emulator
    if args.emulator == 'genymotion':
        SSOAndroidTests.emulator = GenyPlayer(args.name)

    elif args.emulator == 'android':
        options = vars(args)
        SSOAndroidTests.emulator = AndroidEmulator(args.name,
                                                   options={k: v for k, v in options.items() if v is not None})

    if not args.no_emulator_restart:
        SSOAndroidTests.emulator.restart()

    # run test in the emulator
    SSOAndroidTests.idp = args.idp
    SSOAndroidTests.apk = args.apk
    SSOAndroidTests.appium_port = args.port
    SSOAndroidTests.sys_port = args.port + 500
    SSOAndroidTests.dfs = args.dfs
    SSOAndroidTests.explore_logout = args.logout
    SSOAndroidTests.login_twice = not args.no_login_twice
    SSOAndroidTests.no_uninstall = args.no_uninstall
    SSOAndroidTests.result_folder = args.result_folder
    SSOAndroidTests.use_snapshot = args.use_snapshot
    suite = unittest.TestLoader().loadTestsFromTestCase(SSOAndroidTests)
    unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
    main()

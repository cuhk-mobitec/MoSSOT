# -*- coding: utf-8 -*-
"""navigator testcase"""
import os
import unittest
import json
from optparse import OptionParser

from appium import webdriver

from lib.emulator import ADB
from lib.manifest import Manifest
from lib.logger import MyLogger
from lib.uiaction import UIAction


logger = MyLogger(name='NavigatorTest').get_logger()


class SSOAndroidTests(unittest.TestCase):
    """test case of navigating by following config file"""

    apk = None
    idp = None
    path_config = None
    serial = None
    appium_port = None
    no_reset = False

    def setUp(self):
        # init
        idp = self.idp
        adb = ADB(serial=self.serial)

        # extract package, activity from APK
        manifest = Manifest(self.apk)
        package_name = manifest.get_package_name()
        version_name = manifest.get_version_name()
        logger.info(u'APK - Package: %s, Version: %s', package_name, version_name)
        launcher_activity = manifest.get_launcher_activity()
        logger.debug(u'Launcher activity: %s', launcher_activity)
        self.package = package_name
        self.launcher_activity = launcher_activity

        # version check
        installed_version = adb.current_version(package_name)
        if installed_version != version_name:
            logger.warning(u'Different version - Installed: %s， Provided: %s', installed_version, version_name)

        # install the package if it is not installed
        if installed_version is None:
            logger.info(u'Installing ...')
            adb.install_package(self.apk)

        desired_caps = dict()
        desired_caps['platformName'] = 'Android'
        desired_caps['deviceName'] = 'NavigatorDevice'
        desired_caps['automationName'] = 'UiAutomator2'
        desired_caps['appPackage'] = package_name
        desired_caps['appActivity'] = launcher_activity
        desired_caps['newCommandTimeout'] = 9999
        desired_caps['autoGrantPermissions'] = True
        desired_caps['disableWindowAnimation'] = True
        # desired_caps['autoLaunch'] = False
        desired_caps['noReset'] = self.no_reset
        if self.serial:
            desired_caps['udid'] = self.serial
        uiautomator_settings = {
            "waitForIdleTimeout": 3000,
            # "waitForSelectorTimeout": 1000
        }

        self.driver = webdriver.Remote('http://localhost:{}/wd/hub'.format(self.appium_port), desired_caps)
        self.driver.update_settings(uiautomator_settings)

        logger.info(u'[+] UI action initiated')
        self.uiact = UIAction(self.driver, idp=idp, package=package_name, version=version_name,
                              config_file=self.path_config)

    def tearDown(self):
        raw_input("Enter to quit ...")
        self.driver.quit()

    def test_navigator(self):
        """navigation test"""

        try:
            uiact = self.uiact

            result = uiact.login()
            if not result:
                return False
            logger.info(u"[>] Login result: %s", result)

            uiact.idp_handler(result)
            #
            # user = uiact.user_info()
            # if not user:
            #     return False
            # logger.info(u"[>] User info extraction: %s", user)
            #
            # result = uiact.logout(reset=True)
            # if not result:
            #     return False
            # logger.info(u"[>] Logout result: %s", result)
            #
            # user = uiact.user_info()
            # if not user:
            #     return False
            # logger.info(u"[>] User info extraction: %s", user)
            #
            # result = uiact.login()
            # if not result:
            #     return False
            # logger.info(u"[>] Login result: %s", result)
            #
            # uiact.idp_handler(result)
            #
            # user = uiact.user_info()
            # if not user:
            #     return False
            # logger.info(u"[>] User info extraction: %s", user)

        except KeyboardInterrupt:
            return False


def main():
    """main logic"""

    # add options
    usage = "usage: %prog [options] apk_file"
    parser = OptionParser(usage)
    parser.add_option("-i", "--idp", dest="idp",
                      help="specify the IdP to test", default=None)
    parser.add_option("-c", "--config", dest="config",
                      help="provide the path config file", metavar="FILE", default=None)
    parser.add_option("-n", "--no-reset", action="store_true", dest="noreset",
                      help="turn on no-reset", default=False)
    parser.add_option("-s", "--serial", dest="serial",
                      help="specify serial NO. of Android device", default=None)
    parser.add_option("-p", "--port", dest="port",
                      help="specify port of Appium server", default=4723)
    parser.add_option("-q", "--quiet", action="store_false", dest="verbose",
                      help="Do not show debug level output", default=True)
    (options, args) = parser.parse_args()

    # basic check
    if len(args) != 1:
        parser.error("incorrect number of arguments")

    # set log level
    if options.verbose:
        logger.setLevel('DEBUG')
    else:
        logger.setLevel('INFO')

    # set apk
    apk = args[0]
    if not os.path.exists(apk):
        parser.error("APK file not found")
    SSOAndroidTests.apk = apk

    # set idp
    idp = None
    if options.idp:
        idp = options.idp
    elif options.config:
        content = json.load(open(options.config, 'r'))
        if 'idp' in content and content['idp']:
            idp = content['idp']
    if not idp:
        parser.error("Please specify IdP in either --idp or --config option")
    SSOAndroidTests.idp = idp

    # set other parameters
    SSOAndroidTests.path_config = options.config
    SSOAndroidTests.serial = options.serial
    SSOAndroidTests.appium_port = options.port
    SSOAndroidTests.no_reset = options.noreset

    # start test
    suite = unittest.TestLoader().loadTestsFromTestCase(SSOAndroidTests)
    unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
    main()

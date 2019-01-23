#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import subprocess
from time import sleep
import unittest
import codecs
import sys
reload(sys)
sys.setdefaultencoding('utf8')
from lockfile import LockFile
from appium import webdriver
import difflib
import sys
from selenium.common.exceptions import WebDriverException
#import Stepper
#import conf
#from io import open
from rpActions import login
from rpActions import user_info
from uiauto.smartmonkey import SmartMonkey
from tools import getUiautomatorConfig

packageName = 'ctrip.android.view'
activityName = 'ctrip.android.view.splash.CtripSplashActivity'
portNum = 4723
systemPort = 8200

class Ssotest(unittest.TestCase):
    def setUp(self):
        desired_caps = {}
        desired_caps['platformName'] = 'Android'
        desired_caps['platformVersion'] = '6.0'
        desired_caps['deviceName'] = 'emulator'
        desired_caps['appPackage'] = packageName
        desired_caps['appActivity'] = activityName
        desired_caps['disableWindowAnimation'] = True
        desired_caps['autoGrantPermissions'] = True
        desired_caps['systemPort'] = systemPort
        desired_caps['noReset'] = True

        if getUiautomatorConfig():
            desired_caps['automationName'] = 'UiAutomator2'

        url = 'http://localhost:' + str(portNum) + '/wd/hub'
        self.driver = webdriver.Remote(url, desired_caps)
        #SmartMonkey(self.driver).skip_irrelevant()
        #self.home_activity = self.driver.current_activity

    def tearDown(self):
        # end the session
        try:
            self.driver.quit()
        except Exception:
            pass

    def test_rpInfo(self):
        #print user_info(self.driver, package=packageName)
        sys.stdout.write(str(user_info(self.driver, package=packageName)))


if __name__ == '__main__':
    if (len(sys.argv) == 4):
        packageName = str(sys.argv[1])
        activityName = str(sys.argv[2])
        systemPort = int(sys.argv[3])
    if (len(sys.argv) == 5):
        packageName = str(sys.argv[1])
        activityName = str(sys.argv[2]) 
        portNum = int(sys.argv[3])
        systemPort = int(sys.argv[4])

    suite = unittest.TestLoader().loadTestsFromTestCase(Ssotest)
    unittest.TextTestRunner(verbosity=2).run(suite)

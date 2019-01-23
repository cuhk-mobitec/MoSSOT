import os
import subprocess
from time import sleep
import unittest
import codecs
import sys
from lockfile import LockFile
from appium import webdriver
import difflib
import sys
from tools import getUiautomatorConfig
#from io import open

packageName = 'ctrip.android.view'
activityName = 'ctrip.android.view.splash.CtripSplashActivity'
resultPath = './result.txt'
portNum = 4723
systemPort = 8200

def writeResult(result):
    f = open(resultPath,"r")    
    lock = LockFile(resultPath)
    with lock:
        lines = f.readlines()
        f.close()
    resultNum = len(lines) 
    f = open(resultPath,"a+")    
    lock = LockFile(resultPath)
    with lock:
        if resultNum == 0:
            if result == True:
                f.write("True")
            else:
                f.write("False")
        else:
            if result == True:
                f.write("\nTrue")
            else:
                f.write("\nFalse")
        f.close()

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

    def tearDown(self):
        # end the session
        try:
            self.driver.quit()
        except Exception:
            pass

    def test_resetRp(self):
        self.driver.reset()
        sleep(3)
        writeResult(True)

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


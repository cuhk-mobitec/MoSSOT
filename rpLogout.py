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
from rpActions import logout
from uiauto.smartmonkey import SmartMonkey
from tools import getUiautomatorConfig

packageName = 'ctrip.android.view'
activityName = 'ctrip.android.view.splash.CtripSplashActivity'
resultPath = './result.txt'
idpName = 'com.sina.weibo'
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

def IfScrollable(driver):                  #check whether page is scrollable
    S=driver.page_source
    Thelist = S.split('>')

    for i in range(len(Thelist)):
        if 'scrollable="true"' in Thelist[i]:
            Cls=Thelist[i][Thelist[i].find("class")+7:]
            Cls=Cls[:Cls.find('"')]
            Ins=Thelist[i][Thelist[i].find("instance")+10:]
            Ins=Ins[:Ins.find('"')]


            x1=int(Thelist[i][Thelist[i].find('bounds="[')+9:Thelist[i].find(',',Thelist[i].find('bounds="[')+9)])
            y1=int(Thelist[i][Thelist[i].find(',',Thelist[i].find('bounds="[')+9)+1:Thelist[i].find(']',Thelist[i].find('bounds="[')+9)])
            temp=Thelist[i][Thelist[i].find(']',Thelist[i].find('bounds="[')+9)+2:]
            x2=int(temp[:temp.find(',')])
            y2=int(temp[temp.find(',')+1:temp.find(']')])

            x=int((x1+x2)/2)
            Y1=int((y2-y1)*0.25)+y1
            Y2=int((y2-y1)*0.75)+y1
            return [True,x,Y1,Y2]

    return [False,0,0,0]

def getClickableRegion(driver):
    xRegion = []
    yRegion = []
    S=driver.page_source
    widgets = S.split('>')
    for widget in widgets:
        if 'clickable="true"' in widget:
            x1=int(widget[widget.find('bounds="[')+9:widget.find(',',widget.find('bounds="[')+9)])
            y1=int(widget[widget.find(',',widget.find('bounds="[')+9)+1:widget.find(']',widget.find('bounds="[')+9)])
            temp=widget[widget.find(']',widget.find('bounds="[')+9)+2:]
            x2=int(temp[:temp.find(',')])
            y2=int(temp[temp.find(',')+1:temp.find(']')])
            xRegion.append([x1,x2])
            yRegion.append([y1,y2])

    return [xRegion,yRegion]

def findElementByName(driver, keyword):
    [xRegion, yRegion] = getClickableRegion(driver)
    widgets = driver.page_source.split('>')
    for widget in widgets:
        if keyword in widget:
            x1=int(widget[widget.find('bounds="[')+9:widget.find(',',widget.find('bounds="[')+9)])
            y1=int(widget[widget.find(',',widget.find('bounds="[')+9)+1:widget.find(']',widget.find('bounds="[')+9)])
            temp=widget[widget.find(']',widget.find('bounds="[')+9)+2:]
            x2=int(temp[:temp.find(',')])
            y2=int(temp[temp.find(',')+1:temp.find(']')])
            x = (x1 + x2) / 2
            y = (y1 + y2) / 2
            if (checkClickability(x,xRegion)) and (checkClickability(y,yRegion)):
                return [True, x1, x2, y1, y2]
            else:
                continue

    return [False, 0, 0, 0, 0]

def checkClickability(coordinate, regions):
    for region in regions:
        if coordinate >= float(region[0]) and coordinate <= float(region[1]):
            return True
    return False

def tapSuccess(x,y,driver):     #judge whether click action works or not
    s=driver.page_source

    try:
        driver.tap([(x,y)],1)
    except WebDriverException:
        return -2
    else:
        sleep(1)
        if difflib.SequenceMatcher(None,driver.page_source,s).ratio()>=0.95:   #compare two pages
            try:
                driver.tap([(x,y)],1)                                              #try once again
            except WebDriverException:
                pass
            sleep(1)
            if difflib.SequenceMatcher(None,driver.page_source,s).ratio()>=0.95:
                return -1
    return 0

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
        desired_caps['systemPort'] = system_port
        desired_caps['noReset'] = True
        if getUiautomatorConfig():     
            desired_caps['automationName'] = 'UiAutomator2'

        url = 'http://localhost:' + str(portNum) + '/wd/hub'
        self.driver = webdriver.Remote(url, desired_caps)
        #SmartMonkey(self.driver).skip_irrelevant()

    def tearDown(self):
        # end the session
        try:
            self.driver.quit()
        except Exception:
            pass

    def test_rpLogout(self):
        logout(self.driver, package=packageName)
        '''
        if packageName == 'ctrip.android.view':
            ctripLogout(self.driver)
        elif packageName == 'com.autonavi.minimap':
            amapLogout(self.driver)
        elif packageName == 'air.tv.douyu.android':
            douyuLogout(self.driver)
        '''

if __name__ == '__main__':
    if (len(sys.argv) == 4):
        packageName = str(sys.argv[1])
        activityName = str(sys.argv[2])
        systemPort = int(sys.argv[3])
    elif (len(sys.argv) == 5):
        packageName = str(sys.argv[1])
        activityName = str(sys.argv[2])        
        portNum = int(sys.argv[3])
        systemPort = int(sys.argv[4])
    else:
        print "misuse this script. Usage: python rpLogout.py [packageName] [activityName]"
        exit(-1)
    suite = unittest.TestLoader().loadTestsFromTestCase(Ssotest)
    unittest.TextTestRunner(verbosity=2).run(suite)

#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import json
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
import psutil
from selenium.common.exceptions import WebDriverException
from uiauto.myexceptions import *
#import Stepper
#import conf
#from io import open
from rpActions import login
from rpActions import user_info
from uiauto.smartmonkey import SmartMonkey, Stabilizer 
from tools import getLast
from tools import removeLastTested
from tools import getUiautomatorConfig
import logging
from logger import MyLogger


packageName = 'ctrip.android.view'
activityName = 'ctrip.android.view.splash.CtripSplashActivity'
authorized = False
idpName = 'sina'
resultPath = './result.txt'
lockFilePath = './lock.txt'
portNum = 4723
systemPort = 8200

running_logger = MyLogger('rpConfirm').get_logger()

#g_logger = conf.g_logger
#g_result = conf.g_result
#g_conf = conf.g_config
#g_appinfo = conf.g_appinfo

def getLockFileLength():
    f = open(lockFilePath,"r")
    lock = LockFile(lockFilePath)
    with lock:
        lines = f.readlines()
        f.close()
    return len(lines)

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
            elif result == "Alice":
                f.write("\nAlice")
            elif result == "Eve":
                f.write("\nEve")
            else:
                f.write("\nFalse")
        f.close()

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
            if 'clickable="true"' in widget or 'long-clickable="true"' in widget:
                return [True, x1, x2, y1, y2]
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

def sinaConfirm(driver):
    fileLen = getLockFileLength()
    while True:
        if fileLen < getLockFileLength():
            break
        sleep(1)
    f = open(lockFilePath,"r")
    command = None
    lock = LockFile(lockFilePath)
    with lock:
        lines = f.readlines()
        command = lines[len(lines) - 1]
        f.close()
    if command == 'x':
        return False
    s = driver.page_source
    driver.tap([(500, 900)], 1)
    sleep(10)
    return True

def wechatConfirm(driver):
    fileLen = getLockFileLength()
    while True:
        if fileLen < getLockFileLength():
            break
        sleep(1)
    f = open(lockFilePath,"r")
    command = None
    lock = LockFile(lockFilePath)
    with lock:
        lines = f.readlines()
        command = lines[len(lines) - 1]
        f.close()
    if command == 'x':
        return False
    sm = SmartMonkey(driver)
    sm.tap_keyword(u'确认登录')
    sleep(10)
    return True

def fbConfirm(driver):
    fileLen = getLockFileLength()
    while True:
        if fileLen < getLockFileLength():
            break
        sleep(1)
    f = open(lockFilePath,"r")
    command = None
    lock = LockFile(lockFilePath)
    with lock:
        lines = f.readlines()
        command = lines[len(lines) - 1]
        f.close()
    if command == 'x':
        return False

    stab = Stabilizer(driver)
    count = 0
    running_logger.debug(u'Try to handle pages after status change')
    err_keywords = [u'Error', u'Invalid']
    try:
        while driver.current_activity == 'com.facebook.FacebookActivity'\
                or driver.current_activity == 'com.facebook.LoginActivity':
            count += 1
            source = driver.page_source
            # in case of continue appears
            if 'Continue' in source:
                running_logger.debug(u'Try to click Continue')
                stab.find_elements_by_keyword(u'Continue', clickable_only=True,\
                                                exact=False)[-1].click()
            # give all possible permisson to the app
            elif 'would like to' in source:
                running_logger.debug(u'Try to offer permission by clicking OK')
                stab.find_elements_by_keyword(u'OK', clickable_only=True, exact=True)[-1].click()
            sleep(1)
            assert count <= 10
        running_logger.debug(u'Get out of facebook login webview')
    except:
        running_logger.exception("exception in rpConfirm:")
    finally:
        return True

def googleConfirm(driver):
    result = findElementByName(driver, "Alice")
    if result[0] == False:
        result = findElementByName(driver, "Eve")
    x = (result[1] + result[2]) / 2
    y = (result[3] + result[4]) / 2
    if result[0] == False:
        print("Fails to find user Account button!")
        writeResult(False)
        return
    result = tapSuccess(x, y, driver)
    if result != 0:
        print("Fails to click user Account button!")
        writeResult(False)
        return
    sleep(3)
    writeResult(True)

def typeUserInfo(Username,Password,driver):       #input username and keyword when login in Facebook
    s=driver.page_source
    thelist = s.split('>')

    flag = 0
    for i in range(len(thelist)):
        if 'EditText' in thelist[i] and flag==0:
            Cls=thelist[i][thelist[i].find("class")+7:]
            Cls=Cls[:Cls.find('"')]
            Ins=thelist[i][thelist[i].find("instance")+10:]
            Ins=Ins[:Ins.find('"')]

            passEdit=driver.find_element_by_android_uiautomator('new UiSelector().className("'+Cls+'").instance('+Ins+')')
            text=passEdit.get_attribute('name')
            passEdit.click()    #enter the edittext widgt
            driver.press_keycode(123)             #move to the end ot the text
            for i in range(0,len(text)+5):   #delete one by one in the text part
                driver.press_keycode(67)
            passEdit.send_keys(Username)
            flag=1


        elif 'EditText' in thelist[i] and flag==1:
            Cls=thelist[i][thelist[i].find("class")+7:]
            Cls=Cls[:Cls.find('"')]
            Ins=thelist[i][thelist[i].find("instance")+10:]
            Ins=Ins[:Ins.find('"')]
            passEdit=driver.find_element_by_android_uiautomator('new UiSelector().className("'+Cls+'").instance('+Ins+')')
            passEdit.click()
            passEdit.send_keys(Password)
            flag=2
            break

    return 0

def typeContent(content,driver):       #input username and keyword when login in Facebook
    e=driver.find_elements_by_class_name('android.widget.EditText')[0]
    text=e.get_attribute('name')
    e.click()    #enter the edittext widgt
    driver.press_keycode(123)             #move to the end ot the text
    for i in range(0,len(text)+5):   #delete one by one in the text part
        driver.press_keycode(67)
    e.send_keys(content)

    return 0

def facebookInput(driver, name, word):
    try:
        if u'请输入邮箱' in driver.page_source:
            typeContent(name, driver)
            sm = SmartMonkey(driver)
            sm.tap_keyword(u'登录')
            typeContent(word, driver)
            e=driver.find_elements_by_class_name('android.widget.Button')[1]
            e.click()
        elif 'Log in' in driver.page_source:
            typeUserInfo(name,word,driver)
            e=driver.find_elements_by_class_name('android.widget.Button')[-1]
            e.click()
        else:
            typeUserInfo(name,word,driver)
            e=driver.find_elements_by_class_name('android.widget.Button')[0]
            e.click()
    except:
        return False
    return True

class Ssotest(unittest.TestCase):
    def setUp(self):
        data = json.load(open('config.json', 'r'))

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

        if data['snapshot']:
            desired_caps['autoLaunch'] = False
        if getUiautomatorConfig():
            desired_caps['automationName'] = 'UiAutomator2'       

        url = 'http://localhost:' + str(portNum) + '/wd/hub'

        #load snapshot
        try:
            if data['snapshot'] == "True":
                self.emulator = AndroidEmulator(data["emulator"])
                tags_in_use = [ x['tag'] for x in self.emulator.list_snapshot()]
                if data["snapshot_tag"] not in tags_in_use:
                    raise EmulatorActionException('No snapshot with tag {}'.format(data["snapshot_tag"]))
                if not self.emulator.load_snapshot(data["snapshot_tag"]):
                    raise EmulatorActionException('Fail to load snapshot {}'.format(data["snapshot_tag"]))
            else:
                self.emulator = None
            self.driver = webdriver.Remote(url, desired_caps)
        except:
            running_logger.exception('Driver init error')
            raise Exception('Driver init error')
        
        #SmartMonkey(self.driver).skip_irrelevant()
        #self.home_activity = self.driver.current_activity

    def tearDown(self):
        # end the session
        try:
            self.driver.quit()
        except Exception:
            pass

    def test_rpConfirm(self):
        data = json.load(open('config.json', 'r'))
        if data['snapshot'] == "True":
            if data['idp'] == 'sina':
                if data['user'] == "Eve":
                    UIAction(self.driver, idp='sina', config_file='uiaction.json').idp_set_session('sina', data["config"]["user"]["eve"]["weibo"]["session_file"])
                else:
                    raise Exception("The user specified is not implemented yet.")
            elif data['idp'] == 'wechat':
                if data['user'] == "Eve":
                    UIAction(self.driver, idp='wechat', config_file='uiaction.json').idp_set_session('wechat', data["config"]["user"]["eve"]["wechat"]["session_file"])
                else:
                    raise Exception("The user specified is not implemented yet.")
            #print 'enter snapshot handler'
        if data['idp'] != 'fb' or data['snapshot'] == "False":
            result = login(self.driver, package=packageName)
        else:
            result = True
        
        if result == False:
            self.driver.reset()
            print 'reset'
            result = login(self.driver, package=packageName)
        if not result:
            '''
            with open('appiumError.txt','a+') as f:
                f.write('fuzzing fails in ' + str(getLast()) + '\n')   
                removeLastTested()         
            '''
            p = psutil.Process(os.getpid())
            p.terminate()
            return

        if idpName == 'fb':
            data = json.load(open('config.json', 'r'))
            if data['user'] == 'Eve':
                username = data["config"]["user"]["eve"]["facebook"]["name"]
                password = data["config"]["user"]["eve"]["facebook"]["password"]
            elif data['user'] == 'Alice':
                username = data["config"]["user"]["alice"]["facebook"]["name"]
                password = data["config"]["user"]["alice"]["facebook"]["password"]
            else:
                running_logger.error('The user specified is not implemented yet.')
                writeResult(False)
                return              
            if not facebookInput(self.driver, username, password):
                result = login(self.driver, package=packageName)
                if result == False:
                    self.driver.reset()
                    result = login(self.driver, package=packageName)
                if not result:
                    '''
                    with open('appiumError.txt','a+') as f:
                        f.write('fuzzing fails in ' + str(getLast()) + '\n')
                        removeLastTested()
                    '''
                    p = psutil.Process(os.getpid())
                    p.terminate()
                    return
                if not facebookInput(self.driver, username, password):
                    '''
                    with open('appiumError.txt','a+') as f:
                        f.write('fuzzing fails in ' + str(getLast()) + '\n')
                        removeLastTested()
                    '''
                    p = psutil.Process(os.getpid())
                    p.terminate()
                    return                                                
            counter = 0

            while 'Continue' not in self.driver.page_source:
                counter = counter + 1
                if (u'登录' in self.driver.page_source) and counter < 3:
                    try:
                        e=self.driver.find_elements_by_class_name('android.widget.Button')[0]
                        e.click()
                    except:
                        pass
                sleep(1)
                if counter == 10:
                    writeResult(False)
                    return


        if authorized == False:
            sleep(2)
            if idpName == 'sina' and ('OK' in self.driver.page_source or u'确定' in self.driver.page_source):
                self.driver.tap([(500, 900)], 1)
                sleep(10)
                # sleep(5)
            elif idpName == 'wechat':
                if  u'确认登录' in self.driver.page_source:
                    sm = SmartMonkey(self.driver)
                    sm.tap_keyword(u'确认登录')
                    sleep(10)
                else:
                    sleep(8)
            elif idpName == 'fb':
                stab = Stabilizer(self.driver)
                count = 0
                running_logger.debug(u'Try to handle pages after status change')
                err_keywords = [u'Error', u'Invalid']
                try:
                    while self.driver.current_activity == 'com.facebook.FacebookActivity'\
                            or self.driver.current_activity == 'com.facebook.LoginActivity':
                        count += 1
                        source = self.driver.page_source
                        # in case of continue appears
                        if 'Continue' in source:
                            running_logger.debug(u'Try to click Continue')
                            stab.find_elements_by_keyword(u'Continue', clickable_only=True,\
                                                            exact=False)[-1].click()
                        # give all possible permisson to the app
                        elif 'would like to' in source:
                            running_logger.debug(u'Try to offer permission by clicking OK')
                            stab.find_elements_by_keyword(u'OK', clickable_only=True, exact=True)[-1].click()
                        sleep(1)
                        assert count <= 10
                    running_logger.debug(u'Get out of facebook login webview')
                except:
                    running_logger.exception("exception in rpConfirm:")
            if idpName != 'google':
                #verifyCtrip(self.driver)
                #self.driver.start_activity(packageName, self.home_activity)
                #user_info(self.driver, package=packageName)
                writeResult(True)
            return
            
        if idpName != 'google':
            writeResult(True)
        if authorized:
            if idpName == 'sina':
                #if Stepper.actionName == 'Initialize':
                #    if self.driver.current_activity != '.SSOAuthorizeActivity':
                #        g_result.error('Alarm: the app supports webviewer only!')
                result = sinaConfirm(self.driver)
                if result == False:
                    writeResult(False)
                    return
                else:
                    #verifyCtrip(self.driver)
                    #self.driver.start_activity(packageName, self.home_activity)
                    #user_info(self.driver, package=packageName)
                    writeResult(True)
                    return
            elif idpName == 'wechat':
                result = wechatConfirm(self.driver)
                if result == False:
                    writeResult(False)
                    return     
                else:
                    #user_info(self.driver, package=packageName)   
                    writeResult(True)
                    return      
            elif idpName == 'fb':
                result = fbConfirm(self.driver)
                if result == False:
                    writeResult(False)
                    return     
                else:
                    #user_info(self.driver, package=packageName)   
                    writeResult(True)
                    return                       

if __name__ == '__main__':
    if (len(sys.argv) == 4):
        idpName = str(sys.argv[1])
        authorized = str(sys.argv[2])
        systemPort = int(sys.argv[3])
        if authorized == 'True':
            authorized = True
        else:
            authorized = False
    if (len(sys.argv) == 6):
        idpName = str(sys.argv[1])
        authorized = str(sys.argv[2])
        packageName = str(sys.argv[3])
        activityName = str(sys.argv[4])
        systemPort = int(sys.argv[5])
        if authorized == 'True':
            authorized = True
        else:
            authorized = False
    if (len(sys.argv) == 7):
        idpName = str(sys.argv[1])
        authorized = str(sys.argv[2])
        packageName = str(sys.argv[3])
        activityName = str(sys.argv[4])
        portNum = int(sys.argv[5])
        systemPort = int(sys.argv[6])
        if authorized == 'True':
            authorized = True
        else:
            authorized = False
    #print(getLockFileLength())
    suite = unittest.TestLoader().loadTestsFromTestCase(Ssotest)
    unittest.TextTestRunner(verbosity=2).run(suite)

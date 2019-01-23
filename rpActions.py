#!/usr/bin/env python
# -*- coding: utf-8 -*-
from uiauto.uiaction import UIAction
from uiauto.helper import AppNotRunningException
from lockfile import LockFile
import time

resultPath = 'result.txt'

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
            elif result == "Alice":
                f.write("Alice")
            elif result == "Eve":
                f.write("Eve")
            elif result == "Others":
                f.write("Others")                
            else:
                f.write("False")
        else:
            if result == True:
                f.write("\nTrue")
            elif result == "Alice":
                f.write("\nAlice")
            elif result == "Eve":
                f.write("\nEve")
            elif result == "Others":
                f.write("\nOthers")
            else:
                f.write("\nFalse")
        f.close()


def login(driver, config_file=None, package=None, version=None):
    import json

    with open("uiaction.json") as f:
        data = json.load(f)
    if 'count' not in data:
        data['count'] = str(1)
    else:
        data['count'] = str(int(data['count']) + 1)
    json.dump(data, open("uiaction.json", 'w'))

    ui = UIAction(driver, config_file="uiaction.json", package=package, version=version)
    # ui = UIAction(driver, config_file=config_file, package=package, version=version)
    try:
        result = ui.login()
    except AppNotRunningException:
        return False
    if result:
        return True
    else:
        #writeResult(False)
        return False


def logout(driver, config_file=None, package=None, version=None):
    ui = UIAction(driver, config_file="uiaction.json", package=package, version=version)
    # ui = UIAction(driver, config_file=config_file, package=package, version=version)
    try:
        result = ui.logout()
    except AppNotRunningException:
        ui.start_home_activity()
        status = ui.user_info()
        if status != 'Guest':
            ui.start_home_activity()
            result = ui.logout()
    result = True if result else False
    writeResult(result)
    return result


def user_info(driver, config_file=None, package=None, version=None):
    result = UIAction(driver, config_file="uiaction.json", package=package, version=version).user_info()
    # result = UIAction(driver, config_file=config_file, package=package, version=version).user_info()
    #writeResult(result)
    return result

import subprocess
import os
import sys
import json
import tools
from time import sleep
from lockfile import LockFile
from subprocess import PIPE
from util import teardownFBSessions
resultPath = './result.txt'
lockFilePath = './lock.txt'

process = None

def getResultNum():
	f = open(resultPath,"r")    
	lock = LockFile(resultPath)
	with lock:
		lines = f.readlines()
		f.close()
	resultNum = len(lines)
	return resultNum

def getResult(resultNum):
	global process
	while True:
		f = open(resultPath,"r")
		lock = LockFile(resultPath)
		result = None
		with lock:
			lines = f.readlines()
			f.close()
		if len(lines) > resultNum:
			result = lines[len(lines) - 1]
			if result == 'True':
				return True
			elif result == "Alice":
				return 'Alice'
			elif result == "Eve":
				return 'Eve'
			elif result == "Others":
				return 'Others'    
			else:
				return False
				break 
		elif process != None and process.poll() != None:
			return -1
		sleep(1)

def resetRp(packageName = None, activityName = None, port = None, systemPort=8200):
	data = json.load(open('config.json', 'r'))
	if data['idp'] == 'fb':
		teardownFBSessions()
	global process
	process = None
	resultNum = getResultNum()
	if port != None:
		process = subprocess.Popen(["python","resetRp.py", str(packageName),str(activityName), str(port), str(systemPort)])
	elif packageName != None and activityName != None:
		process = subprocess.Popen(["python","resetRp.py", str(packageName),str(activityName), str(systemPort)])
	else:
		process = subprocess.Popen(["python","resetRp.py"])
	process.communicate()
	return getResult(resultNum)

def idpLogin(idpName = None, user = None, packageName = None, activityName = None, port = None):
	global process
	process = None
	resultNum = getResultNum()
	count = 0
	while count < 2:
		if port != None:
			process = subprocess.Popen(["python","idpLogin.py", str(idpName), str(user), str(port)])	
		elif user != None:
			if packageName != None and activityName != None:
				process = subprocess.Popen(["python","idpLogin.py", str(idpName), str(user) ,str(packageName),str(activityName)])
			else:
				process = subprocess.Popen(["python","idpLogin.py", str(idpName), str(user)])			
		else:
			process = subprocess.Popen(["python","idpLogin.py"])
		result = getResult(resultNum)
		if result:
			return True
		else:
			process = subprocess.Popen(["python","idpInfo.py", str(idpName)], stdout = PIPE)
			if 'True' in process.communicate()[0]:
				return True
		count += 1
		resultNum = getResultNum()
	if count == 2:
		return -1				

def idpLogout(idpName = None, packageName = None, activityName = None, port = None):
	global process
	process = None
	resultNum = getResultNum()
	count = 0
	while count < 2:
		if port != None:
			process = subprocess.Popen(["python","idpLogout.py", str(idpName), str(port)])	
		elif packageName != None and activityName != None:
			process = subprocess.Popen(["python","idpLogout.py", str(idpName), str(packageName),str(activityName)])
		else:
			process = subprocess.Popen(["python","idpLogout.py", str(idpName)])
		result = getResult(resultNum)
		if result:
			return True
		else:
			process = subprocess.Popen(["python","idpInfo.py", str(idpName)], stdout = PIPE)
			if 'False' in process.communicate()[0]:
				return True
		count += 1
		resultNum = getResultNum()
	if count == 2:
		return -1				


def rpInput(idpName = None, installed = None, authorized = None, packageName = None, activityName = None, port = None):
	global process
	process = None
	resultNum = getResultNum()
	if port != None:
		process = subprocess.Popen(["python","rpInput.py", str(idpName), str(installed), str(authorized), str(packageName), str(activityName), str(port)])
	elif installed != None and authorized != None:
		if packageName != None and activityName != None:
			process = subprocess.Popen(["python","rpInput.py", str(idpName), str(installed), str(authorized), str(packageName), str(activityName)])
		else:
			process = subprocess.Popen(["python","rpInput.py", str(idpName), str(installed), str(authorized)])
	else:
		process = subprocess.Popen(["python","rpInput.py"])
	result = getResult(resultNum)
	return result

def rpAuthorize(resultNum):	
	f = open(lockFilePath,"a+")    
	lock = LockFile(lockFilePath)
	try:
		with lock:
			f.write("\n1")
			f.close()
			sleep(1)
	except:
		pass
	result = getResult(resultNum)
	return result

def rpLogout(packageName = None, activityName = None, port = None, reset=False, systemPort=8200):
	data = json.load(open('config.json', 'r'))
	if data['idp'] == 'fb':
		teardownFBSessions()
	if reset:
		return resetRp(packageName, activityName, port, systemPort)	
	global process
	process = None
	resultNum = getResultNum()
	count = 0
	while count < 2:
		if port != None:
			process = subprocess.Popen(["python","rpLogout.py", str(packageName),str(activityName), str(port), str(systemPort)])		
		elif packageName != None and activityName != None:
			process = subprocess.Popen(["python","rpLogout.py", str(packageName),str(activityName), str(systemPort)])
		else:
			process = subprocess.Popen(["python","rpLogout.py"])
		result = getResult(resultNum)
		if result:
			return True
		count += 1
		resultNum = getResultNum()
	if count == 2:
		return -1		

def rpConfirm(idpName = None, authorized = None, packageName = None, activityName = None, port = None, systemPort=8200):
	global process
	process = None
	resultNum = getResultNum()
	if port != None:
		process = subprocess.Popen(["python","rpConfirm.py", str(idpName), str(authorized), str(packageName), str(activityName), str(port), str(systemPort)])	
	elif authorized != None:
		if packageName != None and activityName != None:
			process = subprocess.Popen(["python","rpConfirm.py", str(idpName), str(authorized), str(packageName), str(activityName), str(systemPort)])
		else:
			process = subprocess.Popen(["python","rpConfirm.py", str(idpName), str(authorized), str(systemPort)])
	else:
		process = subprocess.Popen(["python","rpConfirm.py"])
	result = getResult(resultNum)
	return result

def rpInfo(packageName = None, activityName = None, port = None, systemPort=8200):
	if port != None:
		process = subprocess.Popen(["python","rpInfo.py", str(packageName), str(activityName), str(port), str(systemPort)], stdout = PIPE)
	else:
		process = subprocess.Popen(["python","rpInfo.py", str(packageName), str(activityName), str(systemPort)], stdout = PIPE)
	result = process.communicate()[0]
	if 'Alice' in result:
		return 'Alice'
	elif 'Eve' in result:
		return 'Eve'
	elif 'Others' in result:
		return 'Others'
	else:
		return False

if __name__ == '__main__':
	print rpConfirm('sina',True, 'ctrip.android.view', 'ctrip.android.view.splash.CtripSplashActivity')
	print rpAuthorize()
	#print rpLogout('ctrip.android.view', 'ctrip.android.view.splash.CtripSplashActivity')

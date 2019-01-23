import os
import time
import glob

import shutil
import argparse

from init import main as init
from main import main as tester
from logger import MyLogger

logger = MyLogger('Batch').get_logger()

def main(args):
    args.config = None

    finished = False
    result_folder = ''
    try:
        # init log
        logger.info('Initialisation starts')
        logger.info('apk:\t\t\t%s', args.apk_file)
        logger.info('appium port:\t\t%s', args.appium_port)
        logger.info('appium back port:\t%s', args.appium_back_port)
        logger.info('proxy port:\t\t%s', args.proxy_port)
        logger.info('system port:\t\t%s', args.appium_system_port)
        finished, result_folder = init(args)
        if finished:
            logger.info('Main program starts')
            logger.info('apk:\t\t\t%s', args.apk_file)
            logger.info('appium port:\t\t%s', args.appium_port)
            logger.info('appium back port:\t%s', args.appium_back_port)
            logger.info('proxy port:\t\t%s', args.proxy_port)
            logger.info('system port:\t\t%s', args.appium_system_port)
            finished = tester(result_folder, args)
            if args.idp_name == 'fb':
                time.sleep(30*60)
        else:
            print "Initialisation fail"
    except Exception:
        logger.exception("exception: ")
    return finished, result_folder

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Initialisation for model testing.')
    parser.add_argument('-f', action='store', dest='apk_folder', type=str, help='testing apk folder', default="../apk/")
    parser.add_argument('--policy', action='store', dest='policy_file', type=str, help='policy configuration file', default=None)
    parser.add_argument('-a', action='store', dest='appium_port', type=int, help='appium server port', default=4723)
    parser.add_argument('-sp', action='store', dest='appium_system_port', type=int, help='appium system port', default=8200)
    parser.add_argument('-bp', action='store', dest='appium_back_port', type=int, help='appium back port', default=2530)
    parser.add_argument('-p', action='store', dest='proxy_port', type=int, help='mitmdump proxy port', default=8080)
    # parser.add_argument('--data', action='store', dest='data_folder', type=str, help='customised data path', default="../networkTraceResult/")
    parser.add_argument('--gpu', action='store', dest='gpu', type=str, choices=['off', 'host', 'shaderswift_indirect'], help='gpu acceleration options', default='host')
    parser.add_argument('--no-windosw', action='store_true', dest='no-window', help='whether there is window for android emulator')
    parser.add_argument('-r', action='store', dest='result_folder', type=str, help='customised result path', default="../networkTraceResult/")
    parser.add_argument('-i', action='store', dest='idp_name', type=str, help='target IdP', default="sina")
    parser.add_argument('-d', action='store', dest='device_name', type=str, help='dedicated machine name', default=None, required=True)
    parser.add_argument('--reset', action='store_true', dest='reset', help='use reset function if this flag is set')
    parser.add_argument('--noappium', action='store_true', dest='noappium', help='do not start appium and new device in this program, environment has been set up by default')
    parser.add_argument('--tag', action='store', dest='snapshot_tag', type=str, help    ='snapshot tag used to login rp', default=None)
    args = parser.parse_args()
    #After reading the basic settings, start checking the apk folder for app to test
    srcAPKpath = args.apk_folder
    files = glob.glob(os.path.join(srcAPKpath, "*.apk"))
    folders = ["../result/failed_result", "../result/failed_apk", "../result/success_result", "../result/success_apk", "../result/noui_result", "../result/noui_apk"]
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder, 0755)
    files.sort()
    with open("../result/run_script_stage.txt", "a") as resultf:
        resultf.write("Start batch testing at "+time.strftime("%H:%M:%S")+"\n")
    while files:
        result_folder = None
        for ff in files:
            finished = False
            result_folder = ''
            # remove the prefix '../apk/'
            f = os.path.basename(ff)
            args.apk_file = ff
            with open("../result/run_script_stage.txt", "a") as resultf:
                resultf.write("Start: "+f+time.strftime("%H:%M:%S")+"\n")
                resultf.close()
            #Now start the test
            try:
                finished, result_folder = main(args)
            except Exception:
                finished = False
                print "Error in the test, try next apk"
            #Now move the result into the correct folder
            printText = "Failed: "+f+time.strftime("%H:%M:%S")+"\n"
            resultMoveFolder = "../result/failed_result"
            resultAPKFolder = "../result/failed_apk"
            if finished:
                printText = "Success: "+f+time.strftime("%H:%M:%S")+"\n"
                resultMoveFolder = "../result/success_result"
                resultAPKFolder = "../result/success_apk"
            elif finished is None:
                resultMoveFolder = "../result/noui_result"
                resultAPKFolder = "../result/noui_apk"
            try:
                shutil.move(result_folder, resultMoveFolder)
            except Exception:
                with open("../result/run_script_stage.txt", "a") as resultf:
                    resultf.write("No result to move: "+f+time.strftime("%H:%M:%S")+"\n")
                    resultf.close()
            shutil.move(ff, os.path.join(resultAPKFolder, f))
            with open("../result/run_script_stage.txt", "a") as resultf:
                #resultf.write(unicode(f,"utf-8").encode("UTF-8"))
                resultf.write(printText)
                resultf.close()
            time.sleep(60)
        files = glob.glob(os.path.join(srcAPKpath, "*.apk"))
        files.sort()
    print "Finished batch testing"

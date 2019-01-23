"""
main script to run model-based testing
"""
import json
import os
import glob
import shutil
import multiprocessing
import argparse
import time
import random
import string
import datetime
import logging
import colorlog

from UI_controller import UI_controller
from init import main as init
from uiauto.manifest import Manifest
from pymodel import pmt
from util import start_android_emulator, revoke_at, term_by_port,\
                fetch_uiaction, launch_appium, launch_mitmdump
from logger import MyLogger
import tools

running_logger = MyLogger('Tester').get_logger()
apkfile = ''

def set_state(appium_port, proxy_port, system_port, current_user, package, launcher_activity, version, idp_name, ui_support, reset=False, emulator_name=None, snapshot_tag=None):
    def change_user(appium_port, idpPackageName, idpActivityName, idp_name, proxy_port, current_user):
        mitmdump = launch_mitmdump(proxy_port)
        uictrl = UI_controller(appium_port, system_port=system_port, package_name=idpPackageName, activity_name=idpActivityName, emulator_name=emulator_name)
        running_logger.debug('Try to change account')
        for _ in range(3):
            try:
                if uictrl.idp_login(current_user, idp_name):
                    break
            except Exception:
                continue
        else:
            mitmdump.terminate()
            raise Exception("Unable to login idp")
        mitmdump.terminate()

    idpPackageName = None
    idpActivityName = None
    if idp_name == 'sina':
        idpPackageName = 'com.sina.weibo'
        idpActivityName = 'com.sina.weibo.SplashActivity'
    elif idp_name == 'wechat':
        idpPackageName = 'com.tencent.mm'
        idpActivityName = 'com.tencent.mm.ui.LauncherUI'
    authorization = 'False'
    rpstatus = 'False'
    statefile = 'state_' + ''.join(random.choice(string.lowercase) for i in range(5))
    if os.path.isfile('state.json'):
        with open('state.json') as f:
            stateVariables = json.load(f)
            authorization = stateVariables['Eve_Auth_RP']
            rpstatus = stateVariables['Eve_state']
    running_logger.info("Setting state, authorization: %s, rpstatus: %s", authorization, rpstatus)

    mitmdump = None
    if (idp_name == 'sina' or idp_name == 'wechat') and snapshot_tag is None:
        change_user(appium_port, idpPackageName, idpActivityName, idp_name, proxy_port, current_user)

    for _ in range(2):
        try:
            mitmdump = launch_mitmdump(proxy_port, extra_cmd=['-s', 'proxy/prob_dump.py -f {} -u {} -i {}'.format(statefile, ui_support, idp_name)])
            login_result = UI_controller(appium_port, system_port=system_port, package_name=package, activity_name=launcher_activity, emulator_name=emulator_name, tag=snapshot_tag).rp_login(package, version, idp_name, user=current_user, reset=reset)
            if login_result != 'Guest' and snapshot_tag is None:
                UI_controller(appium_port, system_port=system_port, package_name=package, activity_name=launcher_activity, emulator_name=emulator_name).rp_logout(package, version, reset=reset)
            mitmdump.terminate()
            time.sleep(3)
            state = json.load(open(statefile, 'r'))
            if reset or login_result != 'Guest':
                break
        except Exception:
            running_logger.exception('Got exception in rp login, package: %s', package)
            term_by_port(proxy_port)
            time.sleep(3)
            state = json.load(open(statefile, 'r'))
            if idp_name == 'sina' and state['status'] == 'rate_limit' and snapshot_tag is None:
                running_logger.warn("Encounter rate limit, current user: %s, rate-limited urls: %s", current_user, str(state['idp_url']))
                current_user = 'Eve1' if current_user == 'Eve' else 'Eve'
                change_user(appium_port, idpPackageName, idpActivityName, idp_name, proxy_port, current_user)
                continue
    else:
        raise Exception("Unable to login")

    time.sleep(3)
    state = json.load(open(statefile, 'r'))
    if idp_name == 'sina' or idp_name == 'fb':
        if authorization == 'False' and state['access_token'] != None:
            revoke_at(idp_name, state['access_token'])
        elif authorization == 'True':
            stateVariables = {}
            with open('state.json', 'r') as f:
                stateVariables = json.load(f)
            stateVariables['access_token'] = state['access_token']
            with open('state.json', 'w') as f:
                json.dump(stateVariables, f)

    if rpstatus == 'False' and snapshot_tag is None:
        UI_controller(appium_port, system_port=system_port, package_name=package, activity_name=launcher_activity, config_file='uiaction.json', emulator_name=emulator_name).rp_logout(package, version, user=current_user, reset=reset)
    os.remove(statefile)
    return current_user

def main(apk_folder, args):

    finished = False

    # make sure folder exists
    if not os.path.isdir(apk_folder):
        raise ValueError('input folder not exists!')

    # prepare working environment #dirty environment
    for filename in glob.glob(os.path.join(apk_folder, '*para*')):
        shutil.copy(filename, './')
    for filename in glob.glob(os.path.join(apk_folder, '*.apk')):
        shutil.copy(filename, './test.apk')
    if os.path.exists(os.path.join(apk_folder, 'appinfo.json')):
        shutil.copy(os.path.join(apk_folder, 'appinfo.json'), './appinfo.json')
    if os.path.exists(os.path.join(apk_folder, 'config.json')):
        shutil.copy(os.path.join(apk_folder, 'config.json'), './config.json')
    if os.path.exists('state.json'):
        os.remove('state.json')

    # extract apk information
    manifest = Manifest('test.apk')
    package_name = manifest.get_package_name()
    launcher_activity = manifest.get_launcher_activity()
    version = manifest.get_version_name()

    # open tested.json and count the number of tested elements# what the hell is this?
    json.dump({}, open('tested.json', 'w'))
    json.dump({}, open('redundant.json', 'w'))

    # setup logger
    logging.root.handlers = []
    formatter = colorlog.ColoredFormatter(
        '[%(name)s][%(levelname)s]%(asctime)s %(log_color)s%(message)s',
        datefmt='%m-%d %H:%M')
    handler = logging.FileHandler(os.path.join(apk_folder, "tester.log"), mode='w')
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    logging.root.addHandler(handler)

    running_logger.info("Testing with apk: %s, policy file: %s", apk_folder, args.policy_file)

    # rewrite config.json and
    config = json.load(open('config.json', 'r'))
    if args.policy_file:
        policy = json.load(open(args.policy_file, 'r'))
        config['policy'] = policy
    config['idp'] = args.idp_name
    config['ui_reset'] = 'True' if args.reset else 'False'
    config['proxy_port'] = str(args.proxy_port)
    config['appium_port'] = str(args.appium_port)
    config['system_port'] = str(args.appium_system_port)
    if args.snapshot_tag != None:
        config["snapshot"] = 'True'
        config["emulator"] = args.device_name
        config["snapshot_tag"] = args.snapshot_tag
    else:
        config["snapshot"] = 'False'
    json.dump(config, open('config.json', 'w'))

    if args.config:
        running_logger('Try to load customized path config')
        # make sure config file exists
        if not os.path.exists(args.config):
            running_logger.exception('Cannot find the path config file')
            return finished
        os.rename(args.config, 'uiaction.json')
    else:
        # get the uiaction.json file from database
        running_logger.debug("fetching ui config from oauth server")
        try:
            fetch_uiaction(package_name, version, args.snapshot_tag, args.idp_name)
        except Exception:
            running_logger.exception('Cannot fetch ui config from database')
            return finished

    import conf
    count = -1
    Appium_process = None
    main_process = None
    retry_time = 0
    max_retry_time = 20
    user = 'Eve'
    emulator = None
    start_time = datetime.datetime.now()
    time.sleep(5)
    while True:
        try:
            new_count = tools.countFuzzedCases()
            # clean up when process behave abnormally or it has finished the target
            if count == new_count or new_count > conf.g_config['policy']['cases'] or (main_process and main_process.exitcode):
                running_logger.warning("cleaning up the enviroment. count == new count? %s; new_count exceed config setting? %s; main_process.exitcode? %s", count == new_count, new_count > conf.g_config['policy']['cases'], (main_process and main_process.exitcode))
                running_logger.warning("main process exit code: %s", main_process.exitcode)
                main_process.terminate()
                try:
                    Appium_process.kill()
                except OSError as e:
                    running_logger.error(e)
                if emulator:
                    emulator.stop()
                if main_process.exitcode == 0 or new_count > conf.g_config['policy']['cases']:
                    running_logger.info("Testing finished, exit from main process.")
                    finished = True
                    break

            # start new testing in the beginning or process behave abnormally
            if count == new_count or count == -1 or (main_process and main_process.exitcode):
                # start new device
                term_by_port(args.proxy_port)
                term_by_port(args.appium_port)
                retry_time = retry_time + 1
                if retry_time > max_retry_time:
                    running_logger.critical("exceed maximum retry limit %s, exit!", max_retry_time)
                    break
                running_logger.info("setting up the enviroment, retry time: %s", retry_time)
                emulator = start_android_emulator('test.apk', args)

                #start appium server to communicate with emulator
                Appium_process = launch_appium(args, emulator)

                #dignose the enviroment: 1) idp api rate limit; 2) other issue
                running_logger.info("dignose the environment problem")
                user = set_state(args.appium_port, args.proxy_port, args.appium_system_port, user, package_name, launcher_activity, version, args.idp_name, config['ui_support'], args.reset, args.device_name, args.snapshot_tag)
                if user != None:
                    running_logger.info("starting new testing")
                    main_process = multiprocessing.Process(target=pmt.main, args=("-i Stepper SSO",))
                    main_process.start()
                else:
                    raise Exception("Unable to start new testing")
            if count != new_count:
                count = new_count
                running_logger.info("Process behave normally, number of tested case: %s", count)
            main_process.join(timeout=300)
        except Exception:
            running_logger.exception("Unknown exception")
            if main_process:
                main_process.terminate()
    end_time = datetime.datetime.now()
    ui_login = 0
    with open("uiaction.json") as f:
        data = json.load(f)
    if 'count' in data:
        ui_login = data['count']
    running_logger.info("Testing duration: %s, effective tested cases: %s, total tested cases: %s, restart time: %s, total RP login times: %s", str(end_time-start_time), tools.countFuzzedCases(), tools.countCases('tested.json'), retry_time, ui_login)
    appiumError = tools.checkAppiumError()
    if appiumError != None:
        for item in appiumError:
            running_logger.info('Potential Appium Error: Apply '+ item[4] +' on '+ item[3] +' for the ' + item[1] + ' of ' + item[0])
    # after testing move files to another folder
    if os.path.exists('state.json'):
        os.rename('state.json', os.path.join(apk_folder, 'state.json'))
    if os.path.exists('tested.json'):
        os.rename('tested.json', os.path.join(apk_folder, 'tested.json'))
    if os.path.exists('redundant.json'):
        os.rename('redundant.json', os.path.join(apk_folder, 'redundant.json'))
    if os.path.exists('proxyMissing.log'):
        os.rename('proxyMissing.log', os.path.join(apk_folder, 'proxyMissing.log'))
    if os.path.exists('appiumError.log'):
        os.rename('appiumError.log', os.path.join(apk_folder, 'appiumError.log'))
    f = open('result.log', 'w')
    f.truncate()
    f.close()
    f = open('running.log', 'w')
    f.truncate()
    f.close()

    running_logger.info("testing result: %s, apk_folder: %s!", finished, apk_folder)
    return finished

if __name__ == '__main__':
    # main program for pipeline testing
    parser = argparse.ArgumentParser(description='Main program for model testing.')
    parser.add_argument('-f', action='store', dest='apk_file', type=str, help='testing apk folder', required=True)
    parser.add_argument('--policy', action='store', dest='policy_file', type=str, help='policy configuration file', default=None)
    parser.add_argument('-a', action='store', dest='appium_port', type=int, help='appium server port', default=4723)
    parser.add_argument('-sp', action='store', dest='appium_system_port', type=int, help='appium system port', default=8200)
    parser.add_argument('-bp', action='store', dest='appium_back_port', type=int, help='appium back port', default=2530)
    parser.add_argument('-p', action='store', dest='proxy_port', type=int, help='mitmdump proxy port', default=8080)
    parser.add_argument('--data', action='store', dest='data_folder', type=str, help='customised data path', default="../networkTraceResult/")
    parser.add_argument('--gpu', action='store', dest='gpu', type=str, choices=['off', 'host', 'shaderswift_indirect'], help='gpu acceleration options', default='host')
    parser.add_argument('--no-window', action='store_true', dest='no_window', help='whether there is window for android emulator')
    parser.add_argument('--qemu', action='store', dest='qemu', help='extra qemu arguments')
    parser.add_argument('-r', action='store', dest='result_folder', type=str, help='customised result path', default="../networkTraceResult/")
    parser.add_argument('-i', action='store', dest='idp_name', type=str, help='target IdP', default="sina")
    parser.add_argument('--conf', action='store', dest='config', type=str,
                        help='path config file')
    parser.add_argument('-d', action='store', dest='device_name', type=str, help='dedicated machine name', default=None, required=True)
    parser.add_argument('--tag', action='store', dest='snapshot_tag', type=str, help='snapshot tag used to login rp', default=None)
    parser.add_argument('--reset', action='store_true', dest='reset', help='use reset function if this flag is set')
    parser.add_argument('--noappium', action='store_true', dest='noappium', help='do not start appium and new device in this program, environment has been set up by default')
    parser.add_argument('--noinit', action='store_true', dest='noinit', help='do not go through initialization procedure, mainly for debugging', default=False)

    args = parser.parse_args()

    if not args.noinit:
        running_logger.info("Initialisation starts")
        running_logger.info("apk folder: %s", args.apk_file)
        running_logger.info("appium port:%s", args.appium_port)
        running_logger.info("appium back port:%s", args.appium_back_port)
        running_logger.info("appium system port:%s", args.appium_back_port)
        running_logger.info("proxy port:%s", args.proxy_port)

        finished, result_folder = init(args)

        if not finished:
            running_logger.error("Initialisation Fail, result folder: %s", result_folder)
            exit()
    else:
        manifest = Manifest(args.apk_file)
        package_name = manifest.get_package_name()
        launcher_activity = manifest.get_launcher_activity()
        version = manifest.get_version_name()
        result_folder = os.path.join(args.result_folder, package_name+'_'+version+'_'+args.idp_name)


    running_logger.info("Main program starts")
    running_logger.info("apk folder: %s", args.apk_file)
    running_logger.info("appium port:%s", args.appium_port)
    running_logger.info("appium back port:%s", args.appium_back_port)
    running_logger.info("appium system port:%s", args.appium_back_port)
    running_logger.info("proxy port:%s", args.proxy_port)
    main(result_folder, args)

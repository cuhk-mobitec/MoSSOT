"""scripts to run explorer in a batch"""
import unittest
import subprocess
import os
import sys
import glob
import time
from optparse import OptionParser

from lib.manifest import Manifest
from lib.emulator import AndroidEmulator, GenyPlayer
from lib.logger import MyLogger
from lib.myexceptions import ADBActionException, EmulatorTimeoutException
from explorer_test import SSOAndroidTests

logger = MyLogger(name='BatchExplorer').get_logger()
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)


def explore(apk_path, result_folder, emulator, options):
    """explore one single apk"""

    # init
    apk = os.path.basename(apk_path)

    # get apk manifest
    manifest = Manifest(apk_path)
    pkg = manifest.get_package_name()

    # check log
    log_path = os.path.join(result_folder, pkg + '.log')
    if os.path.exists(log_path):
        logger.info('Skip %s', pkg)
        return True
    else:
        os.system('touch {}'.format(log_path))

    # Copy stdout to log file
    tee = subprocess.Popen(["tee", log_path], stdin=subprocess.PIPE, bufsize=0)
    saved_stdout_fd = os.dup(sys.stdout.fileno())
    saved_stderr_fd = os.dup(sys.stderr.fileno())
    os.dup2(tee.stdin.fileno(), sys.stdout.fileno())
    os.dup2(tee.stdin.fileno(), sys.stderr.fileno())

    try:
        # init testcase
        SSOAndroidTests.emulator = emulator
        SSOAndroidTests.idp = options.idp
        SSOAndroidTests.dfs = options.dfs
        SSOAndroidTests.apk = apk_path
        SSOAndroidTests.appium_port = options.port
        SSOAndroidTests.login_twice = not options.no_login_twice
        SSOAndroidTests.sys_port = options.port + 500
        SSOAndroidTests.explore_logout = options.logout
        SSOAndroidTests.result_folder = options.result_folder

        # start exploring
        suite = unittest.TestLoader().loadTestsFromTestCase(SSOAndroidTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)

        if not result.errors:
            restore_fd(saved_stdout_fd, saved_stderr_fd, tee)
            return True

        # handle results
        # TODO: cannot enumerate all exceptions, consider using simpler error handling
        retry_err = ['connect ECONNREFUSED']
        exit_err = ['appium is not running', 'Can not stop emulator']
        logger.error('Exception when initializing %s', pkg)
        msg = result.errors[0][1]
        logger.error(msg)

        # terminate testing if there is something wrong with snapshot
        if 'Fail to load snapshot clean_gpu' in msg:
            exit()

        # check emulator status
        if emulator.status != 'On':
            logger.warning(u'Try to restart emulator')
            emulator.restart()
            try:
                emulator.remove_package(pkg)
            except ADBActionException:
                pass
            except EmulatorTimeoutException:
                pass
            return False

        if err_match(msg, retry_err):
            # retry this particular app
            logger.warning(u'Retry this app')
            os.remove(log_path)
            restore_fd(saved_stdout_fd, saved_stderr_fd, tee)
            return explore(apk_path, result_folder, emulator, options)
        elif err_match(msg, exit_err):
            # has error which need to shop testing
            logger.warning(u'Stop testing')
            restore_fd(saved_stdout_fd, saved_stderr_fd, tee)
            os.remove(log_path)
            try:
                emulator.remove_package(pkg)
            except ADBActionException:
                pass
            except EmulatorTimeoutException:
                pass
            exit()
        restore_fd(saved_stdout_fd, saved_stderr_fd, tee)
        try:
            emulator.remove_package(pkg)
        except ADBActionException:
            pass
        except EmulatorTimeoutException:
            pass
        return False

    except KeyboardInterrupt:
        restore_fd(saved_stdout_fd, saved_stderr_fd, tee)

        skip_flag = raw_input(
            "[BatchExplorer] Skip exploring {} or terminate all? [Skip/term]".format(apk))
        logger.info(u'Removing ...')

        # catch case where interruptions comes after remove is done
        try:
            emulator.remove_package(pkg)
        except ADBActionException:
            pass
        if skip_flag.lower() == 'term':
            os.remove(log_path)
            exit(-1)
        else:
            return False

    # restore fd for other exceptions
    except Exception as err:
        logger.error(err)
        restore_fd(saved_stdout_fd, saved_stderr_fd, tee)


def err_match(msg, pattern_list):
    """error match function"""
    return any([p in msg for p in pattern_list])


def restore_fd(saved_stdout_fd, saved_stderr_fd, tee):
    """
    retore normal output
    """
    time.sleep(0.2)
    sys.stdout.flush()
    sys.stderr.flush()
    os.dup2(saved_stdout_fd, sys.stdout.fileno())
    os.dup2(saved_stderr_fd, sys.stderr.fileno())
    os.close(saved_stdout_fd)
    os.close(saved_stderr_fd)
    tee.terminate()


def main():
    """main logic"""

    # add options
    usage = "usage: %prog [options] apk_folder"
    parser = OptionParser(usage)
    parser.add_option("-i", "--idp", dest="idp", metavar='<idp>',
                      help="specify target IdP, current support: sina, wechat, fb", default=None)
    parser.add_option('--dfs', action="store_true", default=False,
                      help='Use DFS algorithm. By default it will use level-based keyword scan')
    parser.add_option("-n", "--name", dest="name", metavar='<name>',
                      help="specify device name of Android device", default=None)
    parser.add_option("-p", "--port", dest="port", type=int, metavar='port',
                      help="specify port of Appium server", default=4723)
    parser.add_option('--emulator', type=str, metavar='<emulator>', default='android',
                      help='type of emulator: android or genymotion')
    parser.add_option('--no-window', action='store_true', default=False,
                      help='for android emulator only: start emulator without window')
    parser.add_option('--http-proxy', type=str, metavar='<http_proxy>', default=None,
                      help='for android emulator only: set proxy for android emulator')
    parser.add_option('--gpu', type=str, metavar='<gpu>', default='auto',
                      help='for android emulator only: gpu rendering: \
                                auto, host, off, shaderswift-indirect')
    parser.add_option('--logout', action="store_true", default=False,
                      help='Explore logout path as well')
    parser.add_option('--no-login-twice', action="store_true", default=False,
                      help='login twice to distinguish passed app or app need configuration')
    parser.add_option('--result-folder', type=str, metavar='<result_folder>', default='explorer_log',
                        help='result folder for recording explorer log')

    # option parser
    (options, args) = parser.parse_args()
    if len(args) != 1:
        parser.error("incorrect number of arguments")
    apk_folder = args[0]

    # input check
    if not options.idp:
        parser.error("Please specify IdP by --idp or -i")
    if not os.path.exists(apk_folder):
        logger.error('%s not exists', apk_folder)
        exit(-1)

    # result_folder check
    result_folder = os.path.join(os.path.abspath(apk_folder), options.result_folder)
    if not os.path.exists(result_folder):
        os.mkdir(result_folder)

    # init emulator
    if options.emulator == 'android':
        emulator = AndroidEmulator(options.name, options=options)
        emulator.restart()
    elif options.emulator == 'genymotion':
        emulator = GenyPlayer(options.name)
        emulator.restart()
    else:
        logger.error('There is no emulator type named %s', options.emulator)
        exit()

    # start testing
    apk_list = glob.glob(os.path.join(apk_folder, '*.apk'))
    for apk_path in apk_list:
        explore(apk_path, result_folder, emulator, options)


if __name__ == "__main__":
    main()

"""
Emulator Module
"""
import os
import re
import time
import signal
import socket
import subprocess
from tempfile import TemporaryFile
import psutil
from myexceptions import EmulatorInitException, EmulatorActionException, \
    EmulatorTimeoutException, ADBActionException


def detach_daemon(func):
    """decorator to detach subprocess"""

    def wrapper(*args, **kwargs):
        """function wrapper"""
        try:
            # spawn detaching process
            pid = os.fork()
            if pid > 0:
                # parent process, wait for detaching process to finish and then keep running
                os.wait()
                return
        except OSError, err:
            raise EmulatorInitException(err.strerror)

        # detaching process
        os.setsid()

        # spawn real subprocess
        try:
            pid = os.fork()
            if pid > 0:
                # detaching process exit instantly to detach the real subprocess
                os._exit(0)
        except OSError, err:
            raise EmulatorInitException(err.strerror)

        # spawn real subprocess
        func(*args, **kwargs)

        # after the execution of the real subprocess, do not return
        os._exit(0)

    return wrapper


class ADB(object):
    """
    wrapper of commonly used adb commands
    """

    android_path = os.environ['ANDROID_HOME']
    adb = os.path.join(android_path, 'platform-tools', 'adb')

    def __init__(self, serial=None):
        self.serial = serial

    @property
    def param(self):
        """param property of adb instance"""
        if self.serial:
            return '-s {}'.format(self.serial)
        return ''

    def disable_keyboard(self, timeout=20):
        """wrapper to disable keyboard"""
        cmd = '{} {} shell settings put secure show_ime_with_hard_keyboard 0' \
            .format(self.adb, self.param)
        result = self._command(cmd, timeout=timeout)
        if 'Success' in result:
            return True
        return False

    def install_package(self, apk_path, timeout=120):
        """wrapper to install package"""
        cmd = "{} {} install -r '{}'".format(self.adb, self.param, apk_path)
        result = self._command(cmd, timeout=timeout)
        if 'Success' in result:
            return True
        raise ADBActionException(result)

    def remove_package(self, package_name, timeout=60):
        """wrapper to remove package"""
        cmd = '{} {} uninstall {}'.format(self.adb, self.param, package_name)
        result = self._command(cmd, timeout=timeout)
        if 'Success' in result:
            return True
        raise ADBActionException(result)

    def reset_package(self, package_name, timeout=20):
        """wrapper to reset package"""
        cmd = '{} {} shell pm clear {}'.format(self.adb, self.param, package_name)
        result = self._command(cmd, timeout=timeout)
        if 'Success' in result:
            return True
        raise ADBActionException(result)

    def current_package(self, timeout=20):
        """wrapper to get current package"""
        cmd = '{} {} shell dumpsys activity|grep Focus|head -n 1|rev|cut -f 2 -d" "|\
            rev |cut -f 1 -d"/"'.format(self.adb, self.param)
        result = self._command(cmd, timeout=timeout).splitlines()
        if result:
            return result[0]
        raise ADBActionException('Something wrong with the emulator')

    def current_version(self, package_name, timeout=20):
        """wrapper to get version of current package"""
        cmd = '{} {} shell dumpsys package {} |grep versionName|cut -f 2 -d"="' \
            .format(self.adb, self.param, package_name)
        result = self._command(cmd, timeout=timeout).splitlines()
        if result:
            return result[0]
        return None

    def check_adb_status(self, timeout=20):
        """wrapper to check whether the adb server is up"""
        if not self.serial:
            raise ADBActionException('serial is no initialized')
        cmd = '{} devices'.format(self.adb)
        content = self._command(cmd, timeout=timeout)
        device_lines = [x for x in content.splitlines()[1:] if x]
        for line in device_lines:
            if self.serial in line:
                if 'off' in line.lower():
                    return False
                else:
                    return True
        return False

    def check_pm_status(self, timeout=20):
        """wrapper to check whether package manager is up"""
        cmd = '{} {} shell pm list package'.format(self.adb, self.param)
        result = self._command(cmd, timeout=timeout)
        if not result:
            return False
        if 'Error' in result:
            return False
        return True

    def adb_reboot(self, timeout=120):
        """wrapper to reboot android"""
        cmd = '{} {} shell reboot'.format(self.adb, self.param)
        self._command(cmd, timeout=timeout)
        count = 0
        while not self.check_adb_status() and count < 10:
            count += 1
            time.sleep(1)
        return self.check_adb_status()

    def force_stop(self, package):
        """wrapper for adb shell am force-stop"""
        cmd = '{} {} shell am force-stop {}'.format(self.adb, self.param, package)
        self._command(cmd)

    def push(self, src, dst):
        """wrapper for adb push"""
        cmd = '{} {} push {} {}'.format(self.adb, self.param, src, dst)
        result = self._command(cmd)
        if 'pushed' in result:
            return True
        else:
            raise ADBActionException(result)

    def rm(self, path):
        """wrapper to remove file/folder on device"""
        cmd = '{} {} shell rm -r {}'.format(self.adb, self.param, path)
        result = self._command(cmd)
        if result:
            raise ADBActionException(result)
        else:
            return True

    def chmod(self, path, mode='777'):
        """wrapper for adb shell chmod"""
        cmd = '{} {} shell chmod -R {} {}'.format(self.adb, self.param, mode, path)
        result = self._command(cmd)
        if result:
            raise ADBActionException(result)
        else:
            return True

    def root(self):
        """wrapper for adb root"""
        cmd = '{} {} root'.format(self.adb, self.param)
        result = self._command(cmd)
        if 'running as root' in result:
            return True
        else:
            raise ADBActionException(result)

    def ls(self, path):
        """wrapper to list dir"""
        cmd = '{} {} shell ls {}'.format(self.adb, self.param, path)
        result = self._command(cmd)
        if not result:
            raise ADBActionException(result)
        else:
            return result.splitlines()

    @staticmethod
    def _command(cmd, timeout=20):
        """receive message with timeout"""
        tmp = TemporaryFile()
        proc = subprocess.Popen(cmd, shell=True, stdout=tmp, stderr=tmp)
        while timeout > 0:
            ret = proc.poll()
            if ret is not None:
                tmp.seek(0)
                return tmp.read()
            time.sleep(1)
            timeout -= 1
        proc.kill()
        raise EmulatorTimeoutException


class BaseEmulator(object):
    """
    abstract base emulator functionalities
    """

    def __init__(self):
        """init base emualtor"""
        super(BaseEmulator, self).__init__()
        # Check if $ANDROID_HOME are set
        if ('ANDROID_HOME' not in os.environ) or (not os.environ['ANDROID_HOME']):
            raise EmulatorInitException("There's no $ANDROID_HOME env variable.\
                                                         Cannot launch emulator.")

    @staticmethod
    def command(cmd, timeout=120):
        """receive message with timeout"""
        tmp = TemporaryFile()
        proc = subprocess.Popen(cmd, shell=True, stdout=tmp, stderr=tmp)
        while timeout > 0:
            ret = proc.poll()
            if ret is not None:
                tmp.seek(0)
                if ret:
                    raise EmulatorActionException(tmp.read())
                return tmp.read()
            time.sleep(1)
            timeout -= 1
        proc.kill()
        raise EmulatorTimeoutException


class EmulatorConsole(object):
    """communicate with android emulator through emulator console"""
    token = open(os.path.join(os.environ['HOME'], '.emulator_console_auth_token')).read()

    def __init__(self, port):
        super(EmulatorConsole, self).__init__()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.port = port

        # authorize to use emulator console
        self._socket.connect(('localhost', self.port))
        self.recv_until('\r\nOK\r\n')
        self._socket.send('auth {}\n'.format(self.token))
        self.recv_until('\r\nOK\r\n')

    def get_name(self):
        """get name of the emulator"""
        self._socket.send('avd name\n')
        name = self.recv_until('\r\n').strip()
        self.recv_until('OK\r\n')
        return name

    def close(self):
        """close socket"""
        self._socket.close()

    def recv_until(self, data):
        """self implemented receive until"""
        buf = ''
        while not data in buf:
            buf += self._socket.recv(1)
        return buf

    def recv_line(self):
        """self implemented receive line"""
        return self.recv_until('\n')

    def kill(self):
        """wrapper to kill emulator when adb errors"""
        self._socket.send('kill\n')
        res = self.recv_line()
        if 'KO' in res:
            raise EmulatorActionException('Fail to kill emulator\n{}'.format(res))
        self.recv_until('OK\r\n')
        return True

    def list_snapshot(self):
        """wrapper to list android emulator snapshots"""
        self._socket.send('avd snapshot list\n')
        content = self.recv_until('OK\r\n')
        if 'no snapshot available' in content:
            return []
        content = content.splitlines()[1:-1]
        header = re.search(r'(\w*\s?\w*)' + r'\s{2,}(\w*\s?\w*)' * 4, content[0])
        keys = [x.strip().lower().replace(' ', '_') for x in header.groups()]
        snapshots = []
        for i in xrange(1, len(content)):
            result = re.search(r'([\w:-]*)' + r'\s+([\w:-]*)' * 4, content[i])
            snapshots.append(dict(zip(keys, result.groups())))
        return snapshots

    def save_snapshot(self, tag):
        """wrapper to save android emulator snapshots"""
        self._socket.send('avd snapshot save {}\n'.format(tag))
        res = self.recv_line()
        if 'KO' in res:
            raise EmulatorActionException('Fail to save snapshot {}'.format(tag))
        return True

    def delete_snapshot(self, tag):
        """wrapper to delete android emulator snapshot"""
        self._socket.send('avd snapshot del {}\n'.format(tag))
        res = self.recv_line()
        if 'KO' in res:
            raise EmulatorActionException('Fail to delete snapshot {}\n{}'.format(tag, res))
        return True

    def load_snapshot(self, tag, timeout=60):
        """wrapper to load android emulator snapshot"""
        def handler(signum, frame):
            """handler for handling alarm signal"""
            raise EmulatorActionException('Fail to load snapshot {}\n{}'.format(tag, res))
        signal.signal(signal.SIGALRM, handler)
        signal.alarm(timeout)
        self._socket.send('avd snapshot load {}\n'.format(tag))
        res = self.recv_line()
        signal.alarm(0)
        if 'KO' in res:
            raise EmulatorActionException('Fail to load snapshot {}\n{}'.format(tag, res))
        return True


class AndroidEmulator(BaseEmulator, ADB):
    """android emulator abstraction"""

    android_path = os.environ['ANDROID_HOME']
    tools = os.path.join(android_path, 'tools')
    avdmanager = os.path.join(tools, 'bin', 'avdmanager')
    emulator = os.path.join(tools, 'emulator')
    adb = os.path.join(android_path, 'platform-tools', 'adb')

    def __init__(self, device_name=None, android_path=None, options=None):
        # init base emulator
        super(AndroidEmulator, self).__init__()

        # check android tools
        if android_path and android_path.strip() != os.environ['ANDROID_HOME'].strip():
            tools = os.path.join(android_path, 'tools')
            avdmanager = os.path.join(tools, 'bin', 'avdmanager')
            emulator = os.path.join(tools, 'emulator')
            adb = os.path.join(android_path, 'platform-tools', 'adb')
            if os.path.exists(tools) and os.path.exists(avdmanager) and \
                    os.path.exists(emulator) and os.path.exists(adb):
                AndroidEmulator.android_path = android_path
                AndroidEmulator.tools = tools
                AndroidEmulator.avdmanager = avdmanager
                AndroidEmulator.emulator = emulator
                AndroidEmulator.adb = adb
            else:
                raise EmulatorInitException('$ANDROID_HOME is not valid')

        # init
        if options:
            if not isinstance(options, dict):
                options = vars(options)
            self.options = {k: v for k, v in options.iteritems() if \
                            k in ['gpu', 'http_proxy', 'no_window', 'qemu']}

            # check $DISPLAY is set in case emulator window is required
            if 'no_window' not in options:
                if ('DISPLAY' not in os.environ) or (not os.environ['DISPLAY']):
                    raise EmulatorInitException("There's no $DISPLAY env variable.\
                            Cannot launch emulator.")
        else:
            self.options = None
        if device_name:
            # check emulator
            if device_name.strip() not in self._get_names_in_use():
                raise EmulatorInitException('There is no emulator named {}'.format(device_name))

            self.device_name = device_name
            port = self._get_port()
            if port:
                self.port = port
                self.serial = 'emulator-{}'.format(self.port)
            else:
                self.port = None
                self.serial = None
        else:
            ports = self._get_ports_in_use()
            emulators = []
            for port in ports:
                try:
                    con = EmulatorConsole(port)
                    name = con.get_name()
                    con.close()
                    emulators.append((port, name))
                except socket.error:
                    continue
            if not emulators:
                raise EmulatorInitException('no running android emulator')
            if len(emulators) > 1:
                raise EmulatorInitException('more than one running android emulators')
            self.device_name = emulators[0][1]
            self.port = emulators[0][0]
            self.serial = 'emulator-{}'.format(self.port)

    def _get_port(self):
        """get port of the emulator"""
        ports = self._get_ports_in_use()
        for port in ports:
            try:
                con = EmulatorConsole(port)
                name = con.get_name()
                con.close()
                if name == self.device_name:
                    return port
            except socket.error:
                pass
        return None

    def start(self, timeout=60):
        """start emulator"""
        if self.port and self.status == 'On':
            return True

        # try to start emulator
        self._launch_emulator()

        count = 0
        # wait emulator to be up and get port of the emulator
        while self.port is None and count < timeout:
            port = self._get_port()
            if port:
                self.port = port
                self.serial = 'emulator-{}'.format(self.port)
                break
            time.sleep(1)
            count += 1
        # wait for package manager to be up
        while self.status != 'On' and count < timeout:
            time.sleep(1)
            count += 1

        if self.status == 'On':
            return True
        return False

    def stop(self, timeout=20):
        """stop emulator"""
        # emulator is already stopped
        if self.status == 'Off':
            return True

        # send stop command
        cmd = '{} -s {} emu kill'.format(self.adb, self.serial)
        self.command(cmd, timeout)

        # wait for result, cut loop if emulator stops or timeout
        count = 0
        while self.status != 'Off' and count < timeout:
            time.sleep(1)
            count += 1
        if self.status == 'Off':
            return True
        return False

    def kill(self):
        """kill emulator"""

        pid = None

        # look for pid
        for proc in psutil.process_iter():

            procinfo = proc.as_dict(attrs=['pid', 'cmdline'])
            if not procinfo['cmdline']:
                continue

            cmdline = ' '.join(procinfo['cmdline'])
            if cmdline and '@{}'.format(self.device_name) in cmdline and 'qemu-system' in cmdline:
                pid = procinfo['pid']
                break

        # kill process
        if pid:
            os.system('kill -9 {}'.format(pid))

        return True

    def restart(self, timeout=120):
        """restart emulator"""
        try:
            if not self.stop(timeout=timeout / 2):
                self.kill()
        except EmulatorTimeoutException:
            self.kill()
        if not self.start(timeout=timeout / 2):
            return False
        return True

    def delete(self, timeout=20):
        """delete emulator"""
        cmd = '{} delete avd -n {}'.format(self.avdmanager, self.device_name)
        self.command(cmd, timeout)
        return True

    def list_snapshot(self):
        """list existed snapshot"""
        return EmulatorConsole(self.port).list_snapshot()

    def save_snapshot(self, tag):
        """save snapshot"""
        return EmulatorConsole(self.port).save_snapshot(tag)

    def delete_snapshot(self, tag):
        """delete snapshot"""
        return EmulatorConsole(self.port).delete_snapshot(tag)

    def load_snapshot(self, tag):
        """load snapshot"""
        EmulatorConsole(self.port).load_snapshot(tag)
        count = 0
        while self.status != 'On' and count <= 20:
            count += 1
            time.sleep(1)
        if self.status == 'On':
            return True
        return False

    @property
    def status(self):
        """property to indicate whether the emulator is up"""
        if not self.port:
            return 'Off'
        if self.port not in self._get_ports_in_use():
            return 'Off'
        try:
            if not self.check_adb_status():
                return 'Error'
            if not self.check_pm_status():
                return 'Error'
        except EmulatorTimeoutException:
            return 'Error'
        return 'On'

    def _options_param(self):
        """process options"""

        # default params should be enforced
        param = ['-no-boot-anim', '-no-audio', '-selinux', 'permissive', '-no-snapshot']

        # if empty
        if not self.options:
            return param

        # process options
        for key in self.options.keys():
            if self.options[key] is None:
                continue
            if isinstance(self.options[key], bool):
                if self.options[key]:
                    param.append('-' + key.replace('_', '-'))
                else:
                    continue
            elif key == 'qemu':
                continue
            else:
                param.append('-' + key.replace('_', '-'))
                param.append(self.options[key])

        # insert qemu option at the end
        if 'qemu' in self.options.keys():
            key = 'qemu'
            if self.options[key]:
                param.append('-' + key)
                param += self.options[key].split(' ')

        return param

    @detach_daemon
    def _launch_emulator(self):
        subprocess.Popen([self.emulator, '@{}'.format(self.device_name)] + self._options_param(), \
                         stderr=subprocess.STDOUT, stdout=subprocess.PIPE, cwd=AndroidEmulator.tools)

    @staticmethod
    def clone(src, dst, timeout=120):
        """clone emulator"""

        # src and dst check
        avd_path = os.path.join(os.environ['HOME'], '.android', 'avd')
        avd_src = os.path.join(avd_path, '{}.avd'.format(src))
        avd_dst = os.path.join(avd_path, '{}.avd'.format(dst))
        ini_src = os.path.join(avd_path, '{}.ini'.format(src))
        ini_dst = os.path.join(avd_path, '{}.ini'.format(dst))
        if not os.path.exists(avd_src):
            raise EmulatorActionException('source emulator does not exist')
        if os.path.exists(avd_dst):
            raise EmulatorActionException('destination emulator already exists')

        # start cloning
        cmd = 'cp -r {} {}'.format(avd_src, avd_dst)
        BaseEmulator.command(cmd, timeout=timeout)
        os.system('cat {} | sed -e "s/\\/{}/\\/{}/" > {}'.format(ini_src, src, dst, ini_dst))

        # overwrite config file
        conf = os.path.join(avd_dst, 'config.ini')
        # bad implemetation of modify config file
        with open(conf, 'a+') as conf_fd:
            content = conf_fd.read()
            if 'hw.keyboard' not in content:
                conf_fd.write('hw.keyboard=yes\n')
            if 'hw.lcd.width' not in content:
                conf_fd.write('hw.lcd.width=1080\n')
            if 'hw.lcd.height' not in content:
                conf_fd.write('hw.lcd.height=1920\n')
            if 'hw.lcd.depth' not in content:
                conf_fd.write('hw.lcd.depth=16\n')
            if 'hw.lcd.density' not in content:
                conf_fd.write('hw.lcd.density=480\n')
            if 'disk.dataPartition.size' not in content:
                conf_fd.write('disk.dataPartition.size = 4g')
        return True

    @staticmethod
    def _get_names_in_use():
        """method to get device names in use"""
        cmd = '{} list avd'.format(AndroidEmulator.avdmanager)
        content = BaseEmulator.command(cmd, timeout=20)
        names = [x.split(':')[-1].strip() for x in content.splitlines() if 'Name' in x]
        return names

    @staticmethod
    def _get_ports_in_use():
        """method to get ports in use"""
        # check devices
        cmd = '{} devices'.format(AndroidEmulator.adb)
        content = BaseEmulator.command(cmd, timeout=20)
        # in case adb-server just restart and bring some extra log
        content = content.split('successfully\n')[-1]
        # parse ports
        device_lines = [x for x in content.splitlines()[1:] if x]
        ports = [int(x.split('\t')[0].split('-')[1]) for x in device_lines]
        return ports


class GenyPlayer(BaseEmulator, ADB):
    """genymotion player abstraction"""

    gmtool = 'gmtool'

    def __init__(self, device_name=None, gmtool_path=None):
        # init base emulator
        super(GenyPlayer, self).__init__()

        # Set gmtool PATH
        if gmtool_path and os.path.exists(gmtool_path):
            GenyPlayer.gmtool = gmtool_path
        if 'Version' not in self.command('{} version'.format(self.gmtool)):
            raise EmulatorInitException("gmtool calling error (check $PATH)")

        players_info = self._get_players_info()
        if device_name:
            # check player
            if device_name not in players_info:
                raise EmulatorInitException('There is no emulator named {}'.format(device_name))

            self.device_name = device_name
            self.port = 5555
            if players_info[device_name]['state'] == 'On':
                self.serial = '{}:{}'.format(players_info[device_name]['adb serial'], self.port)
            else:
                self.serial = None
        else:
            players = [players_info[name] for name in players_info \
                       if players_info[name]['state'] == 'On']
            if not players:
                raise EmulatorInitException('no running genymotion player')
            if len(players) > 1:
                raise EmulatorInitException('more than one running genymotion players')
            self.device_name = players[0]['name']
            self.port = 5555
            self.serial = '{}:{}'.format(players[0]['adb serial'], self.port)

    def start(self, timeout=60):
        """start genymotion player"""
        if self.status != 'On':
            # start emulator
            self._launch_emulator()

            # wait for emulator to be up
            count = 0
            while self._get_players_info()[self.device_name]['adb serial'] == '0.0.0.0' \
                    and count < timeout:
                count += 1
                time.sleep(1)

            self.serial = '{}:{}'.format( \
                self._get_players_info()[self.device_name]['adb serial'], self.port)

            # wait for emulator to be up
            count = 0
            while self.status != 'On' and count < 10:
                count += 1
                time.sleep(1)
            if self.status == 'On':
                return True
            return False
        return True

    def stop(self, timeout=20):
        """stop genymotion player"""
        if self.status != 'Off':
            cmd = "{} admin stop '{}'".format(self.gmtool, self.device_name)
            self.command(cmd, timeout=timeout)
            return True
        return True

    def kill(self, timeout=60):
        """kill genymotion player"""
        if self._get_players_info()[self.device_name]['state'] != 'Off':
            if self.check_adb_status():
                self.adb_reboot()
            cmd = "{} admin stop '{}'".format(self.gmtool, self.device_name)
            self.command(cmd, timeout=timeout / 2)
            if self._get_players_info()[self.device_name]['state'] != 'Off':
                raise EmulatorActionException('Can not stop emulator')
            return True
        return True

    def restart(self, timeout=120):
        """restart genymotion player"""
        if not self.kill(timeout=timeout / 2):
            return False
        if not self.start(timeout=timeout / 2):
            return False
        return True

    def delete(self, timeout=20):
        """delete genymotion player"""
        if self.status == 'Off':
            cmd = "{} admin delete '{}'".format(self.gmtool, self.device_name)
            self.command(cmd, timeout=timeout)
            return True
        return False

    @property
    def status(self):
        """property to indicate whether the emulator is up"""
        status = self._get_players_info()[self.device_name]['state']
        if status == 'Off':
            return 'Off'
        if not self.check_adb_status():
            return 'Error'
        if not self.check_pm_status():
            return 'Error'
        return 'On'

    @staticmethod
    def clone(src, dst, timeout=120):
        """clone genymotion player"""

        # check src and dst emulators
        players_info = GenyPlayer._get_players_info()
        if src not in players_info:
            raise EmulatorActionException('source emulator does not exist')
        if dst in players_info:
            raise EmulatorActionException('destination emulator already exists')

        cmd = "{} admin clone '{}' '{}'".format(GenyPlayer.gmtool, src, dst)
        BaseEmulator.command(cmd, timeout=timeout)
        return True

    @detach_daemon
    def _launch_emulator(self):
        cmd = "{} admin start '{}'".format(self.gmtool, self.device_name)
        self.command(cmd, timeout=60)

    @staticmethod
    def _get_players_info():
        """method to get all genymotion players infomation like state, serial, uuid"""
        result = {}
        cmd = "{} admin list".format(GenyPlayer.gmtool)
        content = BaseEmulator.command(cmd)
        content = content.splitlines()
        header = re.search(r'(.*)\|(.*)\|(.*)\|(.*)', content[0])
        if header:
            keys = [key.strip().lower() for key in header.groups()]
            content = content[1:]
            for line in content:
                if re.match(r'.*\|.*\|.*\|.*', line):
                    tmp = re.search(r'(.*)\|(.*)\|(.*)\|(.*)', line)
                    values = [value.strip() for value in tmp.groups()]
                    player_info = dict(zip(keys, values))
                    result[player_info['name']] = player_info
        return result

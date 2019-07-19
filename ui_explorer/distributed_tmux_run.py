"""
script to run multiple test instances at ease
"""
from subprocess import check_output
from random import randint
import sys


def sh_wrapper(cmd):
    """shell wrapper"""
    return check_output(cmd, shell=True)


def list_devices():
    """list android emulators"""
    output = sh_wrapper("adb devices |awk 'NR>1{print $1}' |sed '$d'")
    return output.split()


def get_idle_devices(devices):
    """get idle android emulators"""
    idle = []
    for device in devices:
        ret = sh_wrapper("adb -s {} shell 'cat /tmp/occupied'".format(device))
        if ret != '1':
            idle.append(device)
    return idle


def setup_tmux(devices, idp, folder):
    """launch batch testing through tmux"""
    devices = sorted(devices)
    for i, device in enumerate(devices):

        cmd = 'python batch_explorer.py -i %s -p {port} -s {device} %s' % (idp, folder)

        if ':' in device:
            port = 10000 + int(device.split(':')[0].split('.')[-1])
        elif 'emulator-' in device:
            port = 10000 + int(device.split('-')[-1])
        else:
            port = 11000 + randint(1, 999)

        opt = {'device': device, 'port': port}
        tmux_controls = [
                "tmux new-window -n '{port}'",
                "tmux send-keys -t '{port}' '%s' 'C-m'" % cmd,
                "tmux split-window -t '{port}'",
                "tmux send-keys -t '{port}' 'appium -p {port}' 'C-m'",
                'tmux select-window -t 0'
              ]
        map(sh_wrapper, [c.format(**opt) for c in tmux_controls])


def main():
    """
    main logic
    """
    if len(sys.argv) == 3:
        idp = sys.argv[1]
        folder = sys.argv[2]
    else:
        print "Usage: python %s IdP APK_FOLDER" % sys.argv[0]
        return False
    sh_wrapper('tmux set-option -g allow-rename off')
    sh_wrapper('tmux set -g remain-on-exit on')
    devices = list_devices()
    devices = get_idle_devices(devices)
    setup_tmux(devices, idp, folder)


if __name__ == '__main__':
    main()

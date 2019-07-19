import os
import glob
import json

if os.path.exists('Configs') or os.path.exists('APKs'):
    print 'Configs or APKs exists...'
    print 'exit'
    exit()
os.mkdir('Configs')
os.mkdir('APKs')

configs = glob.glob('apk/explorer_log/*.json')

for config in configs:
    package = os.path.basename(config[:-5])
    conf_j = json.load(open(config, 'r'))
    version = conf_j['version']
    apks = glob.glob('/nfs/oauth/backup/APKdownloaded/apkpure/*/{}*.apk'.format(package))
    if len(apks) > 1:
        apks = glob.glob('/nfs/oauth/backup/APKdownloaded/apkpure/*/{}_{}.apk'.format(package, version))
        print apks

    cmd = 'cp "{}" "APKs"'.format(apks[0])
    os.system(cmd)
    cmd = 'cp "{}" "Configs"'.format(config)
    os.system(cmd)

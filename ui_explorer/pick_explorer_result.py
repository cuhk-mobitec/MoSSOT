"""
Screen explorer result
"""
import os
import sys
from shutil import copy

def main():
    """
    main logic
    """
    if not len(sys.argv) == 3:
        print 'Usage: %s apk_folder output_folder' % sys.argv[0]
        exit(-1)

    apkdir = sys.argv[1]
    outdir = sys.argv[2]
    outapk = os.path.join(outdir, 'APKs/')
    outconf = os.path.join(outdir, 'configs/')
    if not os.path.exists(outapk):
        os.mkdir(outapk)
    if not os.path.exists(outconf):
        os.mkdir(outconf)

    results = [os.path.basename(f) for f in os.listdir(os.path.join(apkdir,\
                                'explorer_log/')) if f.endswith('.json')]
    pkgs = [r.rsplit('.', 1)[0] for r in results]
    apks = [os.path.basename(f) for f in os.listdir(apkdir) if f.endswith('.apk')]
    for pkg in pkgs:
        matched = [apk for apk in apks if pkg+'_' in apk]
        best_match = min(matched, key=len)
        print best_match
        copy(os.path.join(apkdir, best_match), outapk)
        copy(os.path.join(apkdir, 'explorer_log', pkg+'.json'), outconf)

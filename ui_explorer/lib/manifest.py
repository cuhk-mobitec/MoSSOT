# -*- coding: utf-8 -*-
import re
import subprocess
from myexceptions import ManifestParsingException


class Manifest:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.content = self.__dump_manifest(apk_path)

    @staticmethod
    def __dump_manifest(apk_path):
        cmd = "aapt d xmltree '{0}' AndroidManifest.xml".format(apk_path)
        p = subprocess.Popen(cmd, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        if 'command not found' in out:
            raise ManifestParsingException('Command "aapt" not available, have you add it to PATH?')
        if 'ERROR: dump failed' in out:
            raise ManifestParsingException(u'Dump failed. Maybe invalid APK file: {}'.format(apk_path))
        return out.decode('utf-8')  # 内部统一使用unicode

    @staticmethod
    def __parse_xmltree(xmltree):
        activities = []
        lines = iter(xmltree.splitlines())
        line = lines.next()
        while True:
            m = re.match(r'^( +)E: activity', line)
            if m:
                indent_num = int(len(m.group(1)))
                pattern = '^ {%d,}.:' % (indent_num+2)
                act_content = [line]
                while True:
                    try:
                        line = lines.next()
                    except StopIteration:
                        break
                    if re.match(pattern, line):
                        act_content.append(line)
                    else:  # not in sub level
                        break
                act_content = '\n'.join(act_content)
                activities.append(act_content)
            else:  # not into sub level
                try:
                    line = lines.next()
                except StopIteration:
                    break
        return activities

    def get_package_name(self):
        try:
            package = re.findall(r'package="(.*?)"', self.content)[0]
        except IndexError:
            raise ManifestParsingException("Cannot parse package name from {}".format(self.apk_path))
        return package

    def get_version_name(self):
        try:
            match = re.findall(r'android:versionName\(0x0101021c\)="(.*?)"', self.content)
            if match:
                version_name = match[0]
            else:
                code = re.findall(r'android:versionCode\(0x0101021b\)=\(.*\)(0x[0-9a-f]+)', self.content)[0]
                version_name = "ver_code_{}".format(int(code, 16))
        except IndexError:
            raise ManifestParsingException("Cannot parse package version from {}".format(self.apk_path))
        return version_name

    def get_launcher_activity(self):
        for act in self.__parse_xmltree(self.content):
            if 'android.intent.category.LAUNCHER' in act:
                launcher = re.findall(r'E: activity.*?name.*?="(.*?)"', act, re.DOTALL)[0]
                return launcher
        return None

    def get_activity_names(self):
        act_list = re.findall(r'E: activity.*?name.*?="(.*?)"', self.content, re.DOTALL)
        return act_list

    def search_login_activities(self, keywords=None, blacklist=None):
        """Return a list of login-like activity names"""
        act_list = self.get_activity_names()

        # all activities contains keyword
        if keywords is None:
            keywords = ['login', 'signin', 'signup']
        match = lambda s: any([(kw in s.lower().split('.')[-1]) for kw in keywords])
        filtered1 = filter(match, act_list)

        # those related to target package
        if blacklist is None:
            blacklist = ['com', 'android', 'view']
        def related(act):
            common_word = set(self.get_package_name().lower().split('.')).intersection(act.lower().split('.'))
            return len(set(blacklist).union(common_word) - set(blacklist)) > 0
        filtered2 = filter(related, filtered1)
        return filtered2

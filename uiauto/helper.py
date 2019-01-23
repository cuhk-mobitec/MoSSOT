# -*- coding: utf-8 -*-
from __future__ import division

import json

from myexceptions import *


class PathJsonBuilder(object):
    def __init__(self, package=None, version=None, idp=None):
        self.package = package
        self.version = version
        self.idp = idp
        self.home_activity = None
        self.status = ''
        self.paths = {}

    def update_path(self, path_name, stops=None, dest=None):
        # nothing to update
        if not stops and not dest:
            return
        if path_name not in self.paths:
            self.paths[path_name] = {}
        # keyword list
        if stops and isinstance(stops, list):
            stops = [{"keyword": kw} for kw in stops]
            self.paths[path_name]["stops"] = stops
        # single keyword destination
        if dest and isinstance(dest, str):
            self.paths[path_name]["destination"] = dest

    def update_home_activity(self, activity_name):
        if activity_name:
            self.home_activity = activity_name

    def update_status(self, status):
        if status:
            self.status = status

    def update_destination(self, path_name, key, value):
        if path_name not in self.paths:
            self.paths[path_name] = {}
        if 'destination' not in self.paths[path_name]:
            self.paths[path_name]['destination'] = {}
        if key and value:
            self.paths[path_name]['destination'][key] = value

    def dump(self):
        if not (self.package and self.version and self.paths):
            raise PathJsonBuilderException('Cannot dump config: incomplete information. \n'
                                           'package: {0}, version: {1}')
        config = {
            "package": self.package,
            "version": self.version,
            "paths": self.paths,
            "idp": self.idp,
            "status": self.status
        }
        if self.home_activity:
            config['home_activity'] = self.home_activity
        return json.dumps(config, indent=4, sort_keys=True, ensure_ascii=False)

    def dump_path(self, path_name):
        if path_name not in self.paths:
            raise PathJsonBuilderException('Path with name {} not exist'.format(path_name))
        return json.dumps(self.paths[path_name])

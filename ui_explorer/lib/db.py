from pymongo import MongoClient, ReturnDocument
from logger import logger
import json


class DB(object):
    def __init__(self):
        # client = MongoClient('localhost', 27017)
        client = MongoClient('oauth.ie.cuhk.edu.hk', 27017)
        self.configs = client.uiauto.configs

    def fetch_config(self, package, idp, snapshot=None, version=None, version_strict=False):
        query = {'package': package, 'idp': idp}
        if snapshot is not None:
            query['snapshot'] = snapshot
        if version:
            query['version'] = version

        result = self.configs.find_one(query)
        if not version_strict and not result:
            query.pop('version')
            result = self.configs.find_one(query)
            if result:
                logger.warning(u'No config for {0} with IdP {3} of version {1} in DB, use {2} instead'
                               .format(package, version, result['version'], idp))
        if not result:
            logger.error(u'No config for {0} with IdP {1} in DB'.format(package, idp))
        return result

    def update_config(self, package, idp, data, version=None, version_strict=False):
        query = {'package': package, 'idp': idp}
        if version:
            query['version'] = version

        result = self.configs.find_one_and_update(query, {'$set': data},
                                                  return_document=ReturnDocument.AFTER)
        if not version_strict and not result:
            query.pop('version')
            result = self.configs.find_one_and_update(query, {'$set': data},
                                                      return_document=ReturnDocument.AFTER)
            if result:
                logger.warning(u'No config for {0} with IdP {3} of version {1} in DB, update on {2} instead'
                               .format(package, version, result['version'], idp))
        if not result:
            logger.error(u'No config for {0} with IdP {1} in DB'.format(package, idp))
        return result

    # untested, will be used by Explorer
    def insert_config(self, config):
        if isinstance(config, str):
            config = json.loads(config)
        self.configs.insert_one(config)
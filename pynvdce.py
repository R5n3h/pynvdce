import urllib
import logging
import gzip
import sys
import time
import json
import os

# Create logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)
logger.addHandler(handler)

# Define URLs
CVE_20_MODIFIED_URL = 'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz'
PACKAGES_LOCK_JSON = './package-lock.json'
COMPOSER_LOCK_JSON = './composer.lock'
OVERWRITE_CVE_FEED_FILE = True

# NVDFeed class
class NVDFeed:
    cve_file = 'nvdcve-1.0-modified.json.gz'
    cve_dict = None

    def __init__(self):
        cve_exists = os.path.exists(self.cve_file)
        if not cve_exists or OVERWRITE_CVE_FEED_FILE:
            self.download()
        else:
            self.extract()

    def __logger__(self, msg):
        logger.info("%s: %s" % (self.__class__.__name__, msg))

    def download(self):
        self.__logger__('Start downloading...')
        cve_file = urllib.URLopener()
        cve_file.retrieve(CVE_20_MODIFIED_URL, self.cve_file)
        self.__logger__('Finish downloading.')
        self.extract()

    def extract(self):
        self.__logger__('Start extracting file...')
        with gzip.open(self.cve_file, 'rb') as f:
            self.cve_file_content = f.read()
        self.__logger__('Finish extracting file. (size: %s)' % len(self.cve_file_content))
        self.cve_dict = json.loads(self.cve_file_content)

    def search_packages(self, packages):
        cve_items = self.cve_dict.get('CVE_Items', None)
        if not cve_items:
            raise Exception('CVE_Items not found. Check the CVE Feed')

        matches = []
        for cve_item in cve_items:
            baseSeverity = None
            cve = cve_item.get('cve', None)
            if not cve:
                continue

            configurations = cve_item.get('configurations', None)
            if not configurations:
                continue

            impact = cve_item.get('impact', None)
            if impact:
                try:
                    severity = impact['baseMetricV2']['severity']
                    impactScore = impact['baseMetricV2']['impactScore']
                except Exception as e:
                    severity = None
                    impactScore = None

            nodes = configurations.get('nodes', None)
            if not nodes:
                continue

            nodes = nodes[0]
            cpe = nodes.get('cpe', None)
            if not cpe:
                continue

            for e in cpe:
                cpe22Uri = e.get('cpe22Uri', None)
                versionEndExcluding = e.get('versionEndExcluding', None)
                versionEndIncluding = e.get('versionEndIncluding', None)
                if cpe22Uri:
                    cpe_uri = cpe22Uri.split(':')
                    ver = cpe_uri[4] if len(cpe_uri) > 4 and cpe_uri[4] != '' else None
                    for p in packages:
                        if p == cpe_uri[3]:
                            match = {
                                'package': p,
                                'cpe22Uri': cpe22Uri,
                                'cve': cve['CVE_data_meta']['ID'],
                                'version': ver,
                                'versionEndExcluding': versionEndExcluding,
                                'versionEndIncluding': versionEndIncluding,
                                'impact': {
                                    'severity': severity,
                                    'impactScore': impactScore
                                }
                            }
                            self.__logger__(match)
                            matches.append(match)
        return matches

class LockPackages:
    files = []
    packages = []
    full_packages = []

    def __init__(self):
        self.check_packages_type()
        self.prepare_dependencies()
        self.__logger__('Package lock file(s) is %s' % ','.join(self.files))
        self.__logger__('Found %d packages in project' % len(self.packages))

    def __logger__(self, msg):
        logger.info("%s: %s" % (self.__class__.__name__, msg))

    def check_packages_type(self):
        if os.path.exists(COMPOSER_LOCK_JSON):
            self.files.append(COMPOSER_LOCK_JSON)

        if os.path.exists(PACKAGES_LOCK_JSON):
            self.files.append(PACKAGES_LOCK_JSON)

    def prepare_dependencies(self):
        packages = []
        for _file in self.files:
            if _file == PACKAGES_LOCK_JSON:
                packages_json = json_file_to_dict(PACKAGES_LOCK_JSON)
                if 'dependencies' not in packages_json:
                    raise Exception('No dependencies found. YOU GOOD TO GO!')

                dependencies = packages_json.get('dependencies')
                packages = packages + dependencies.keys()
                # self.full_packages = self.full_packages + dependencies

            if _file == COMPOSER_LOCK_JSON:
                packages_json = json_file_to_dict(COMPOSER_LOCK_JSON)
                if 'packages' not in packages_json:
                    raise Exception('No dependencies found. YOU GOOD TO GO!')

                _packages = packages_json.get('packages')
                # self.full_packages = self.full_packages + _packages
                for _pack in _packages:
                    p = _pack['name'].split('/')
                    packages.append(p[1])

        self.packages = packages

    def get(self):
        return self.packages

# json to dict
def json_file_to_dict(file):
    data = None
    with open(file) as f:
        data = json.load(f)

    if not data:
        raise Exception('Cannot convert file to dict.')

    return data

# Main
if __name__ == '__main__':
    start_time = time.time()
    feed = NVDFeed()
    lock_packages = LockPackages()
    packages = lock_packages.get()
    matches = feed.search_packages(packages)
    end_time = time.time()

    duration = (end_time - start_time)
    logger.info("MAIN: Action took %04f seconds" % duration)

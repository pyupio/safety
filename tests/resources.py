from safety.models import Package, Vulnerability, SafetyRequirement
from packaging.specifiers import SpecifierSet

# JSON report loaded
VALID_REPORT = {'report_meta': {'scan_target': 'environment', 'scanned': ['/usr/local/lib/python3.9/site-packages'],
                                'api_key': True, 'packages_found': 50, 'local_database_path_used': None,
                                'timestamp': '2022-04-30 08:16:30',
                                'safety_version': '2.0b1'},
                'scanned_packages': {'safety': {'name': 'safety', 'version': '2.0b1',
                                                'requirements': [{
                                                    "raw": "safety==2.0b1",
                                                    "extras": [],
                                                    "marker": None,
                                                    "name": "safety",
                                                    "specifier": "==2.0b1",
                                                    "url": None
                                                }]
                                                },
                                     'click': {'name': 'click', 'version': '8.0.4',
                                               'requirements': [{
                                                   "raw": "click==8.0.4",
                                                   "extras": [],
                                                   "marker": None,
                                                   "name": "click",
                                                   "specifier": "==8.0.4",
                                                   "url": None
                                               }]},
                                     'insecure-package': {'name': 'insecure-package', 'version': '0.1.0',
                                                          'requirements': [
                                                              {
                                                                  "raw": "insecure-package==0.1.0",
                                                                  "extras": [],
                                                                  "marker": None,
                                                                  "name": "insecure-package",
                                                                  "specifier": "==0.1.0",
                                                                  "url": None
                                                              }]}},
                'affected_packages': {'insecure-package': {'name': 'insecure-package', 'version': '0.1.0',
                                                           'requirements':
                                                               [
                                                                   {
                                                                       "raw": "insecure-package==0.1.0",
                                                                       "extras": [],
                                                                       "marker": None,
                                                                       "name": "insecure-package",
                                                                       "specifier": "==0.1.0",
                                                                       "url": None
                                                                   }
                                                               ],
                                                           'found': '/usr/local/lib/python3.9/site-packages',
                                                           'insecure_versions': ['0.1.0'], 'secure_versions': [],
                                                           'latest_version_without_known_vulnerabilities': '',
                                                           'latest_version': '0.1.0',
                                                           'more_info_url': 'https://pyup.io/packages/pypi/insecure-package/'}},
                'announcements': [], 'vulnerabilities': [
        {'vulnerability_id': '25853', 'package_name': 'insecure-package', 'ignored': False, 'ignored_reason': None,
         'ignored_expires': None, 'vulnerable_spec': ['<0.2.0'],
         'all_vulnerable_specs': ['<0.2.0'], 'analyzed_version': '0.1.0', 'analyzed_requirement': {
                                                                  "raw": "insecure-package==0.1.0",
                                                                  "extras": [],
                                                                  "marker": None,
                                                                  "name": "insecure-package",
                                                                  "specifier": "==0.1.0",
                                                                  "url": None
                                                              },
         'advisory': 'This is an insecure package with lots of exploitable security vulnerabilities.',
         'is_transitive': False, 'published_date': '2021-Apr-14',
         'fixed_versions': [''], 'closest_versions_without_known_vulnerabilities': [],
         'resources': ['https://pypi.org/project/insecure-package'],
         'CVE': None,
         'severity': None, 'affected_versions': ['0.1.0'],
         'more_info_url': 'https://pyup.io/vulnerabilities/PVE-2021-25853/25853/'}],
                'ignored_vulnerabilities': [],
                'remediations': {
                    'insecure-package': {
                        'requirements': {
                            '==0.1.0': {
                                'version': '0.1.0',
                                'requirement': {
                                    "raw": "insecure-package==0.1.0",
                                    "extras": [],
                                    "marker": None,
                                    "name": "insecure-package",
                                    "specifier": "==0.1.0",
                                    "url": None
                                },
                                'vulnerabilities_found': 1, 'recommended_version': None,
                                'other_recommended_versions': [],
                                'more_info_url': 'https://pyup.io/packages/pypi/insecure-package/'
                            },
                        }}}}


# Python objects
SCANNED_PACKAGES = {
    'safety': Package(name='safety', version='2.0b1', requirements=[SafetyRequirement('safety==2.0b1')]),
    'click': Package(name='click', version='8.0.4', requirements=[SafetyRequirement('click==8.0.4')]),
    'insecure-package': Package(name='insecure-package', version='0.1.0',
                                requirements=[SafetyRequirement('insecure-package==0.1.0')]),
}

VULNS = [Vulnerability(vulnerability_id='25853', package_name='insecure-package',
                       pkg=Package(name='insecure-package', version='0.1.0',
                                   requirements=[SafetyRequirement('insecure-package==0.1.0')],
                                   found=None,
                                   insecure_versions=[], secure_versions=[],
                                   latest_version_without_known_vulnerabilities=None,
                                   latest_version=None,
                                   more_info_url=None),
                       ignored=False, ignored_reason=None, ignored_expires=None, vulnerable_spec=['<0.2.0'],
                       all_vulnerable_specs=['<0.2.0'], analyzed_version='0.1.0',
                       analyzed_requirement=SafetyRequirement('insecure-package==0.1.0'),
                       advisory='This is an insecure package with lots of exploitable security vulnerabilities.',
                       is_transitive=False, published_date='2021-Apr-14', fixed_versions=[''],
                       closest_versions_without_known_vulnerabilities=[],
                       resources=['https://pypi.org/project/insecure-package'],
                       CVE=None, severity=None, affected_versions=['0.1.0'],
                       more_info_url='https://pyup.io/vulnerabilities/PVE-2021-25853/25853/')]


REMEDIATIONS = {
    'insecure-package': {
        '==0.1.0': {
            'version': '0.1.0',
            'requirement': SafetyRequirement('insecure-package==0.1.0'),
            'vulnerabilities_found': 1, 'recommended_version': None,
            'other_recommended_versions': [],
            'more_info_url': 'https://pyup.io/packages/pypi/insecure-package/'
        },
    }
}

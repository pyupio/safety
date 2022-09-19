# Changelog

All notable changes to this project will be documented in this file.

The format is partly based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [PEP 440](https://peps.python.org/pep-0440/)

## [2.2.0] - 2022-09-19
- Safety starts to use dparse to parse files, now Safety supports mainly Poetry and Pipenv lock files plus other files supported by dparse.
- Added logic for custom integrations like pipenv check.
- The --db flag is compatible remote sources too.
- Added more logging
- Upgrade dparse dependency to avoid a possible ReDos security issue
- Removed Travis and Appveyor, the CI/CD was migrated to GitHub Actions

## [2.1.1] - 2022-07-18
- Fix crash when running on systems without git present (Thanks @andyjones)

## [2.1.0] - 2022-07-14

### Summary:
- Improved error messages & fixed issues with proxies
- Fixed license command
- Added the ability for scan outputs to be sent to pyup.io. This will only take effect if using an API key, the feature is enabled on your profile, and the `--disable-audit-and-monitor` is not set
- Added the ability to have a Safety policy file set centrally on your pyup.io profile. This remote policy file will be used if there's no local policy file present, otherwise a warning will be issued.

### Updated outputs:
- Text & screen output: If a scan has been logged, this is now mentioned in the output.
- JSON output: The JSON output now includes git metadata about the folder Safety was run in. It also includes a version field, and telemetry information that would be sent separately. There are no breaking changes in the output.

### New inputs:
- New command line flags
    - The `--disable-audit-and-monitor` flag can be set to disable sending a scan's result to pyup.io
    - The `--project` flag can be set to manually specify a project to associate these scans with. By default, it'll autodetect based on the current folder and git.

## [2.0.0] - 2022-06-28

### Summary:
- Compared to previous versions, Safety 2.0 will be a significant update that includes new features and refactors, resulting in breaking changes to some inputs and outputs.

### Updated outputs:
- Text & screen output: Upgraded the text and screen outputs, removing the old table style and adding new data and formats to vulnerabilities.
- JSON output: New and updated JSON output (breaking change). Safety adds all the possible information in the JSON report. The structure of this JSON file has been improved.
- Improved the support for exit codes. There are now custom exit codes with detailed information about the result. Examples include: VULNERABILITIES_FOUND and INVALID_API_KEY.
- Added remediations (fix recommendations) sections to outputs. Now, Safety will suggest the steps to fix a detected vulnerability when an API key is used.
- Added new summary meta-data data to the reports showing the Safety version used, the dependencies found, the timestamp, the target scanned, and more. These data are included in the text, screen, and JSON output for improved audit capabilities.
- Added more info per vulnerability, including URLs to read more about a vulnerability and/or a package.

###New command line flags:
- New command line flags
    - The `--output` flag replaces `--bare`, `--text`, `--screen`, and `--json` flags. In this new release, examples would be: `--output json` or `--output bare`.
    - The `--continue-on-error` flag suppresses non-zero exit codes to force pass CI/CD checks, if required.
    - The `--debug` flag allows for a more detailed output.
    - The `--disable-telemetry` flag has been added to disable telemetry data
    - The `--policy-file` flag to include a local security policy file. This file (called `.safety-policy.yml`, found in either the root directory where Safety is being run or in a custom location) is based on YAML 1.2 and allows for:
        - Ignoring individual vulnerabilities with optionally a note and an expiry date.
        - Filtering vulnerabilities by their CVSS severity. (CVSS data is only available for some paid accounts.)

### Other
- Dropped support for Python < 3.6
- The free version of the Safety vulnerability database is downloaded from a public S3 bucket (via PyUp.io) and no longer from GitHub. This free database is only updated once a month and is not licensed for commercial use.
- Telemetry data will be sent with every Safety call. These data are anonymous and not sensitive. This includes the Python version, the Safety command used (`check`/`license`/`review`), and the Safety options used (without their values). Users can disable this functionality by adding the `--disable-telemetry` flag.
- Added validations to avoid the use of exclusive options.
- Added announcements feature to receive informative or critical messages from the PyUp Safety team.
- Increased test coverage.
- Now Safety can be used as a dependency in your code
- Added Safety as a Github Action
- Improved the help text in the CLI
- Added the --save-json flag


## [2.0b5] - 2022-06-24

### Summary:
- Removed the click context use, so Safety can be used in non-CLI cases
- Added Safety as a Github Action
- Improved the CLI help copy
- Increased the coverage

## [2.0b4] - 2022-06-16

### Summary:
- Fixed issue with paddings and margins at specific console outputs like Github actions console
- Added the --save-json flag and other aliases
- Added a fallback size for the terminal size function, related to https://bugs.python.org/issue42174
- Suppressed the announcements sent to stderr when it is running via 'run' environments


## [2.0b3] - 2022-05-30

### Summary:
- Fixed issue in the Screen and Text report due to the remediations rendering for the users using an API Key
- Improved the handling exception in the generate command


## [2.0b2] - 2022-05-27

### Summary:
- This version of Safety is not stable; it is only a beta, pre-release version.
- Compared to previous versions, Safety 2.0 will be a significant update that includes new features and refactors, resulting in breaking changes to some inputs and outputs.
- Improved grammar and formatting in the whole code
- Improved the exception handling in the .yml policy file parsing
- Improved the JSON output following the customers/users feedback - (This is a breaking change between beta releases)
- Added the generate command
- Added the validate command

## [2.0b1] - 2022-05-08

### Summary:
- This version of Safety is not stable; it is only a beta, pre-release version.
- Compared to previous versions, Safety 2.0 will be a significant update that includes new features and refactors, resulting in breaking changes to some inputs and outputs.

### Updated outputs:
- Text & screen output: Upgraded the text and screen outputs, removing the old table style and adding new data and formats to vulnerabilities.
- JSON output: New and updated JSON output (breaking change). Safety adds all the possible information in the JSON report. The structure of this JSON file has been improved.
- Improved the support for exit codes. There are now custom exit codes with detailed information about the result. Examples include: VULNERABILITIES_FOUND and INVALID_API_KEY.
- Added remediations (fix recommendations) sections to outputs. Now, Safety will suggest the steps to fix a detected vulnerability when an API key is used.
- Added new summary meta-data data to the reports showing the Safety version used, the dependencies found, the timestamp, the target scanned, and more. These data are included in the text, screen, and JSON output for improved audit capabilities.
- Added more info per vulnerability, including URLs to read more about a vulnerability and/or a package.

### New inputs:
- New command line flags
    - The `--output` flag replaces `--bare`, `--text`, `--screen`, and `--json` flags. In this new release, examples would be: `--output json` or `--output bare`.
    - The `--continue-on-error` flag suppresses non-zero exit codes to force pass CI/CD checks, if required.
    - The `--debug` flag allows for a more detailed output.
    - The `--disable-telemetry` flag has been added to disable telemetry data
    - The `--policy-file` flag to include a local security policy file. This file (called `.safety-policy.yml`, found in either the root directory where Safety is being run or in a custom location) is based on YAML 1.2 and allows for:
        - Ignoring individual vulnerabilities with optionally a note and an expiry date.
        - Filtering vulnerabilities by their CVSS severity. (CVSS data is only available for some paid accounts.)

### Other
- Dropped support for Python < 3.6
- The free version of the Safety vulnerability database is downloaded from a public S3 bucket (via PyUp.io) and no longer from GitHub. This free database is only updated once a month.
- Telemetry data will be sent with every Safety call. These data are anonymous and not sensitive. This includes the Python version, the Safety command used (`check`/`license`/`review`), and the Safety options used (without their values). Users can disable this functionality by adding the `--disable-telemetry` flag.
- Added validations to avoid the use of exclusive options.
- Added announcements feature to receive informative or critical messages from the PyUp Safety team.
- Increased test coverage.


## [1.10.3] - 2021-01-15
- Avoid 1.10.2post1 bug with pyup updates

## [1.10.2] - 2021-01-12
- Provide CVSS values on full report for CVEs (requires a premium PyUp subscription)
- Fixed used DB wrong info
- Support line breaks on advisories

## [1.10.1] - 2021-01-03
- Reduced Docker image and Binary size
- Added bare and json outputs to license command

## [1.10.0] - 2020-12-20
- Added README information about Python 2.7 workaround
- Adjusted some pricing information
- Fixed MacOS binary build through AppVeyor
- Added the ability to check packages licenses (requires a premium PyUp subscription)

## [1.9.0] - 2020-04-27
- Dropped Python 2.7 support, requiring Python 3.5+
- Binary adjustments and enhancements on top of reported vulnerability
- Using tox to help with local tests against different Python versions

## [1.8.7] - 2020-03-10
- Fixed a hidden import caused the binary to produce errors on Linux.

## [1.8.6] - 2020-03-10
- Safety is now available as a binary release for macOS, Windows and Linux.

## [1.8.5] - 2019-02-04
- Wrap words in full report (Thanks @mgedmin)
- Added Dockerfile and readme instructions (Thanks @ayeks)
- Remove API dependency on pip (Thanks @benjaminp)

## [1.8.4] - 2018-08-03
- Update cryptography dependency from version 1.9 to version 2.3 due to security vulnerability

## [1.8.3b] - 2018-07-24
- Allows both unicode and non-unicode type encoding when parsing requriment files

## [1.8.2] - 2018-07-10
- Fixed unicode error

## [1.8.1] - 2018-04-06
- Fixed a packaging error with the dparse dependency

## [1.8.0] - 2018-04-05
- Safety now support pip 10

## [1.7.0] - 2018-02-03
- Safety now shows a filename if it finds an unpinned requirement. Thanks @nnadeau
- Removed official support for Python 2.6 and Python 3.3. Thanks @nnadeau

## [1.6.1] - 2017-10-20
- Fixed an error that caused the CLI to fail on requirement files/stdin.

## [1.6.0] - 2017-10-20
- Added an indicator which DB is currently used
- Added a package count how many packages have been checked
- Allow multiple version of the same library. Thanks @thatarchguy

## [1.5.1] - 2017-07-20
- Fixed an error on unpinned VCS requirements. This is a regression, see https://github.com/pyupio/safety/issues/72

## [1.5.0] - 2017-07-19
- Internal refactoring. Removed dependency on setuptools and switched to the new dparse library.

## [1.4.1] - 2017-07-04
- Fixed a bug where absence of ``stty`` was causing a traceback in ``safety
  check`` on Python 2.7 for Windows.

## [1.4.0] - 2017-04-21
- Added the ability to ignore one (or multiple) vulnerabilities by ID via the `--ignore`/`-i` flag.

## [1.3.0] - 2017-04-21
- Added `--bare` output format.
- Added a couple of help text to the command line interface.
- Fixed a bug that caused requirement files with unpinned dependencies to fail when using
 a recent setuptools release.

## [1.2.0] - 2017-04-06
- Added JSON as an output format. Use it with the `--json` flag. Thanks @Stype.

## [1.1.1] - 2017-03-27
- Fixed terminal size detection when fed via stdin.

## [1.1.0] - 2017-03-23
- Compatibility release. Safety should now run on macOs, Linux and Windows with Python 2.7, 3.3-3.6.
 Python 2.6 support is available on a best-effort basis on Linux.

## [1.0.2] - 2017-03-23
- Fixed another error on Python 2. The fallback function for get_terminal_size wasn't working correctly.

## [1.0.1] - 2017-03-23
- Fixed an error on Python 2, FileNotFoundError was introduced in Python 3.

## [1.0.0] - 2017-03-22
- Added terminal size detection. Terminals with fewer than 80 columns should now display nicer reports.
- Added an option to load the database from the filesystem or a mirror that's reachable via http(s).
 This can be done by using the --db flag.
- Added an API Key option that uses pyup.io's vulnerability database.
- Added an option to cache the database locally for 2 hours. The default still is to not use the cache. Use the --cache flag.


## [0.6.0] - 2017-03-10
- Made the requirements parser more robust. The parser should no longer fail on editable requirements
  and requirements that are supplied by package URL.
- Running safety requires setuptools >= 16

## [0.5.1] - 2016-11-08
- Fixed a bug where not all requirement files were read correctly.

## [0.5.0] - 2016-11-08
- Added option to read requirements from files.

## [0.4.0] - 2016-11-07
- Filter out non-requirements when reading from stdin.

## [0.3.0] - 2016-10-28
- Added option to read from stdin.

## [0.2.2] - 2016-10-21
- Fix import errors on python 2.6 and 2.7.

## [0.2.1] - 2016-10-21
- Fix packaging bug.

## [0.2.0] - 2016-10-20
- Releasing first prototype.

## [0.1.0] - 2016-10-19
- First release on PyPI.

# Changelog

All notable changes to this project will be documented in this file.

The format is partly based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and [PEP 440](https://peps.python.org/pep-0440/)


## 3.5.0 (2025-05-07)

### Fix

- poetry error on source and parsing pyproject.toml (#739)

## 3.5.0b2 (2025-05-06)

### Feat

- included project id in project specific files (#736)
- add 'SAFETY_REQUEST_TIMEOUT_EVENTS' so users can use a custom timeout (#737)

### Fix

- source error copy for Poetry (#738)

## 3.5.0b1 (2025-05-06)

### Fix

- fix the version information passing (#735)

## 3.5.0b0 (2025-05-05)

### Feat

- improved rendering of the warning messages (#732)
- added resolution of installed packages (#730)

### Fix

- missing uninstall option when feature flag is disabled (#734)
- usage of aot instead of tables for uv project (#733)
- suppress event loop errors during subprocess transport cleanup (#731)
- uv index out of range issue (#729)

## 3.4.1b0 (2025-04-29)

### Fix

- the unix-like alias interceptors (#728)
- tool parsing and tool exit codes (#727)
- tool issues on uv and poetry setup (#726)
- add missing instructions for terminal activation after safety init (#724)
- instantaneous init output (#723)
- codebase verification flow (#722)

## 3.4.0 (2025-04-23)

## 3.4.0b9 (2025-04-23)

### Feat

- add meta client headers to all requests (#719)
- include other category in the init scan (#718)

## 3.4.0b8 (2025-04-22)

### Feat

- add new onboarding events (#708)
- displaying package installation warnings (#707)

### Fix

- init scan none links (#714)
- using direct audit api to avoid redirect (#712)
- add compatibility for marshmallow 4.* (#713)

## 3.4.0b7 (2025-04-11)

### Feat

- integrate full support for poetry (#706)

## 3.4.0b6 (2025-04-07)

### Fix

- patch asyncio to avoid Windows exception on legacy Python versions (#705)

## 3.4.0b5 (2025-04-07)

## 3.4.0b4 (2025-04-01)

### Fix

- missing package-related events/handlers subscription (#703)

## 3.4.0b3 (2025-04-01)

## 3.4.0b2 (2025-04-01)

### Fix

- handling API Key usage and missing token (#701)

## 3.4.0b1 (2025-04-01)

### Fix

- prevent AttributeError on event bus start when only API Key is used (#700)

## 3.4.0b0 (2025-03-31)

### Feat

- Generating organization slug
- configuring the repository URL using project id (#693)
- add security events for firewall users (#694)

## 3.3.1 (2025-02-24)

## 3.3.1b0 (2025-02-21)

### Fix

- no proper handling of JSON server errors (#685)
- send proper close connection on local webserver redirect (#681)

## 3.3.0 (2025-02-14)

## 3.3.0b0 (2025-02-13)

### Feat

- added safety firewall (#671)

## [3.2.14] - 2024-12-20
- Add fun-mode (#649)
- Package version upgrade for psutil and filelock (#652)
- Package version upgrade for typer (#654)
- Package version upgrade for pydantic (#655)
- Add "--use-server-matching" arguement (#640)
- Bugfix for safety "NoneType is not iterable" error (#657)


## [3.2.13] - 2024-12-10
- Remove email verification for running scans (#645)

## [3.2.12] - 2024-12-10
- Add CVE Details and Single-Key Filtering for JSON Output in safety scan (#643)
- feature/add-branch-name (#641)
- feat/add --headless to --help (#636)

## [3.2.11] - 2024-11-12
- chore/upgrade-dparse (#633)
- Migrate to PyPI Trusted Publisher for Automated Package Deployment (#632)
- fix/fix-test-validate-func (#631)
- feat: api keys now work without specifying the env (#630)
- fix:jupyter notebook rich format removal (#628)

## [3.2.10] - 2024-10-25
- Support for scanning pyproject.toml files (#625)
- Update safety-schemas version used (#624)
- Fix basic poloicy test (#622)

## [3.2.9] - 2024-10-23
- chore: deprection-message-for-license-command (4149b70)
- feat: add-pull-request-template (#604) (61b2fe2)
- fix:  devcontainer fix (be42d8e)
- fix: safety error when scan is run without being authed (5ec80dd)
- feat: add-devcontainers-support (0591838)
- fix: internal-server-error (04d7efb)
- fix: clarify-vulnerabilities-found/ Fixed the issue where the vulnerabilities (07bc5b7)
- chore: added check arg depreciation warning (78109e5)
- feature: release-script: add release script (#602) (cc49542)

## [3.2.8] - 2024-09-27
- feat: enhance version comparison logic for check-updates command (#605)
- docs: add demo Jupyter Notebook (#601)
- feat: add script to generate CONTRIBUTORS.md with Shields.io badges based on merged PRs (#600)
- chore: fix CLI help text by removing rich formatting for cleaner output (#599)
- chore: hide system scan from help text (#598)
- chore: add LICENSES.md file to document dependency licenses (#597)
- docs: add SECURITY.md file with security policy and bug bounty details (#593)

## [3.2.7] - 2024-08-29
- fix/increase-auth-timeout: increase timeout to 5s (#583)
- Update Issue Templates: Add Feature Request Template and Improve Issue Submission Process (#580)

## [3.2.6] - 2024-08-21
- fix/update-schemas-0-0-4 (#581)
- chore/update-coc-email (#579)
- docs(contributing): add CONTRIBUTING.md with guidelines for contributors (#571)
- chore: update-network-url (#569)

## [3.2.5] - 2024-08-09
- fix: increment schemas version (#567)
- Add SLA Document (#565)
- Add Table of Contents to README.md (#564)
- docs: code of conduct (#559)
- Add More Badges (#558)
- feat: fixed issue responder (#561)
- feat(logger): config.ini, proxy, network stats (#547)
- refactor: replace private typer functions with rich module equivalents (#556)
- feat(safety_cli): docstrings, type hints, comments (#549)
- feat: add GitHub Action to automatically respond to new issues (#554)
- readme: add download badge to readme (#557)
- fix(debug): fix --debug flag and associated tests (#552)
- chore: release 3.2.4 (#545)
- fix(cache): handle get_from_cache=None and ensure directory exists (#544)
- REQUEST_TIMEOUT Env Var (#541)
- Update URLs, Lint (#540)

## [3.2.4] - 2024-07-04
- Handle `get_from_cache=None` and ensure directory exists (#538)
- Switch filelock package to compatible release clause (#538)
- Add filelock to `install_requires` (#538)

## [3.2.3] - 2024-06-10
- Increase request timeout to 30 seconds (#535)
- fix: fail on none severities (#534)

## [3.2.2] - 2024-06-07
- fix: include scan template in build (#531)

## [3.2.1] - 2024-06-04
- fix: include all templates in the manifest (#529)
- fix: use available email verification claims (#528)

## [3.2.0] - 2024-05-01
- feat: add SAFETY_DB_DIR env var to the scan command (#523)
- fix: update pyinstaller target (#522)
- docs: added note on hiring and added careers page link (#510)

## [3.1.0] - 2024-03-25
- fix: ensure compatibility with Pydantic version 2.0 (#509)
- feat: introduce --headless flag to enable an alternative login mechanism that bypasses the need for a local web server. (#508)

## [3.0.1] - 2024-01-19
- fix: add back the license legacy cmd (#498)
- perf: unpin authlib and remove jwt

## [3.0.0] - 2024-01-17

### Safety 3.0.0 major version release!
- Safety 3.0.0 is a significant update to Safety CLI from 2.x versions, including enhancements to core features, new capabilities, and breaking changes from 2.x.
- See our [Blog article announcing Safety CLI 3](https://safetycli.com/research/safety-cli-3-vulnerability-scanning-for-secure-python-development) for more details on Safety 3 and these changes
- See [Migrating from Safety 2.x to Safety CLI 3](https://docs.safetycli.com/safety-docs/safety-cli-3/migrating-from-safety-cli-2.x-to-safety-cli-3.x) for notes and steps to migrating from Safety 2 to Safety 3

### Main updates
- Added scan command, which scans a project’s directory for all Python dependencies and includes many improvements over the `check` command, including automatic Python project scanning, native support for Poetry and Pipenv files, Python virtual environment folders, and more granular configuration options.
- Added auth commands, enabling new browser-based authentication of Safety CLI.
- An updated safety policy file schema to support new scan and system-scan commands. This policy file schema is a breaking change from the policy schema used for `safety check`. To migrate a Safety 2.x policy, see  [Migrating from Safety 2.x to Safety CLI 3](https://docs.safetycli.com/safety-docs/safety-cli-3/migrating-from-safety-cli-2.x-to-safety-cli-3.x).
- Updated screen output to modern interactive interface, with new help interfaces.
- Updated to new JSON output structure to support new scan command, other ecosystems, and other security findings.
- Added a supporting [safety-schemas project dependency](https://pypi.org/project/safety-schemas/), also published and maintained by Safety, which defines Safety vulnerability database file, Safety CLI policy file, and Safety CLI JSON output schemas as pydantic models, formalizing these into testable and versioned schemas.

### New scan command:
- New scan command: scans a Python project directory for Python dependencies and security vulnerabilities. Safety scan replaces `safety check` with a more powerful and easier to use command. The scan command:
- Finds and scans Python dependency files and virtual environments inside the target directory without needing to specify file or environment locations.
- Adds native scanning and reporting for Poetry and Pipenv manifest files, and Python virtual environment folders.
- Adds configuration of scanning rules to;
    -  exclude files and folders from the scan using Unix shell-style wildcards only
    - Include files to be scanned
    - Max folder depth setting
- Reporting configuration rules
    -  Reporting rules defining which types and specific vulnerabilities to include or ignore stay the same as safety 2.x, although now in a slightly different structure.
- Failing rules
    - Adds ability to configure rules for when safety should return a non-zero (failing) exit code, which can be different from reporting rules under the `report` field.
- Auto-updating rules
    - Adds ability to easily update insecure package versions in pip requirements files.

### Other new commands:
- Added auth command: manages Safety CLI’s authentication in development environments, allowing easy authentication via the browser.
    - auth login - adds ability to authenticate safety cli via the browser
    - auth register - adds ability to register for a Safety account via the CLI, and get scanning within minutes
    - auth status -
    - auth logout -
    - `safety check` command can still be used with the API key --key argument, and scan and system-scan commands should also be
- Added configure command: configures safety cli using a config.ini file, either saved to the user settings or system settings. This can be used to configure safety’s authentication methods and global proxy details.
- Added system-scan command (beta): Adds the system-scan command, which scans a machine for Python files and environments, reporting these to screen output. system-scan is an experimental beta feature that can scan an entire drive or machine for Python dependency files and Python virtual environments, reporting on packages found and their associated security vulnerabilities.
- Added check-updates command: Check for version updates to Safety CLI, and supports screen and JSON format outputs. Can be used in organizations to test and rollout new version updates as recommended by Safety Cybersecurity.

### New policy file schema for scan and system-scan commands
- New policy file schema to support safety scan and safety system-scan.
Adds scanning-settings root property, which contains settings to configure rules and settings for how safety traverses the directory and subdirectories being scanned, including “exclude” rules, “include” rules, the max directory depth to scan and which root directories safety system-scan should start from.
- Adds report root property, which defines which vulnerability findings safety should auto-ignore (exclude) in its reporting. Supports excluding vulnerability IDs manually, as well as vulnerability groups to ignore based on CVSS severity score.
- Adds new fail-scan-with-exit-code root property, which defines when safety should exit with a failing exit code. This separates safety’s reporting rules from its failing exit code rules, which is a departure from Safety 2.x which had combined rulesets for these. Failing exit codes can be configured based on CVSS severity score.
- Note that the old `safety check` command still supports and relies on the policy schema from safety 2.3.5 and below, meaning no changes are required when migrating to safety 2.x to Safety 3.0.0 when only using the `safety check` command.

### New global options and configurations
- Added global --stage option, to set the development lifecycle stage for the `scan` and `system-scan` commands.
- Added global --key option, to set a Safety API key for any command, including scan, system-scan and check.

### Other
- Safety now requires Python>=3.7. Python 3.7 doesn't have active security support from the Python foundation, and we recommend upgrading to at least Python >= 3.8 whenever possible. Safety’s 3.0.0 Docker image can still be used to scan and secure all Python projects, regardless of Python version. Refer to our [Documentation](https://docs.safetycli.com) for details.
- Dropped support for the license command. This legacy command is being replaced by the scan command. Users relying on the license command should continue to use Safety 2.3.5 or 2.4.0b2 until Safety 3 adds license support in an upcoming 3.0.x release.
- Add deprecation notice to `safety check` command, since this is now replaced by `safety scan`, a more comprehensive scanning command. The check command will continue receiving maintenance support until June 2024.
- Add deprecation notice to `safety alert` command, which works in tandem with the `safety check` command. Safety alert functionality is replaced by [Safety Platform](https://safetycli.com/product/safety-platform). The alert command will continue receiving maintenance support until June 2024.
- `safety validate` will assume 3.0 policy file version by default.


### Small updates/ bug fixes
- Fixes [a bug](https://github.com/pyupio/safety/issues/488) related to ignoring vulnerability IDs in Safety’s policy file.
- https://github.com/pyupio/safety/issues/480
- https://github.com/pyupio/safety/issues/478
- https://github.com/pyupio/safety/issues/455
- https://github.com/pyupio/safety/issues/447

## [2.4.0b2] - 2023-11-15
- Removed the upper clause restriction for the packaging dependency

## [2.4.0b1] - 2022-02-26
- Added support for coma separated ignore (--ignore=123,456) on top of existing --ignore=123 --ignore=456
- Added support for requirements per package. Safety can check, report, suggest, and apply remediations for unpinned requirements.
- Added support for unpinned requirements in the Safety GitHub action. This feature doesn't support old-version reports.
- Added support for HTML5 output and the ability to save the report as an HTML5 file.
- Started to use schema 2.0 of the PyUp vulnerability database.
- Fixed packaging dependency issue and their deprecation of LegacyVersion class.
- Narrowed down the allowed versions in the Safety dependencies.
- Added local announcements.
- This version makes changes in the JSON report, these aren't breaking changes, but these may need adjustment if you are ingesting the JSON report.
- Added ability to ignore unpinned requirements.

## [2.3.5] - 2022-12-08
- Pinned packaging dependency to a compatible range.
- Pinned the CI actions to the runner image with Python 3.6 support.

## [2.3.4] - 2022-12-07
- Removed LegacyVersion use; this fixes the issue with packaging 22.0.
- Fixed typos in the README.
- Added Python 3.11 to the classifiers in the setup.cfg.

## [2.3.3] - 2022-11-27
- Fixed recursive requirements issue when an unpinned package is found.

## [2.3.2] - 2022-11-21
- Fixed #423: Bare output includes extra line in non-screen output with no vulnerabilities.
- Fixed #422: ResourceWarning (unclosed socket) in safety v.2.3.1.
- Fixed telemetry data missing when the CLI mode is used.
- Fixed wrong database fetching when the KEY and the database arguments are used at the same time.
- Added `SAFETY_PURE_YAML` env var, used for cases that require pure Python in the YAML parser.

## [2.3.1] - 2022-10-05
- Add `safety.alerts` module to setup.cfg

## [2.3.0] - 2022-10-05
- Safety can now create GitHub PRs and Issues for vulnerabilities directly, with the new `safety alert` subcommand.
- Support for GitHub PR and Issue alerting has been added to the GitHub Action.

## [2.2.1] - 2022-10-04
- Fixed the use of the SAFETY_COLOR environment variable
- Fixed bug in the case of vulnerabilities without a CVE linked
- Fixed GitHub version in the README

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

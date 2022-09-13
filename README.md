[![safety](https://raw.githubusercontent.com/pyupio/safety/master/safety.jpg)](https://pyup.io/safety/)

[![PyPi](https://img.shields.io/pypi/v/safety.svg)](https://pypi.python.org/pypi/safety)
[![Travis](https://img.shields.io/travis/pyupio/safety.svg)](https://travis-ci.org/pyupio/safety)
[![Updates](https://pyup.io/repos/github/pyupio/safety/shield.svg)](https://pyup.io/repos/github/pyupio/safety/)

Safety checks Python dependencies for known security vulnerabilities and suggests the proper remediations for vulnerabilities detected. Safety can be run on developer machines, in CI/CD pipelines and on production systems.

By default it uses the open Python vulnerability database [Safety DB](https://github.com/pyupio/safety-db), which is **licensed for non-commercial use only**.

For all commercial projects, Safely must be upgraded to use a [PyUp API](https://pyup.io) using the `--key` option.

# Using Safety as a GitHub Action

Safety can be integrated into your existing GitHub CI pipeline as an action. Just add the following as a step in your workflow YAML file after setting your `SAFETY_API_KEY` secret on GitHub under Settings -> Secrets -> Actions:

```yaml
      - uses: pyupio/safety@v1
        with:
          api-key: ${{ secrets.SAFETY_API_KEY }}
```

(Don't have an API Key? You can sign up for one with [PyUp](https://pyup.io).)

This will run Safety in auto-detect mode which figures out your project's structure and the best configuration to run in automatically. It'll fail your CI pipeline if any vulnerable packages are found.

If you have something more complicated such as a monorepo; or once you're finished testing, read the [Action Documentation](https://docs.pyup.io/docs/github-actions-safety) for more details on configuring Safety as an action.

# Installation

Install `safety` with pip. Keep in mind that we support only Python 3.6 and up.

```bash
pip install safety
```

# Documentation

For detailed documentation, please see [Safety's documentation portal](https://docs.pyup.io/docs/getting-started-with-safety-cli).

# Basic Usage

To check your currently selected virtual environment for dependencies with known security
 vulnerabilites, run:

```bash
safety check
```

You should get a report similar to this:
```bash
+=================================================================================+

                               /$$$$$$            /$$
                              /$$__  $$          | $$
           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$
          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$
         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$
          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$
          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$
         |_______/  \_______/|__/     \_______/   \___/   \____  $$
                                                          /$$  | $$
                                                         |  $$$$$$/
  by pyup.io                                              \______/

+=================================================================================+

 REPORT

  Safety v2.0.0 is scanning for Vulnerabilities...
  Scanning dependencies in your environment:

  -> /scanned-path/

  Using non-commercial database
  Found and scanned 295 packages
  Timestamp 2022-06-28 15:42:04
  0 vulnerabilities found
  0 vulnerabilities ignored
+=================================================================================+

 No known security vulnerabilities found.

+=================================================================================+
```


Now, let's install something insecure:

```bash
pip install insecure-package
```
*Yeah, you can really install that.*

Run `safety check` again:

```bash
 +=================================================================================+

  Safety v2.0.0.dev6 is scanning for Vulnerabilities...
  Scanning dependencies in your environment:

    -> /scanned-path/

  Using non-commercial database
  Found and scanned 295 packages
  Timestamp 2022-06-28 15:42:04
  1 vulnerabilities found
  0 vulnerabilities ignored

+=================================================================================+
 VULNERABILITIES FOUND
+=================================================================================+

-> Vulnerability found in insecure-package version 0.1.0
    Vulnerability ID: 25853
    Affected spec: <0.2.0
    ADVISORY: This is an insecure package with lots of exploitable
    security vulnerabilities.
    Fixed versions:
    PVE-2021-25853

    For more information, please visit
    https://pyup.io/vulnerabilities/PVE-2021-25853/25853/


 Scan was completed.

+=================================================================================+
```


## Starter documentation

### Configuring the target of the scan
Safety can scan requirements.txt files, the local environemnt as well as direct input piped into Safety.

To scan a requirements file:

```bash
safety check -r requirements.txt
```

To scan the local enviroment:

```bash
safety check
```

Safety is also able to read from stdin with the `--stdin` flag set.
```
cat requirements.txt | safety check --stdin
```

or the output of `pip freeze`:
```
pip freeze | safety check --stdin
```

or to check a single package:
```
echo "insecure-package==0.1" | safety check --stdin
```

*For more examples, take a look at the [options](#options) section.*


### Specifying the output format of the scan

Safety can output the scan results in a variety of formats and outputs. This includes: screen, text, JSON, and bare outputs. Using the ```--output``` flag to configure this output. The default output is to the screen.

```--output json``` will output JSON for further processing and analysis.
```--output text``` can be used to save the scan to file to later auditing.
```--output bare``` simply prints out the packages that have known vulnerabilities

### Exit codes

Safety by default emits exit codes based on the result of the code, allowing you to run safety inside of CI/CD processes. If no vulnerabilities were found the exit code will be 0. In cases of a vulnerability being found, non-zero exit codes will be returned.

### Scan a Python-based Docker image

To scan a docker image `IMAGE_TAG`, you can run

```console
docker run -it --rm ${IMAGE_TAG} /bin/bash -c "pip install safety && safety check"
```

## Using Safety in Docker

Safety can be easily executed as Docker container. It can be used just as
described in the [examples](#examples) section.

```console
echo "insecure-package==0.1" | docker run -i --rm pyupio/safety safety check --stdin
cat requirements.txt | docker run -i --rm pyupio/safety safety check --stdin
```

## Using the Safety binaries

The Safety [binaries](https://github.com/pyupio/safety/releases) provide some
[extra security](https://pyup.io/posts/patched-vulnerability/).

After installation, they can be used just like the regular command line version
of Safety.

## Using Safety with a CI service

Safety works great in your CI pipeline. It returns by default meaningful non-zero exit codes:


| CODE NAME      | MEANING     | VALUE  |
| ------------- |:-------------:| -----:|
| EXIT_CODE_OK                    | Successful scan  | 0 |
| EXIT_CODE_FAILURE               | An unexpected issue happened, please run the debug mode and write to us      |   1 |
| EXIT_CODE_VULNERABILITIES_FOUND | Safety found vulnerabilities      |    64 |
| EXIT_CODE_INVALID_API_KEY       | The API KEY used is invalid | 65 |
| EXIT_CODE_TOO_MANY_REQUESTS     | You are making too many request, please wait around 40 seconds | 66 |
| EXIT_CODE_UNABLE_TO_LOAD_LOCAL_VULNERABILITY_DB | The local vulnerability database is malformed | 67 |
| EXIT_CODE_UNABLE_TO_FETCH_VULNERABILITY_DB | Client network or server issues trying to fetch the database | 68 |
| EXIT_CODE_MALFORMED_DB | The fetched vulnerability database is malformed or in the review command case, the report to review is malformed | 69 |

if you want Safety continues on error (always return zero exit code), you can use `--continue-on-error` flag

Run it before or after your tests. If Safety finds something, your tests will fail.

**Travis CI**
```yaml
install:
  - pip install safety

script:
  - safety check
```

**Gitlab CI**
```yaml
safety:
  script:
    - pip install safety
    - safety check
```

**Tox**
```ini
[tox]
envlist = py37

[testenv]
deps =
    safety
    pytest
commands =
    safety check
    pytest
```

**Deep GitHub Integration**

If you are looking for a deep integration with your GitHub repositories: Safety is available as a
part of [pyup.io](https://pyup.io/), called [Safety CI](https://pyup.io/safety/ci/). Safety CI
checks your commits and pull requests for dependencies with known security vulnerabilities
and displays a status on GitHub.

![Safety CI](https://github.com/pyupio/safety/raw/master/safety_ci.png)

# Using Safety in production

Safety is free and open source (MIT Licensed). The data it relies on from the free Safety-db database is license for non-commercial use only, is limited and only updated once per month.

**All commercial projects and teams must sign up for a paid plan at [PyUp.io](https://pyup.io)**

## Options

### `--key`

*API Key for pyup.io's vulnerability database. This can also be set as `SAFETY_API_KEY` environment variable.*

**Example**
```bash
safety check --key=12345-ABCDEFGH
```

___

### `--db`

*Path to a directory with a local vulnerability database including `insecure.json` and `insecure_full.json`*

**Example**
```bash
safety check --db=/home/safety-db/data
```

### `--proxy-host`

*Proxy host IP or DNS*

### `--proxy-port`

*Proxy port number*

### `--proxy-protocol`

*Proxy protocol (https or http)*

___


### `--output json`

*Output a complete report with the vulnerabilities in JSON format.*
The report may be used too with the review command.

if you are using the PyUp commercial database, Safety will use the same JSON structure but with all the full data for commercial users.

**Example**
```bash
safety check --output json
```
```json
{
    "report_meta": {
        "scan_target": "environment",
        "scanned": [
            "/usr/local/lib/python3.9/site-packages"
        ],
        "api_key": false,
        "packages_found": 1,
        "timestamp": "2022-03-23 01:41:25",
        "safety_version": "2.0.0.dev6"
    },
    "scanned_packages": {
        "insecure-package": {
            "name": "insecure-package",
            "version": "0.1.0"
        }
    },
    "affected_packages": {
        "insecure-package": {
            "name": "insecure-package",
            "version": "0.1.0",
            "found": "/usr/local/lib/python3.9/site-packages",
            "insecure_versions": [],
            "secure_versions": [],
            "latest_version_without_known_vulnerabilities": null,
            "latest_version": null,
            "more_info_url": "None"
        }
    },
    "announcements": [],
    "vulnerabilities": [
        {
            "name": "insecure-package",
            "ignored": false,
            "reason": "",
            "expires": "",
            "vulnerable_spec": "<0.2.0",
            "all_vulnerable_specs": [
                "<0.2.0"
            ],
            "analyzed_version": "0.1.0",
            "advisory": "This is an insecure package with lots of exploitable security vulnerabilities.",
            "vulnerability_id": "25853",
            "is_transitive": false,
            "published_date": null,
            "fixed_versions": [],
            "closest_versions_without_known_vulnerabilities": [],
            "resources": [],
            "CVE": {
                "name": "PVE-2021-25853",
                "cvssv2": null,
                "cvssv3": null
            },
            "affected_versions": [],
            "more_info_url": "None"
        }
    ],
    "ignored_vulnerabilities": [],
    "remediations": {
        "insecure-package": {
            "vulns_found": 1,
            "version": "0.1.0",
            "recommended": null,
            "other_recommended_versions": [],
            "more_info_url": "None"
        }
    }
}
```
___

### `--full-report`

*Full reports includes a security advisory. It also shows CVSS values for CVEs (requires a premium PyUp subscription).*

**Example**
```bash
safety check --full-report
```

### `--output bare`

*Output vulnerable packages only. Useful in combination with other tools.*

**Example**
```bash
safety check --output bare
```

```
cryptography django
```
___


### `--stdin`

*Read input from stdin.*

**Example**
```bash
cat requirements.txt | safety check --stdin
```
```bash
pip freeze | safety check --stdin
```
```bash
echo "insecure-package==0.1" | safety check --stdin
```
___

### `--file`, `-r`

*Read input from one (or multiple) requirement files.*

**Example**
```bash
safety check -r requirements.txt
```
```bash
safety check --file=requirements.txt
```
```bash
safety check -r req_dev.txt -r req_prod.txt
```
___

### `--ignore`, `-i`

*Ignore one (or multiple) vulnerabilities by ID*

**Example**
```bash
safety check -i 1234
```
```bash
safety check --ignore=1234
```
```bash
safety check -i 1234 -i 4567 -i 89101
```

### `--output`, `-o`

*Save the report to a file*

**Example**
```bash
safety check --output text > insecure_report.txt
```
```bash
safety check --output json > insecure_report.json
```
___

# Review

If you save the report in JSON format you can review in the report format again.

## Options

### `--file`, `-f` (REQUIRED)

*Read an insecure report.*

**Example**
```bash
safety review -f insecure.json
```
```bash
safety review --file=insecure.json
```
___

### `--full-report`

*Full reports include a security advisory (if available).*

**Example**
```bash
safety review -r insecure.json --full-report
```

___

### `--bare`

*Output vulnerable packages only.*

**Example**
```bash
safety review --file report.json --output bare
```

```
django
```


___

# License

Display packages licenses information (requires a premium PyUp subscription).

## Options

### `--key` (REQUIRED)

*API Key for pyup.io's licenses database. Can be set as `SAFETY_API_KEY` environment variable.*

**Example**
```bash
safety license --key=12345-ABCDEFGH
```
*Shows the license of each package in the current environment*


### `--output json` (Optional)

This license command can also be used in conjuction with optional arguments `--output bare` and `--output json` for structured, parsable outputs that can be fed into other tools and pipelines.

___

### `--db`

*Path to a directory with a local licenses database `licenses.json`*

**Example**
```bash
safety license --key=12345-ABCDEFGH --db /home/safety-db/data
```
___

### `--file`, `-r`

*Read input from one (or multiple) requirement files.*

**Example**
```bash
safety license --key=12345-ABCDEFGH -r requirements.txt
```
```bash
safety license --key=12345-ABCDEFGH --file=requirements.txt
```
```bash
safety license --key=12345-ABCDEFGH -r req_dev.txt -r req_prod.txt
```

___


### `--proxy-host`, `-ph`

*Proxy host IP or DNS*

### `--proxy-port`, `-pp`

*Proxy port number*

### `--proxy-protocol`, `-pr`

*Proxy protocol (https or http)*

**Example**
```bash
safety license --key=12345-ABCDEFGH -ph 127.0.0.1 -pp 8080 -pr https
```

___

# Python 2.7

This tool requires latest Python patch versions starting with version 3.6. We
did support Python 2.7 in the past but, as for other Python 3.x minor versions,
it reached its End-Of-Life and as such we are not able to support it anymore.

We understand you might still have Python < 3.6 projects running. At the same
time, Safety itself has a commitment to encourage developers to keep their
software up-to-date, and it would not make sense for us to work with officially
unsupported Python versions, or even those that reached their end of life.

If you still need to run Safety from a Python 2.7 environment, please use
version 1.8.7 available at PyPi. Alternatively, you can run Safety from a
Python 3 environment to check the requirements file for your Python 2.7
project.

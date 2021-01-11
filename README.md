[![safety](https://raw.githubusercontent.com/pyupio/safety/master/safety.jpg)](https://pyup.io/safety/)

[![PyPi](https://img.shields.io/pypi/v/safety.svg)](https://pypi.python.org/pypi/safety)
[![Travis](https://img.shields.io/travis/pyupio/safety.svg)](https://travis-ci.org/pyupio/safety)
[![Updates](https://pyup.io/repos/github/pyupio/safety/shield.svg)](https://pyup.io/repos/github/pyupio/safety/)

Safety checks your installed dependencies for known security vulnerabilities. 

By default it uses the open Python vulnerability database [Safety DB](https://github.com/pyupio/safety-db), 
but can be upgraded to use pyup.io's [Safety API](https://github.com/pyupio/safety/blob/master/docs/api_key.md) using the `--key` option. 

# Installation

Install `safety` with pip. Keep in mind that we support only Python 3.5 and up.
Look at *Python 2.7* section at the end of this document.

```bash
pip install safety
```

# Usage

To check your currently selected virtual environment for dependencies with known security
 vulnerabilites, run:

```bash
safety check
```

You should get a report similar to this:
```bash
+==============================================================================+
|                                                                              |
|                               /$$$$$$            /$$                         |
|                              /$$__  $$          | $$                         |
|           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           |
|          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           |
|         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           |
|          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           |
|          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           |
|         |_______/  \_______/|__/     \_______/   \___/   \____  $$           |
|                                                          /$$  | $$           |
|                                                         |  $$$$$$/           |
|  by pyup.io                                              \______/            |
|                                                                              |
+==============================================================================+
| REPORT                                                                       |
+==============================================================================+
| No known security vulnerabilities found.                                     |
+==============================================================================+
```

Now, let's install something insecure:

```bash
pip install insecure-package
```
*Yeah, you can really install that.*

Run `safety check` again:
```bash
+==============================================================================+
|                                                                              |
|                               /$$$$$$            /$$                         |
|                              /$$__  $$          | $$                         |
|           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           |
|          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           |
|         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           |
|          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           |
|          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           |
|         |_______/  \_______/|__/     \_______/   \___/   \____  $$           |
|                                                          /$$  | $$           |
|                                                         |  $$$$$$/           |
|  by pyup.io                                              \______/            |
|                                                                              |
+==============================================================================+
| REPORT                                                                       |
+==========================+===============+===================+===============+
| package                  | installed     | affected          | source        |
+==========================+===============+===================+===============+
| insecure-package         | 0.1.0         | <0.2.0            | changelog     |
+==========================+===============+===================+===============+
```

## Examples

### Read requirement files
Just like pip, Safety is able to read local requirement files:

```bash
safety check -r requirements.txt
```

### Read from stdin
Safety is also able to read from stdin with the `--stdin` flag set.

To check a local requirements file, run:
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


### Scan a Python-based Docker image

To scan a docker image `IMAGE_TAG`, you can run

```console
docker run -it --rm ${IMAGE_TAG} "/bin/bash -c \"pip install safety && safety check\"
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

Safety works great in your CI pipeline. It returns a non-zero exit status if it finds a vulnerability. 

Run it before or after your tests. If Safety finds something, your tests will fail.

**Travis**
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

Safety is free and open source (MIT Licensed). The underlying open vulnerability database is updated once per month.

To get access to all vulnerabilites as soon as they are added, you need a [Safety API key](https://github.com/pyupio/safety/blob/master/docs/api_key.md) that comes with a paid [pyup.io](https://pyup.io) account, starting at $99.

## Options

### `--key`

*API Key for pyup.io's vulnerability database. Can be set as `SAFETY_API_KEY` environment variable.*

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

### `--json`

*Output vulnerabilities in JSON format.*

**Example**
```bash
safety check --json
```
```javascript
[
    [
        "django",
        "<1.2.2",
        "1.2",
        "Cross-site scripting (XSS) vulnerability in Django 1.2.x before 1.2.2 allows remote attackers to inject arbitrary web script or HTML via a csrfmiddlewaretoken (aka csrf_token) cookie.",
        "25701"
    ]
]
```
___

### `--full-report`

*Full reports includes a security advisory. It also shows CVSS values for CVEs (requires a premium PyUp subscription).*

**Example**
```bash
safety check --full-report
```

```
+==============================================================================+
|                                                                              |
|                               /$$$$$$            /$$                         |
|                              /$$__  $$          | $$                         |
|           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           |
|          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           |
|         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           |
|          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           |
|          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           |
|         |_______/  \_______/|__/     \_______/   \___/   \____  $$           |
|                                                          /$$  | $$           |
|                                                         |  $$$$$$/           |
|  by pyup.io                                              \______/            |
|                                                                              |
+==============================================================================+
| REPORT                                                                       |
+============================+===========+==========================+==========+
| package                    | installed | affected                 | ID       |
+============================+===========+==========================+==========+
| CVSS v2 | BASE SCORE: 6.5 | IMPACT SCORE: 6.4                                |
+============================+===========+==========================+==========+
| django                     | 1.2       | <1.2.2                   | 25701    |
+==============================================================================+
| Cross-site scripting (XSS) vulnerability in Django 1.2.x before 1.2.2 allows |
|  remote attackers to inject arbitrary web script or HTML via a csrfmiddlewar |
| etoken (aka csrf_token) cookie.                                              |
+==============================================================================+
```
___

### `--bare`

*Output vulnerable packages only. Useful in combination with other tools.*

**Example**
```bash
safety check --bare
```

```
cryptography django
```
___

### `--cache`

*Cache requests to the vulnerability database locally for 2 hours.*

**Example**
```bash
safety check --cache
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
safety check -o insecure_report.txt
```
```bash
safety check --output --json insecure_report.json
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

```
+==============================================================================+
|                                                                              |
|                               /$$$$$$            /$$                         |
|                              /$$__  $$          | $$                         |
|           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           |
|          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           |
|         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           |
|          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           |
|          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           |
|         |_______/  \_______/|__/     \_______/   \___/   \____  $$           |
|                                                          /$$  | $$           |
|                                                         |  $$$$$$/           |
|  by pyup.io                                              \______/            |
|                                                                              |
+==============================================================================+
| REPORT                                                                       |
+============================+===========+==========================+==========+
| package                    | installed | affected                 | ID       |
+============================+===========+==========================+==========+
| django                     | 1.2       | <1.2.2                   | 25701    |
+==============================================================================+
| Cross-site scripting (XSS) vulnerability in Django 1.2.x before 1.2.2 allows |
|  remote attackers to inject arbitrary web script or HTML via a csrfmiddlewar |
| etoken (aka csrf_token) cookie.                                              |
+==============================================================================+
```
___

### `--bare`

*Output vulnerable packages only.*

**Example**
```bash
safety review --file report.json --bare
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


```
+==============================================================================+
|                                                                              |
|                               /$$$$$$            /$$                         |
|                              /$$__  $$          | $$                         |
|           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           |
|          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           |
|         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           |
|          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           |
|          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           |
|         |_______/  \_______/|__/     \_______/   \___/   \____  $$           |
|                                                          /$$  | $$           |
|                                                         |  $$$$$$/           |
|  by pyup.io                                              \______/            |
|                                                                              |
+==============================================================================+
| Packages licenses                                                            |
+=============================================+===========+====================+
| package                                     |  version  | license            |
+=============================================+===========+====================+
| requests                                    | 2.25.0    | Apache-2.0         |
|------------------------------------------------------------------------------|
| click                                       | 7.1.2     | BSD-3-Clause       |
|------------------------------------------------------------------------------|
| safety                                      | 1.10.0    | MIT                |
+==============================================================================+
```

___

### `--db`

*Path to a directory with a local licenses database `licenses.json`*

**Example**
```bash
safety license --key=12345-ABCDEFGH --db=/home/safety-db/data
```
___

### `--no-cache`

*Since PyUp.io licenses DB is updated once a week, the licenses database is cached locally for 7 days. You can use `--no-cache` to download it once again.*

**Example**
```bash
safety license --key=12345-ABCDEFGH --no-cache
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

This tool requires latest Python patch versions starting with version 3.5. We
did support Python 2.7 in the past but, as for other Python 3.x minor versions,
it reached its End-Of-Life and as such we are not able to support it anymore.

We understand you might still have Python 2.7 projects running. At the same
time, Safety itself has a commitment to encourage developers to keep their
software up-to-date, and it would not make sense for us to work with officially
unsupported Python versions, or even those that reached their end of life.

If you still need to run Safety from a Python 2.7 environment, please use
version 1.8.7 available at PyPi. Alternatively, you can run Safety from a
Python 3 environment to check the requirements file for your Python 2.7
project.

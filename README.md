[![safety](https://raw.githubusercontent.com/pyupio/safety/master/safety.jpg)](https://pyup.io/safety/)

[![PyPi](https://img.shields.io/pypi/v/safety.svg)](https://pypi.python.org/pypi/safety)
[![Travis](https://img.shields.io/travis/pyupio/safety.svg)](https://travis-ci.org/pyupio/safety)
[![Updates](https://pyup.io/repos/github/pyupio/safety/shield.svg)](https://pyup.io/repos/github/pyupio/safety/)

Safety checks your installed dependencies for known security vulnerabilities. 

By default it uses the open Python vulnerability database [Safety DB](https://github.com/pyupio/safety-db), 
but can be upgraded to use pyup.io's [Safety API](https://github.com/pyupio/safety/blob/master/docs/api_key.md) using the `--key` option. 

# Installation

Install `safety` with pip

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
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                              │
│                               /$$$$$$            /$$                         │
│                              /$$__  $$          | $$                         │
│           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           │
│          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           │
│         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           │
│          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           │
│          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           │
│         |_______/  \_______/|__/     \_______/   \___/   \____  $$           │
│                                                          /$$  | $$           │
│                                                         |  $$$$$$/           │
│  by pyup.io                                              \______/            │
│                                                                              │
╞══════════════════════════════════════════════════════════════════════════════╡
│ REPORT                                                                       │
╞══════════════════════════════════════════════════════════════════════════════╡
│ No known security vulnerabilities found.                                     │
╘══════════════════════════════════════════════════════════════════════════════╛
```

Now, let's install something insecure:

```bash
pip install insecure-package
```
*Yeah, you can really install that.*

Run `safety check` again:
```bash
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                              │
│                               /$$$$$$            /$$                         │
│                              /$$__  $$          | $$                         │
│           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           │
│          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           │
│         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           │
│          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           │
│          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           │
│         |_______/  \_______/|__/     \_______/   \___/   \____  $$           │
│                                                          /$$  | $$           │
│                                                         |  $$$$$$/           │
│  by pyup.io                                              \______/            │
│                                                                              │
╞══════════════════════════════════════════════════════════════════════════════╡
│ REPORT                                                                       │
╞══════════════════════════╤═══════════════╤═══════════════════╤═══════════════╡
│ package                  │ installed     │ affected          │ source        │
╞══════════════════════════╧═══════════════╧═══════════════════╧═══════════════╡
│ insecure-package         │ 0.1.0         │ <0.2.0            │ changelog     │
╘══════════════════════════╧═══════════════╧═══════════════════╧═══════════════╛
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

## Using Safety with a CI service

Safety works great in your CI pipeline. It returns a non-zero exit status if it finds a vulnerability. 

Run it before or after your tests. If Safety finds something, your tests will fail.

**Travis**
```
install:
  - pip install safety

script:
  - safety check
```

**Deep GitHub Integration**

If you are looking for a deep integration with your GitHub repositories: Safety is available as a 
part of [pyup.io](https://pyup.io/), called [Safety CI](https://pyup.io/safety/ci/). Safety CI 
checks your commits and pull requests for dependencies with known security vulnerabilities 
and displays a status on GitHub.

![Safety CI](https://github.com/pyupio/safety/raw/master/safety_ci.png)


# Using Safety in production

Safety is free and open source (MIT Licensed). The underlying open vulnerability database is updated once per month.

To get access to all vulnerabilites as soon as they are added, you need a [Safety API key](https://github.com/pyupio/safety/blob/master/docs/api_key.md) that comes with a paid [pyup.io](https://pyup.io) account, starting at $14.99 for individuals, or $49.99 for organizations.

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

*Full reports include a security advisory (if available).*

**Example**
```bash
safety check --full-report
```

```
╒══════════════════════════════════════════════════════════════════════════════╕
│                                                                              │
│                               /$$$$$$            /$$                         │
│                              /$$__  $$          | $$                         │
│           /$$$$$$$  /$$$$$$ | $$  \__//$$$$$$  /$$$$$$   /$$   /$$           │
│          /$$_____/ |____  $$| $$$$   /$$__  $$|_  $$_/  | $$  | $$           │
│         |  $$$$$$   /$$$$$$$| $$_/  | $$$$$$$$  | $$    | $$  | $$           │
│          \____  $$ /$$__  $$| $$    | $$_____/  | $$ /$$| $$  | $$           │
│          /$$$$$$$/|  $$$$$$$| $$    |  $$$$$$$  |  $$$$/|  $$$$$$$           │
│         |_______/  \_______/|__/     \_______/   \___/   \____  $$           │
│                                                          /$$  | $$           │
│                                                         |  $$$$$$/           │
│  by pyup.io                                              \______/            │
│                                                                              │
╞══════════════════════════════════════════════════════════════════════════════╡
│ REPORT                                                                       │
╞════════════════════════════╤═══════════╤══════════════════════════╤══════════╡
│ package                    │ installed │ affected                 │ ID       │
╞════════════════════════════╧═══════════╧══════════════════════════╧══════════╡
│ django                     │ 1.2       │ <1.2.2                   │ 25701    │
╞══════════════════════════════════════════════════════════════════════════════╡
│ Cross-site scripting (XSS) vulnerability in Django 1.2.x before 1.2.2 allows │
│  remote attackers to inject arbitrary web script or HTML via a csrfmiddlewar │
│ etoken (aka csrf_token) cookie.                                              │
╘══════════════════════════════════════════════════════════════════════════════╛
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
___

[![safety](https://raw.githubusercontent.com/pyupio/safety/master/safety.png)](https://pyup.io/safety/)

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

## From files
Just like pip, Safety is able to read local requirement files:

```bash
safety check -r requirements.txt
```

## From stdin
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

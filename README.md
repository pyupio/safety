[![safety](https://cdn.safetycli.com/images/cli_readme_header.png)](https://docs.safetycli.com/)

[![Downloads](https://static.pepy.tech/badge/safety/month)](https://pepy.tech/project/safety)
![CI Status](https://github.com/pyupio/safety/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/github/license/pyupio/safety)
![PyPI Version](https://img.shields.io/pypi/v/safety)
![Python Versions](https://img.shields.io/pypi/pyversions/safety)
![Coverage](https://img.shields.io/codecov/c/github/pyupio/safety)

> [!NOTE]
> [Come and join us at SafetyCLI](https://apply.workable.com/safety/). We are hiring for various roles.

# Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Key Features](#key-features)
- [Getting Started](#getting-started)
  - [GitHub Action](#github-action)
  - [Command Line Interface](#command-line-interface)
    - [1. Installation](#1-installation)
    - [2. Log In or Register](#2-log-in-or-register)
    - [3. Running Your First Scan](#3-running-your-first-scan)
  - [Basic Commands](#basic-commands)
- [Service-Level Agreement (SLA)](#service-level-agreement-sla)
- [Detailed Documentation](#detailed-documentation)
- [License](#license)
- [Supported Python Versions](#supported-python-versions)
- [Resources](#resources)

# Introduction
Safety CLI is a Python dependency vulnerability scanner designed to enhance software supply chain security by detecting packages with known vulnerabilities and malicious packages in local development environments, CI/CD, and production systems.
Safety CLI can be deployed in minutes and provides clear, actionable recommendations for remediation of detected vulnerabilities.

Leveraging the industry's most comprehensive database of vulnerabilities and malicious packages, Safety CLI Scanner allows teams to detect vulnerabilities at every stage of the software development lifecycle.

# Key Features
- Versatile, comprehensive dependency security scanning for Python packages.
- Leverages Safety DB, the most comprehensive vulnerability data available for Python.
- Clear output with detailed recommendations for vulnerability remediation.
- Automatically updates requirements files to secure versions of dependencies where available, guided by your project's policy settings.
- Scanning of individual requirements files and project directories or system-wide scans on developer machines, CI/CD pipelines, and Production systems to detect vulnerable or malicious dependencies.
- JSON, SBOM, HTML and text output.
- Easy integration with CI/CD pipelines, including GitHub Actions.
- Enterprise Ready: Safety CLI can be deployed to large teams with complex project setups with ease, on-premise or as a SaaS product.

# Getting Started
## GitHub Action

- Test Safety CLI in CI/CD using our [GitHub Action](https://github.com/pyupio/safety-action).
- Full documentation on the [GitHub Action](https://github.com/pyupio/safety-action) is available on our [Documentation Hub](https://docs.safetycli.com).

## Command Line Interface

### 1. Installation

- Install Safety on your development machine.
- Run `pip install safety`.

### 2. Log In or Register

- Run your first scan using `safety scan`.
- If not authenticated, Safety will prompt for account creation or login.
- Use `safety auth` to check authentication status.

### 3. Running Your First Scan

- Navigate to a project directory and run `safety scan`.
- Safety will perform a scan and present results in the Terminal.

## Basic Commands

- `safety --help`: Access help and display all available commands.
- `safety auth`: Start authentication flow or display status.
- `safety scan`: Perform a vulnerability scan in the current directory.
- `safety system-scan`: Perform a scan across the entire development machine.
- `safety scan --apply-fixes`: Update vulnerable dependencies.

# Service-Level Agreement (SLA)

We are committed to maintaining a high level of responsiveness and transparency in managing issues reported in our codebases. This SLA outlines our policies and procedures for handling issues to ensure timely resolutions and effective communication with our community.

- [Read our full SLA](./SLA.md)

# Detailed Documentation
Full documentation is available at [https://docs.safetycli.com](https://docs.safetycli.com).

Included in the documentation are the following key topics:

**Safety CLI 3**
- [Introduction to Safety CLI 3](https://docs.safetycli.com/safety-docs/safety-cli-3/introduction-to-safety-cli-scanner)
- [Quick Start Guide](https://docs.safetycli.com/safety-docs/safety-cli-3/quick-start-guide)
- [Installation and Authentication](https://docs.safetycli.com/safety-docs/safety-cli-3/installation-and-authentication)
- [Scanning for Vulnerable and Malicious Packages](https://docs.safetycli.com/safety-docs/safety-cli-3/scanning-for-vulnerable-and-malicious-packages)
- [System-Wide Developer Machine Scanning](https://docs.safetycli.com/safety-docs/safety-cli-3/system-wide-developer-machine-scanning)
- [Viewing Scan Results](https://docs.safetycli.com/safety-docs/safety-cli-3/viewing-scan-results)
- [Available Commands and Inputs](https://docs.safetycli.com/safety-docs/safety-cli-3/available-commands-and-inputs)
- [Scanning in CI/CD](https://docs.safetycli.com/safety-docs/safety-cli-3/scanning-in-ci-cd)
- [License Scanning](https://docs.safetycli.com/safety-docs/safety-cli-3/license-scanning)
- [Exit Codes](https://docs.safetycli.com/safety-docs/safety-cli-3/exit-codes)

**Vulnerability Remediation**
- [Applying Fixes](https://docs.safetycli.com/safety-docs/vulnerability-remediation/applying-fixes)

**Integration**
- [Securing Git Repositories](https://docs.safetycli.com/safety-docs/installation/securing-git-repositories)
- [GitHub](https://docs.safetycli.com/safety-docs/installation/github)
- [GitHub Actions](https://docs.safetycli.com/safety-docs/installation/github-actions)
- [GitLab](https://docs.safetycli.com/safety-docs/installation/gitlab)
- [Git Post-Commit Hooks](https://docs.safetycli.com/safety-docs/installation/git-post-commit-hooks)
- [BitBucket](https://docs.safetycli.com/safety-docs/installation/bitbucket)
- [Pipenv](https://docs.safetycli.com/safety-docs/installation/pipenv)
- [Docker Containers](https://docs.safetycli.com/safety-docs/installation/docker-containers)

**Administration**
- [Policy Management](https://docs.safetycli.com/safety-docs/administration/policy-management)

**Output**
- [Output Options and Recommendations](https://docs.safetycli.com/safety-docs/output/output-options-and-recommendations)
- [JSON Output](https://docs.safetycli.com/safety-docs/output/json-output)
- [SBOM Output](https://docs.safetycli.com/safety-docs/output/sbom-output)
- [HTML Output](https://docs.safetycli.com/safety-docs/output/html-output)

**Miscellaneous**
- [Release Notes](https://docs.safetycli.com/safety-docs/miscellaneous/release-notes)
- [Breaking Changes in Safety 3](https://docs.safetycli.com/safety-docs/miscellaneous/release-notes/breaking-changes-in-safety-3)
- [Safety 2.x Documentation](https://docs.safetycli.com/safety-2)
- [Support](https://docs.safetycli.com/safety-docs/miscellaneous/support)

System status is available at [https://status.safetycli.com](https://status.safetycli.com)

Further support is available by emailing support@safetycli.com.

# License
Safety is released under the MIT License.

Upon creating an account, a 7-day free trial of our Team plan is offered to new users, after which they will be downgraded to our Free plan. This plan is limited to a single user and is not recommended for commercial purposes.

Our paid [plans for commercial use](https://safetycli.com/resources/plans) begin at just $25 per seat per month and allow scans to be performed using our full vulnerability database, complete with 3x more tracked vulnerabilities and malicious packages than our free plan and other providers. To learn more about our Team and Enterprise plans, please visit [https://safetycli.com/resources/plans](https://safetycli.com/resources/plans) or email sales@safetycli.com.

# Supported Python Versions
Safety CLI 3 supports Python versions >=3.7. Further details on supported versions, as well as options to run Safety CLI on versions <3.7 using a Docker image are available in our [Documentation Hub](https://docs.safetycli.com).

We maintain a policy of supporting all maintained and secure versions of Python, plus one minor version below the oldest maintained and secure version. Details on Python versions that meet these criteria can be found here: https://endoflife.date/python.

# Resources

- [Safety Cybersecurity website](https://safetycli.com)
- [Safety Login Page](https://safetycli.com/login)
- [Documentation](https://docs.safetycli.com)
- [Careers/Hiring](https://apply.workable.com/safety/)
- [Security Research and Blog](https://safetycli.com/blog)
- [GitHub Action](https://github.com/safetycli/action)
- [Support](mailto:support@safetycli.com)
- [Status Page](https://status.safetycli.com)

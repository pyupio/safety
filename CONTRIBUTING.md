# Contributing to SafetyCLI

First off, thanks for taking the time to contribute! We welcome contributions from everyone and are grateful for your help in making SafetyCLI better.

## Table of Contents
- [Contributing to SafetyCLI](#contributing-to-safetycli)
  - [Table of Contents](#table-of-contents)
  - [How Can I Contribute?](#how-can-i-contribute)
    - [Reporting Bugs](#reporting-bugs)
    - [Suggesting Enhancements](#suggesting-enhancements)
    - [Improving Documentation](#improving-documentation)
  - [Getting Started](#getting-started)
    - [Code of Conduct](#code-of-conduct)
    - [Development Setup](#development-setup)
    - [Running Tests](#running-tests)
  - [Pull Request Process](#pull-request-process)
    - [Commit Messages](#commit-messages)
    - [Merging Changes](#merging-changes)
  - [License](#license)

## How Can I Contribute?

### Reporting Bugs

If you find a bug, please report it by opening a [GitHub issue](https://github.com/pyupio/safety/issues). When reporting a bug, please include:
- A clear and descriptive title.
- Steps to reproduce the issue.
- Expected and actual behavior.
- Any relevant logs or screenshots.
- The version of SafetyCLI and Python you are using.

If your bug report has security implications or involves a potential vulnerability, we encourage you to participate in our [Bug Bounty Program](https://safetycli.com/resources/bug-bounty). Your responsible disclosure will help us improve the security of our software and may be eligible for a reward.

Please use the appropriate label when creating an issue:
- `bug`: Indicates a problem that needs to be resolved.
- `Critical`: Issues that break core functionality or pose significant security vulnerabilities.
- `High`, `Medium`, `Low`: Significance of bugs affecting users.

### Suggesting Enhancements

To suggest an enhancement, open an issue with details on the proposed improvement:
- A detailed description of the enhancement.
- A rationale for why the enhancement is needed.
- Any possible alternatives or workarounds.

Please use the following label:
- `enhancement`: Suggests an improvement or new feature.

### Improving Documentation

Improving documentation is one of the best ways to contribute. You can suggest improvements, correct typos, or add new sections. The documentation is located [here](https://docs.safetycli.com/safety-docs).

Please use the following label:
- `documentation`: Indicates issues related to documentation improvements or updates.

Before submitting code changes, please ensure:
- Your changes are focused on a single issue or feature.
- You have written tests for your changes.
- All tests pass locally.

Please use the following labels as needed:
- `help wanted`: Requests assistance from the community or other contributors.
- `good first issue`: Highlights issues that are suitable for first-time contributors.

## Getting Started

### Code of Conduct

Please read and adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) to ensure a welcoming environment for all contributors.

### Development Setup
1. **Clone the repository:**
   ```bash
   git clone https://github.com/pyupio/safety.git
   ```

2. **Set up your environment:**
- Ensure you are using Python 3.11.2.
- Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

### Running Tests
We use pytest for running tests. To run the tests locally:
    ```pytest```

Ensure all tests pass before submitting your changes.

## Pull Request Process

### Commit Messages

We follow Conventional Commits for our commit messages. Please ensure your commits adhere to this specification.
Use the following format:

```markdown
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Merging Changes
- Ensure all CI checks pass.
- A project maintainer will review and merge the pull request.
- Pull requests require at least one approval before merging.

## License
By contributing to SafetyCLI, you agree that your contributions will be licensed under the same [MIT License](https://github.com/pyupio/safety/blob/main/LICENSE) that covers the project.

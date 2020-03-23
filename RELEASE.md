# Release

Safety is distributed as a binary for Windows 32/64 bit, Linux 32/64 bit and macOS 64 bit.
The binary is built on appveyor (see `appveyor.py` and `appveyor.yml`) and distributed through GitHub.

## Issuing a new release

First, update the version string in `setup.py` and `safety/__init__.py` and push the changes to master.

Make sure the release builds properly on appveyor prior to tagging it.

To issue a new release, tag the release with `git tag 1.x.x` and push the tag with `git push origin --tags`.
Once the build is completed and all artifacts are collected, the binaries are uploaded as a GitHub release.


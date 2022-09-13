# Release

Safety is distributed as a binary for Windows 32/64 bit, Linux 32/64 bit and macOS 64 bit.
The binary is built on appveyor (see `appveyor.py` and `appveyor.yml`) and distributed through GitHub.

## Issuing a new release

First, review and update the `CHANGELOG.md` file; then the version string in `safety/VERSION` and `appveyor.yml` and push the changes to master.

Make sure the release builds properly on appveyor prior to tagging it.

To issue a new release, tag the release with `git tag -s -a 1.x.x -m "Small description"` and push the tag with `git push origin --tags`.
Once the build is completed and all artifacts are collected, the binaries are uploaded as a GitHub release.

### Note:

Use standard PEP 440 versions, verify if the version to tag matches the current AppVeyor and Travis regexes.

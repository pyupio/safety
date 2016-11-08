# -*- coding: utf-8 -*-
from __future__ import absolute_import
import os
import pip
import sys
import click
from safety import __version__
from safety import safety
from safety.formatter import report
from pkg_resources import parse_requirements
from collections import namedtuple
import itertools

Package = namedtuple("Package", ["key", "version"])


def read_requirements(fh, resolve=False):
    """
    Reads requirements from a file like object and (optionally) from referenced files.
    :param fh: file like object to read from
    :param resolve: boolean. resolves referenced files.
    :return: generator
    """
    # filter out all "non-requirement" lines and resolve all referenced files.
    # "non-requirement" lines typically begin with a dash, e.g:
    # -e git://some-repo, or --index-server=https://foo.bar
    # lines referenced files start with a '-r'
    reqs = []
    for line in fh.readlines():
        if resolve and (line.startswith("-r") or line.startswith("--requirement")):
            # got a referenced file here, resolve it
            filename = line.strip("-r ").strip("--requirement").strip()
            # if there is a comment, remove it
            if " #" in filename:
                filename = filename.split(" #")[0].strip()
            basepath = os.path.dirname(fh.name)
            req_file = os.path.join(basepath, filename)
            if os.path.exists(req_file):
                # recursively yield the resolved requirements
                with open(req_file) as _fh:
                    for req in read_requirements(_fh, resolve=True):
                        yield req
        elif not line.startswith("-"):
            reqs.append(line)

    for req in parse_requirements("\n".join(reqs)):
        if len(req.specs) == 1 and req.specs[0][0] == "==":
            yield Package(key=req.key, version=req.specs[0][1])
        else:
            click.secho(
                "Warning: unpinned requirement '{req}' found, unable to check.".format(req=req.key),
                fg="yellow"
            )


@click.group()
@click.version_option(version=__version__)
def cli():
    pass


@cli.command()
@click.option("--full-report/--short-report", default=False)
@click.option("--stdin/--no-stdin", default=False)
@click.option("files", "--file", "-r", multiple=True, type=click.File())
def check(full_report, stdin, files):

    if files and stdin:
        click.secho("Can't read from --stdin and --file at the same time, exiting", fg="red")
        sys.exit(-1)

    if files:
        packages = itertools.chain.from_iterable(read_requirements(f, resolve=True) for f in files)
    elif stdin:
        packages = read_requirements(sys.stdin)
    else:
        packages = pip.get_installed_distributions()

    vulns = safety.check(packages=packages)
    click.secho(report(vulns=vulns, full=full_report))
    sys.exit(-1 if vulns else 0)


if __name__ == "__main__":
    cli()

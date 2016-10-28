# -*- coding: utf-8 -*-
from __future__ import absolute_import
import pip
import sys
import click
from safety import __version__
from safety import safety
from safety.formatter import report
from pkg_resources import parse_requirements
from collections import namedtuple

Package = namedtuple("Package", ["key", "version"])


def read_requirements(fh):
    for req in parse_requirements(fh.read()):
        if len(req.specs) == 1 and req.specs[0][0] == "==":
            yield Package(key=req.key, version=req.specs[0][1])
        else:
            click.secho(
                "Warning: unable to check {req}, because it is unpinned. Make sure to always "
                "pin your requirements like this '{req}==1.2.3'.".format(req=req.key),
                fg="red"
            )


@click.group()
@click.version_option(version=__version__)
def cli():
    pass


@cli.command()
@click.option("--full-report/--short-report", default=False)
@click.option("--stdin/--no-stdin", default=False)
def check(full_report, stdin):

    packages = read_requirements(sys.stdin) if stdin else pip.get_installed_distributions()

    vulns = safety.check(packages=packages)
    click.secho(report(vulns=vulns, full=full_report))
    sys.exit(-1 if vulns else 0)


if __name__ == "__main__":
    cli()

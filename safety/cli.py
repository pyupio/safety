# -*- coding: utf-8 -*-
from __future__ import absolute_import
import sys
import click
from safety import __version__
from safety import safety
from safety.formatter import report


@click.group()
@click.version_option(version=__version__)
def cli():
    pass


@cli.command()
@click.option("--full-report/--short-report", default=False)
def check(full_report):
    vulns = safety.check()
    click.secho(report(vulns=vulns, full=full_report))
    sys.exit(-1 if vulns else 0)


if __name__ == "__main__":
    cli()

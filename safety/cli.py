# -*- coding: utf-8 -*-
from __future__ import absolute_import
import pip
import sys
import click
from safety import __version__
from safety import safety
from safety.formatter import report


def read_requirements_func():
    with open('requirements.txt', 'r') as fh:
        for line in fh.readlines():
            parts = line.strip().split('>=')
            if len(parts) > 1:
                print(parts)
                yield pip._vendor.pkg_resources.EggInfoDistribution(
                          project_name=parts[0], version=parts[1])


@click.group()
@click.version_option(version=__version__)
def cli():
    pass


@cli.command()
@click.option("--full-report/--short-report", default=False)
@click.option("--read-requirements/--no-read-requirements", default=False)
def check(full_report, read_requirements):
    if read_requirements:
        vulns = safety.check(read_requirements_func)
    else:
        vulns = safety.check()
    click.secho(report(vulns=vulns, full=full_report))
    sys.exit(-1 if vulns else 0)


if __name__ == "__main__":
    cli()

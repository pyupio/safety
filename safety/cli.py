# -*- coding: utf-8 -*-
from __future__ import absolute_import
import pip
import sys
import click
from safety import __version__
from safety import safety
from safety.formatter import report
import itertools
from safety.util import read_requirements
from safety.errors import DatabaseFetchError, DatabaseFileNotFoundError, InvalidKeyError

@click.group()
@click.version_option(version=__version__)
def cli():
    pass


@cli.command()
@click.option("--key", default="")
@click.option("--db", default="")
@click.option("--full-report/--short-report", default=False)
@click.option("--cache/--no-cache", default=False)
@click.option("--stdin/--no-stdin", default=False)
@click.option("files", "--file", "-r", multiple=True, type=click.File())
def check(key, db, full_report, stdin, files, cache):

    if files and stdin:
        click.secho("Can't read from --stdin and --file at the same time, exiting", fg="red")
        sys.exit(-1)

    if files:
        packages = itertools.chain.from_iterable(read_requirements(f, resolve=True) for f in files)
    elif stdin:
        packages = read_requirements(sys.stdin)
    else:
        packages = pip.get_installed_distributions()

    try:
        vulns = safety.check(packages=packages, key=key, db_mirror=db, cached=cache)
        click.secho(report(vulns=vulns, full=full_report))
        sys.exit(-1 if vulns else 0)
    except InvalidKeyError:
        click.secho("Your API Key is invalid", fg="red")
        sys.exit(-1)
    except DatabaseFileNotFoundError:
        click.secho("Unable to load vulnerability database from {db}".format(db=db), fg="red")
        sys.exit(-1)
    except DatabaseFetchError:
        click.secho("Unable to load vulnerability database", fg="red")
        sys.exit(-1)


if __name__ == "__main__":
    cli()

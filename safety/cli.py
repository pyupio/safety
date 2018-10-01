# -*- coding: utf-8 -*-
from __future__ import absolute_import
import sys
import click
from safety import __version__
from safety import safety
from safety.formatter import report
import itertools
from safety.util import read_requirements
from safety.errors import DatabaseFetchError, DatabaseFileNotFoundError, InvalidKeyError


try:
    # pip 9
    from pip import get_installed_distributions
except ImportError:
    # pip 10
    from pip._internal.utils.misc import get_installed_distributions


@click.group()
@click.version_option(version=__version__)
def cli():
    pass


@cli.command()
@click.option("--key", default="",
              help="API Key for pyup.io's vulnerability database. Can be set as SAFETY_API_KEY "
                   "environment variable. Default: empty")
@click.option("--db", default="",
              help="Path to a local vulnerability database. Default: empty")
@click.option("--json/--no-json", default=False,
              help="Output vulnerabilities in JSON format. Default: --no-json")
@click.option("--full-report/--short-report", default=False,
              help='Full reports include a security advisory (if available). Default: '
                   '--short-report')
@click.option("--bare/--not-bare", default=False,
              help='Output vulnerable packages only. Useful in combination with other tools.'
                   'Default: --not-bare')
@click.option("--cache/--no-cache", default=False,
              help="Cache requests to the vulnerability database locally. Default: --no-cache")
@click.option("--stdin/--no-stdin", default=False,
              help="Read input from stdin. Default: --no-stdin")
@click.option("files", "--file", "-r", multiple=True, type=click.File(),
              help="Read input from one (or multiple) requirement files. Default: empty")
@click.option("ignore", "--ignore", "-i", multiple=True, type=str, default=[],
              help="Ignore one (or multiple) vulnerabilities by ID. Default: empty")
@click.option("proxyhost", "--proxy-host", "-ph", multiple=False, type=str, default=None,
              help="Proxy host IP or DNS --proxy-host")
@click.option("proxyport", "--proxy-port", "-pp", multiple=False, type=int, default=80,
              help="Proxy port number --proxy-port")
@click.option("proxyprotocol", "--proxy-protocol", "-pr", multiple=False, type=str, default='http',
              help="Proxy protocol (https or http) --proxy-protocol")
def check(key, db, json, full_report, bare, stdin, files, cache, ignore, proxyprotocol, proxyhost, proxyport):

    if files and stdin:
        click.secho("Can't read from --stdin and --file at the same time, exiting", fg="red")
        sys.exit(-1)

    if files:
        packages = list(itertools.chain.from_iterable(read_requirements(f, resolve=True) for f in files))
    elif stdin:
        packages = list(read_requirements(sys.stdin))
    else:
        packages = get_installed_distributions()
    proxy_dictionary = {}
    if proxyhost is not None:
        if proxyprotocol in ["http", "https"]:
            proxy_dictionary = {proxyprotocol: "{0}://{1}:{2}".format(proxyprotocol, proxyhost, str(proxyport))}
        else:
            click.secho("Proxy Protocol should be http or https only.", fg="red")
            sys.exit(-1)
    try:
        vulns = safety.check(packages=packages, key=key, db_mirror=db, cached=cache, ignore_ids=ignore, proxy=proxy_dictionary)
        click.secho(report(
            vulns=vulns,
            full=full_report,
            json_report=json,
            bare_report=bare,
            checked_packages=len(packages),
            db=db,
            key=key
            )
        )
        sys.exit(-1 if vulns else 0)
    except InvalidKeyError:
        click.secho("Your API Key '{key}' is invalid. See {link}".format(
            key=key, link='https://goo.gl/O7Y1rS'),
            fg="red")
        sys.exit(-1)
    except DatabaseFileNotFoundError:
        click.secho("Unable to load vulnerability database from {db}".format(db=db), fg="red")
        sys.exit(-1)
    except DatabaseFetchError:
        click.secho("Unable to load vulnerability database", fg="red")
        sys.exit(-1)


if __name__ == "__main__":
    cli()

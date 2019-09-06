# -*- coding: utf-8 -*-
from __future__ import absolute_import
from distutils import cmd
import os

from safety import cli

class SafetyCommand(cmd.Command):
    description = 'Check this project using the safety utility'
    user_options = [
        ("bare", None, "Output vulnerable packages only."),
        ("cache", None, "Cache requests to vulnerability database locally."),
        ("db=", None, "Path to a local vulnerability database."),
        ("files=", None, "Read input from one or more requirement files."),
        ("full-report", None, "Generate a full report."),
        ("ignore=", None, "Ignore one or more vulnerabilities by ID."),
        ("json", None, "Output vulnerabilities in JSON format."),
        ("key=", None, "API key for pyup.io's vulnerability database."),
        ("output=", None, "Path to where output file will be placed."),
        ("proxy-host=", None, "Proxy host IP or DNS."),
        ("proxy-port=", None, "Proxy port number."),
        ("proxy-protocol=", None, "Proxy protocol (https or http)."),
        ("stdin", None, "Read input from stdin."),
    ]
    boolean_options = ["bare", "cache", "full-report", "json", "stdin"]

    def initialize_options(self):
        self.bare = False
        self.cache = False
        self.db = ""
        self.files = []
        self.full_report = False
        self.ignore = []
        self.json = False
        self.key = os.environ.get("SAFETY_API_KEY", "")
        self.output = ""
        self.proxy_host = None
        self.proxy_port = None
        self.proxy_protocol = None
        self.stdin = False

    def finalize_options(self):  # pragma: no-cover
        if len(self.files) > 0:
            self.ensure_string_list("files")
        if len(self.ignore) > 0:
            self.ensure_string_list("ignore")

    def run(self):
        args = []
        if self.bare:
            args.append("--bare")
        if self.cache:
            args.append("--cache")
        if self.db:
            args.extend(["--db", self.db])
        for file_name in self.files:
            args.extend(["--files", file_name])
        if self.full_report:
            args.append("--full-report")
        for ignore_id in self.ignore:
            args.extend(["--ignore", ignore_id])
        if self.json:
            args.append("--json")
        if self.key:
            args.extend(["--key", self.key])
        if self.output:
            args.extend(["--output", self.output])
        if self.proxy_host:
            args.extend(["--proxy-host", self.proxy_host])
            if self.proxy_protocol:
                args.extend(["--proxy-protocol", self.proxy_protocol])
            if self.proxy_port:
                args.extend(["--proxy-port", self.proxy_port])
        if self.stdin:
            args.append("--stdin")
        cli.check(args=args)

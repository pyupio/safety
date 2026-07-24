# -*- coding: utf-8 -*-
"""
Safety CLI — Vulnerability scanning for Python (and other ecosystem) dependencies.

This package is the core entry point for the Safety CLI tool. It provides
vulnerability scanning, policy enforcement, authentication, event tracking,
and tool-interception (firewall) capabilities for Python and npm ecosystems.

Top-level modules:
    - cli:          Click/Typer command-line interface definitions
    - safety:       Core vulnerability database fetching, caching, and checking
    - auth:         Authentication (OAuth2, API keys, machine enrollment)
    - scan:         Modern scan command (project & system scans)
    - tool:         Package-tool interception (pip, poetry, uv, npm)
    - firewall:     Package firewall for proxy-based security
    - config:       Configuration management
    - events:       Telemetry and security-event emission
    - models:       Data models (Vulnerability, Package, etc.)
    - formatters:   Report output formatting (screen, json, html, bare, text)

Sub-packages:
    - alerts:       Deprecated alert/notification system
    - codebase:     Codebase initialization and management
    - init:         Safety init workflow (project setup)
"""

__author__ = """safetycli.com"""
__email__ = "cli@safetycli.com"

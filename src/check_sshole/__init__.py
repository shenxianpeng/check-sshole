"""check-sshole: find Dockerfiles that ship an sshd exposed to *sshole (CVE-2026-123158)."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from check_sshole.checker import CVE, Finding, check

try:
    __version__ = version('check-sshole')
except PackageNotFoundError:  # run from a source checkout, as the GitHub Action does
    __version__ = '0+unknown'

__all__ = ['CVE', 'Finding', '__version__', 'check']

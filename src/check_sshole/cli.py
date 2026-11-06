"""check-sshole [PATH ...]: scan Dockerfiles, or folders of them, for *sshole."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from check_sshole import __version__
from check_sshole.checker import CVE, INFO_URL, Finding, check, read_text

# Folders that hold other people's code or tool state, not your Dockerfiles.
SKIP_DIRS = frozenset({
    '.git', '.hg', '.svn', 'node_modules', '.venv', 'venv', '.tox', '.nox',
    '__pycache__', '.mypy_cache', '.pytest_cache', '.ruff_cache', '.terraform',
})
_KINDS = ('dockerfile', 'containerfile')
_NOT_DOCKERFILES = ('.dockerignore', '.md', '.rst', '.txt')

EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def is_dockerfile(name: str) -> bool:
    """Dockerfile, Containerfile, Dockerfile.prod, app.Dockerfile, and so on."""
    name = name.lower()
    if name.endswith(_NOT_DOCKERFILES):
        return False
    return any(name == kind or name.startswith(f'{kind}.') or name.endswith(f'.{kind}') for kind in _KINDS)


def _display(path: str) -> str:
    return Path(os.path.normpath(path)).as_posix()


def collect(paths: Sequence[str]) -> tuple[list[str], list[str]]:
    """The Dockerfiles to check, and the paths that do not exist.

    Files are taken as given (pre-commit has already picked them); folders
    are searched for Dockerfiles.
    """
    files: list[str] = []
    missing: list[str] = []
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, names in os.walk(path):
                dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS)
                files.extend(_display(os.path.join(root, name)) for name in sorted(names) if is_dockerfile(name))
        elif os.path.exists(path):
            files.append(_display(path))
        else:
            missing.append(path)
    return list(dict.fromkeys(files)), missing


def _plural(count: int, word: str) -> str:
    return f'{count} {word}' if count == 1 else f'{count} {word}s'


def summary(files: int, findings: int, errors: int) -> str:
    if not files and not errors:
        return 'check-sshole: no Dockerfiles found'
    text = f'check-sshole: {_plural(findings, "finding")} in {_plural(files, "Dockerfile")}'
    if errors:
        text += f', {_plural(errors, "path")} could not be read'
    return text


def to_json(files: int, findings: list[Finding], errors: list[tuple[str, str]]) -> str:
    return json.dumps({
        'version': __version__,
        'files': files,
        'findings': [
            {
                'rule': finding.rule,
                'cve': CVE,
                'path': finding.path,
                'line': finding.lineno,
                'message': finding.lines[0],
                'details': [line.strip() for line in finding.lines[1:]],
            }
            for finding in findings
        ],
        'errors': [{'path': path, 'error': error} for path, error in errors],
    }, indent=2)


def _escape(text: str, prop: bool = False) -> str:
    """Escape text for a GitHub workflow command (``::error file=...::message``)."""
    text = text.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')
    if prop:
        text = text.replace(':', '%3A').replace(',', '%2C')
    return text


def to_github(finding: Finding) -> str:
    title = _escape(f'*sshole ({CVE})', prop=True)
    return f'::error file={_escape(finding.path, prop=True)},line={finding.lineno},title={title}::' + _escape(
        '\n'.join(finding.lines)
    )


def _cell(text: str) -> str:
    return text.replace('|', '\\|').replace('*', '\\*')


def step_summary(files: int, findings: list[Finding], errors: list[tuple[str, str]]) -> str:
    """Markdown for the GitHub job summary page."""
    lines = ['### check-sshole', '', summary(files, len(findings), len(errors)).replace('check-sshole: ', '', 1), '']
    if findings:
        lines += ['| File | Line | Finding |', '|---|---|---|']
        lines += [f'| `{_cell(f.path)}` | {f.lineno} | {_cell(f.lines[0])} |' for f in findings]
        lines += ['', f'How to fix: {INFO_URL} and the `fix:` lines in the job log.', '']
    return '\n'.join(lines) + '\n'


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog='check-sshole',
        description=f'Find Dockerfiles that ship an sshd exposed to *sshole ({CVE}).',
        epilog='Exit status: 0 nothing found, 1 findings, 2 a path could not be read.',
    )
    parser.add_argument(
        'paths', nargs='*', metavar='PATH', help='Dockerfiles or folders to scan (default: the current folder)'
    )
    parser.add_argument(
        '--format', choices=('text', 'json', 'github'), default='text',
        help='github prints workflow annotations and writes a job summary (default: text)',
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    args = parser.parse_args(argv)

    files, missing = collect(args.paths or ['.'])
    errors = [(path, 'no such file or folder') for path in missing]
    findings: list[Finding] = []
    checked = 0
    for path in files:
        text = read_text(Path(path))
        if text is None:
            errors.append((path, 'cannot read file'))
            continue
        checked += 1
        findings.extend(check(text, path))

    if args.format == 'json':
        print(to_json(checked, findings, errors))
    else:
        for finding in findings:
            print(to_github(finding) if args.format == 'github' else finding.render() + '\n')
        sys.stdout.flush()  # keep stderr lines after the findings when both go to one pipe
        for path, error in errors:
            if args.format == 'github':
                print(f'::error file={_escape(path, prop=True)}::{_escape(error)}')
            else:
                print(f'{path}: {error}', file=sys.stderr)
        print(summary(checked, len(findings), len(errors)), file=sys.stderr)
        summary_file = os.environ.get('GITHUB_STEP_SUMMARY')
        if args.format == 'github' and summary_file:
            with open(summary_file, 'a', encoding='utf-8') as handle:
                handle.write(step_summary(checked, findings, errors))

    if errors:
        return EXIT_ERROR
    return EXIT_FINDINGS if findings else EXIT_CLEAN

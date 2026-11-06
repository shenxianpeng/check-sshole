"""Tests for the check-sshole command: finding Dockerfiles, output formats, exit status."""

from __future__ import annotations

import importlib
import importlib.metadata
import json
import runpy
import sys
from pathlib import Path

import pytest

import check_sshole
from check_sshole import cli

SSHD_ON_ALPINE = 'FROM alpine:3.22\nRUN apk add openssh-server\n'
CLEAN = 'FROM alpine:3.22\nRUN apk add curl\n'


@pytest.fixture(autouse=True)
def in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv('GITHUB_STEP_SUMMARY', raising=False)
    return tmp_path


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


# --- finding Dockerfiles -----------------------------------------------------


@pytest.mark.parametrize(
    'name',
    ['Dockerfile', 'dockerfile', 'Containerfile', 'Dockerfile.prod', 'app.Dockerfile', 'app.dockerfile',
     'base.containerfile', 'Dockerfile.alpine.j2'],
)
def test_is_dockerfile(name: str) -> None:
    assert cli.is_dockerfile(name)


@pytest.mark.parametrize(
    'name',
    ['Dockerfile.dockerignore', 'Dockerfile.md', 'dockerfile.txt', 'README.md', 'docker-compose.yml',
     'Dockerfiles', 'mydockerfile', '.dockerignore'],
)
def test_is_not_dockerfile(name: str) -> None:
    assert not cli.is_dockerfile(name)


def test_collect_walks_folders(in_tmp_path: Path) -> None:
    for name in ['Dockerfile', 'b/Dockerfile.prod', 'a/app.Dockerfile', '.devcontainer/Dockerfile', 'a/README.md']:
        write(in_tmp_path / name, CLEAN)
    files, missing = cli.collect(['.'])
    # Top-down: a folder's own Dockerfiles first, then its subfolders in name order.
    assert files == ['Dockerfile', '.devcontainer/Dockerfile', 'a/app.Dockerfile', 'b/Dockerfile.prod']
    assert missing == []


def test_collect_skips_vendored_and_tool_folders(in_tmp_path: Path) -> None:
    for folder in sorted(cli.SKIP_DIRS):
        write(in_tmp_path / folder / 'Dockerfile', CLEAN)
    write(in_tmp_path / 'docker' / 'Dockerfile', CLEAN)
    assert cli.collect(['.']) == (['docker/Dockerfile'], [])


def test_collect_takes_files_as_given(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'build' / 'image.def', CLEAN)  # not a Dockerfile name, but asked for
    write(in_tmp_path / 'Dockerfile', CLEAN)
    files, missing = cli.collect(['./build/image.def', 'Dockerfile', '.', 'nope', 'build/../Dockerfile'])
    assert files == ['build/image.def', 'Dockerfile']
    assert missing == ['nope']


# --- summary and formats -----------------------------------------------------


@pytest.mark.parametrize(
    ('counts', 'text'),
    [
        ((0, 0, 0), 'check-sshole: no Dockerfiles found'),
        ((1, 0, 0), 'check-sshole: 0 findings in 1 Dockerfile'),
        ((3, 1, 0), 'check-sshole: 1 finding in 3 Dockerfiles'),
        ((2, 2, 1), 'check-sshole: 2 findings in 2 Dockerfiles, 1 path could not be read'),
        ((0, 0, 2), 'check-sshole: 0 findings in 0 Dockerfiles, 2 paths could not be read'),
    ],
)
def test_summary(counts: tuple[int, int, int], text: str) -> None:
    assert cli.summary(*counts) == text


def test_escape() -> None:
    assert cli._escape('50%\r\nnext: a,b') == '50%25%0D%0Anext: a,b'
    assert cli._escape('dir:a,b', prop=True) == 'dir%3Aa%2Cb'


def test_markdown_cells_are_escaped() -> None:
    assert cli._cell('a|b *c*') == 'a\\|b \\*c\\*'


def test_step_summary_without_findings() -> None:
    assert cli.step_summary(2, [], []) == '### check-sshole\n\n0 findings in 2 Dockerfiles\n\n'


# --- main --------------------------------------------------------------------


def test_clean_file(in_tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(in_tmp_path / 'Dockerfile', CLEAN)
    assert cli.main(['Dockerfile']) == 0
    out, err = capsys.readouterr()
    assert out == ''
    assert err == 'check-sshole: 0 findings in 1 Dockerfile\n'


def test_scans_the_current_folder_by_default(in_tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(in_tmp_path / 'svc' / 'Dockerfile', SSHD_ON_ALPINE)
    assert cli.main([]) == 1
    out, err = capsys.readouterr()
    assert out.startswith("svc/Dockerfile:2: sshd from 'openssh-server' on 'alpine:3.22' accepts password logins")
    assert out.endswith('above line 2)\n\n')
    assert err == 'check-sshole: 1 finding in 1 Dockerfile\n'


def test_no_dockerfiles(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(['.']) == 0
    assert capsys.readouterr().err == 'check-sshole: no Dockerfiles found\n'


def test_reports_every_file(in_tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(in_tmp_path / 'ok.Dockerfile', CLEAN)
    write(in_tmp_path / 'a.Dockerfile', SSHD_ON_ALPINE)
    write(in_tmp_path / 'b.Dockerfile', SSHD_ON_ALPINE)
    assert cli.main(['.']) == 1
    out, err = capsys.readouterr()
    assert [line.split(':', 1)[0] for line in out.splitlines() if 'sshd from' in line] == ['a.Dockerfile', 'b.Dockerfile']
    assert err == 'check-sshole: 2 findings in 3 Dockerfiles\n'


def test_missing_path(in_tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(in_tmp_path / 'Dockerfile', SSHD_ON_ALPINE)
    assert cli.main(['Dockerfile', 'missing/Dockerfile']) == 2
    out, err = capsys.readouterr()
    assert out.startswith('Dockerfile:2: ')
    assert err == (
        'missing/Dockerfile: no such file or folder\n'
        'check-sshole: 1 finding in 1 Dockerfile, 1 path could not be read\n'
    )


def test_unreadable_file(
    in_tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write(in_tmp_path / 'Dockerfile', CLEAN)
    monkeypatch.setattr(cli, 'read_text', lambda path: None)
    assert cli.main(['Dockerfile']) == 2
    assert capsys.readouterr().err == (
        'Dockerfile: cannot read file\ncheck-sshole: 0 findings in 0 Dockerfiles, 1 path could not be read\n'
    )


def test_json_format(in_tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(in_tmp_path / 'Dockerfile', SSHD_ON_ALPINE)
    assert cli.main(['--format', 'json', 'Dockerfile', 'gone']) == 2
    out, err = capsys.readouterr()
    assert err == ''
    data = json.loads(out)
    assert data['version'] == check_sshole.__version__
    assert data['files'] == 1
    assert data['errors'] == [{'path': 'gone', 'error': 'no such file or folder'}]
    (finding,) = data['findings']
    assert finding['rule'] == 'sshole'
    assert finding['cve'] == 'CVE-2026-123158'
    assert (finding['path'], finding['line']) == ('Dockerfile', 2)
    assert finding['message'].startswith("sshd from 'openssh-server' on 'alpine:3.22'")
    assert finding['details'][0].startswith('why: ')
    assert finding['details'][-1].startswith('more: https://sshhole.com/')


def test_json_format_when_clean(in_tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(in_tmp_path / 'Dockerfile', CLEAN)
    assert cli.main(['--format=json']) == 0
    assert json.loads(capsys.readouterr().out)['findings'] == []


def test_github_format(in_tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write(in_tmp_path / 'svc' / 'Dockerfile', SSHD_ON_ALPINE)
    assert cli.main(['--format', 'github', '.', 'gone']) == 2
    out, err = capsys.readouterr()
    annotation, error = out.splitlines()
    assert annotation.startswith(
        "::error file=svc/Dockerfile,line=2,title=*sshole (CVE-2026-123158)::sshd from 'openssh-server'"
    )
    assert '%0A  why: ' in annotation
    assert error == '::error file=gone::no such file or folder'
    assert err == 'check-sshole: 1 finding in 1 Dockerfile, 1 path could not be read\n'


def test_github_format_writes_the_job_summary(
    in_tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write(in_tmp_path / 'svc' / 'Dockerfile', SSHD_ON_ALPINE)
    summary = write(in_tmp_path / 'summary.md', '# earlier step\n')
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(summary))
    assert cli.main(['--format', 'github', 'svc/Dockerfile']) == 1
    assert summary.read_text() == (
        '# earlier step\n'
        '### check-sshole\n\n'
        '1 finding in 1 Dockerfile\n\n'
        '| File | Line | Finding |\n'
        '|---|---|---|\n'
        "| `svc/Dockerfile` | 2 | sshd from 'openssh-server' on 'alpine:3.22' accepts password logins:"
        ' exposed to \\*sshole (CVE-2026-123158) |\n\n'
        'How to fix: https://sshhole.com/ and the `fix:` lines in the job log.\n\n'
    )


def test_text_format_leaves_the_job_summary_alone(in_tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(in_tmp_path / 'Dockerfile', SSHD_ON_ALPINE)
    summary = write(in_tmp_path / 'summary.md', '')
    monkeypatch.setenv('GITHUB_STEP_SUMMARY', str(summary))
    assert cli.main(['Dockerfile']) == 1
    assert summary.read_text() == ''


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        cli.main(['--version'])
    assert excinfo.value.code == 0
    assert capsys.readouterr().out == f'check-sshole {check_sshole.__version__}\n'


def test_version_from_a_source_checkout(monkeypatch: pytest.MonkeyPatch) -> None:
    def not_installed(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, 'version', not_installed)
    try:
        assert importlib.reload(check_sshole).__version__ == '0+unknown'
    finally:
        monkeypatch.undo()
        importlib.reload(check_sshole)


def test_running_as_a_module(in_tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(in_tmp_path / 'Dockerfile', SSHD_ON_ALPINE)
    monkeypatch.setattr(sys, 'argv', ['check-sshole', 'Dockerfile'])
    monkeypatch.delitem(sys.modules, 'check_sshole.__main__', raising=False)
    with pytest.raises(SystemExit) as excinfo:
        runpy.run_module('check_sshole', run_name='__main__')
    assert excinfo.value.code == 1

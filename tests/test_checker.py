"""Tests for the Dockerfile check (check_sshole.checker)."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from check_sshole import checker


def findings(text: str, path: str = 'Dockerfile') -> list[checker.Finding]:
    return checker.check(textwrap.dedent(text).lstrip('\n'), path)


def flagged_lines(text: str, path: str = 'Dockerfile') -> list[int]:
    return [finding.lineno for finding in findings(text, path)]


def message(text: str, path: str = 'Dockerfile') -> str:
    (finding,) = findings(text, path)
    return finding.render()


@pytest.fixture(autouse=True)
def in_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run every test from an empty directory so COPY sources resolve predictably."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


# --- versions ----------------------------------------------------------------


@pytest.mark.parametrize(
    ('smaller', 'bigger'),
    [
        ('10.0_p1-r10', '10.0_p1-r11'),
        ('10.0_p1-r2', '10.0_p1-r10'),
        ('9.9_p2-r1', '10.0_p1-r0'),
        ('10.0', '10.0_p1'),
        ('10.0_rc1', '10.0'),
        ('10.0_alpha1', '10.0_beta1'),
        ('10.0', '10.0.1'),
        ('10.0_p1', '10.0_p1-r1'),
    ],
)
def test_version_order(smaller: str, bigger: str) -> None:
    assert checker.version_key(smaller) < checker.version_key(bigger)  # type: ignore[operator]


@pytest.mark.parametrize('version', ['latest', '', '10.0_p1-rc', 'v10.0'])
def test_unparseable_versions(version: str) -> None:
    assert checker.version_key(version) is None
    assert checker.is_fixed(version) is False


def test_unknown_suffix_sorts_like_no_suffix() -> None:
    assert checker.version_key('1.0_zzz') == ((1, 0), ((0, 0),), 0)


@pytest.mark.parametrize(
    ('version', 'fixed'),
    [
        ('10.0_p1-r11', True),
        ('10.0_p1-r12', True),
        ('10.0_p1-r10', False),
        ('9.0_p1-r6', True),
        ('9.0_p1-r5', False),
        ('10.6_p2-r0', True),
        ('10.7_p1-r0', True),
        ('11.0_p1-r0', True),
        ('8.8_p1-r1', False),  # Alpine 3.15: never fixed
        ('9.8_p1-r0', False),  # no Alpine branch ships it, so no fixed build exists
        ('10.0_p1', False),  # no -r means r0
    ],
)
def test_is_fixed(version: str, fixed: bool) -> None:
    assert checker.is_fixed(version) is fixed


def test_every_fixed_build_is_fixed() -> None:
    for build in checker.FIXED_BUILDS.values():
        assert checker.is_fixed(build)
        assert checker.fixed_build_for(build) == build


# --- base images -------------------------------------------------------------


@pytest.mark.parametrize(
    ('ref', 'branch'),
    [
        ('alpine:3.22', '3.22'),
        ('alpine:3.22.2', '3.22'),
        ('ALPINE:3.22', '3.22'),
        ('docker.io/library/alpine:3.21', '3.21'),
        ('index.docker.io/library/alpine:3.15', '3.15'),
        ('library/alpine:3.20@sha256:abc', '3.20'),
        ('alpine:edge', 'edge'),
        ('alpine:edge-20261101', 'edge'),
        ('alpine', None),
        ('alpine:latest', None),
        ('alpine:3', None),
        ('python:3.12-alpine3.22', '3.22'),
        ('node:20-alpine-3.19', '3.19'),
        ('node:20-alpine', None),
        ('golang:1.23', None),
        ('localhost:5000/alpine', None),
        ('', None),
    ],
)
def test_alpine_branch(ref: str, branch: str | None) -> None:
    assert checker.alpine_branch(ref) == branch


@pytest.mark.parametrize(
    ('branch', 'eol'),
    [('3.15', True), ('3.9', True), ('3.16', False), ('3.24', False), ('3.30', False), ('edge', False), (None, False)],
)
def test_is_eol_branch(branch: str | None, eol: bool) -> None:
    assert checker.is_eol_branch(branch) is eol


@pytest.mark.parametrize(
    ('ref', 'glibc'),
    [
        ('cgr.dev/chainguard/wolfi-base', True),
        ('cgr.dev/acme/custom:latest', True),
        ('chainguard/wolfi-base', True),
        ('ghcr.io/wolfi-dev/sdk', True),
        ('alpine:3.22', False),
        ('python:3.12-alpine', False),
    ],
)
def test_is_glibc_apk(ref: str, glibc: bool) -> None:
    assert checker.is_glibc_apk(ref) is glibc


# --- Dockerfile parsing ------------------------------------------------------


def parse(text: str) -> list[checker.Instruction]:
    return checker.parse_dockerfile(textwrap.dedent(text).lstrip('\n'))


def test_parse_joins_continuations_and_skips_comments_inside() -> None:
    (inst,) = parse(
        """
        RUN apk add \\
        # a comment in the middle

            openssh-server
        """
    )
    assert (inst.lineno, inst.keyword, inst.args) == (1, 'RUN', 'apk add     openssh-server')


def test_parse_continuation_at_end_of_file() -> None:
    (inst,) = parse('RUN apk add \\\n# trailing comment\n')
    assert inst.args == 'apk add'


def test_parse_line_numbers_and_keyword_case() -> None:
    instructions = parse(
        """
        # comment

        from alpine:3.22
        run echo hi
        """
    )
    assert [(i.lineno, i.keyword) for i in instructions] == [(3, 'FROM'), (4, 'RUN')]


def test_parse_lone_escape_line() -> None:
    (inst,) = parse('\\\n')
    assert (inst.keyword, inst.args) == ('', '')


def test_parse_escape_directive() -> None:
    (_, inst) = parse(
        """
        # escape=`
        FROM alpine:3.22
        RUN apk add `
            openssh-server
        """
    )
    assert inst.args == 'apk add     openssh-server'


def test_parse_directives_stop_at_first_other_line() -> None:
    instructions = parse(
        """
        # syntax=docker/dockerfile:1
        FROM alpine
        # escape=`
        RUN a \\
            b
        """
    )
    assert instructions[1].args == 'a     b'


def test_parse_file_of_only_directives() -> None:
    assert parse('# syntax=docker/dockerfile:1\n# escape=\\\n') == []


def test_parse_heredocs() -> None:
    (run, copy, tabbed, unterminated) = parse(
        """
        RUN <<SH
        apk add openssh-server
        SH
        COPY <<"CONF" /etc/ssh/sshd_config.d/a.conf
        PasswordAuthentication no
        CONF
        RUN <<-EOT cat
        \t\tindented
        \tEOT
        RUN cat <<OPEN
        never closed
        """
    )
    assert run.heredocs == ['apk add openssh-server']
    assert copy.heredocs == ['PasswordAuthentication no']
    assert tabbed.heredocs == ['\t\tindented']
    assert unterminated.heredocs == ['never closed']


def test_parse_two_heredocs_on_one_line() -> None:
    (inst, after) = parse(
        """
        RUN <<A <<B
        one
        A
        two
        B
        CMD x
        """
    )
    assert inst.heredocs == ['one', 'two']
    assert after.keyword == 'CMD'


def test_parse_here_string_is_not_a_heredoc() -> None:
    (inst, after) = parse(
        """
        RUN cat <<<EOF
        CMD x
        """
    )
    assert inst.heredocs == []
    assert after.keyword == 'CMD'


def test_parse_heredoc_only_for_run_copy_add() -> None:
    (cmd, after) = parse(
        """
        CMD cat <<EOF
        RUN x
        """
    )
    assert cmd.heredocs == []
    assert after.keyword == 'RUN'


def test_parse_pragma_applies_to_next_instruction_only() -> None:
    (ignored, normal) = parse(
        """
        # check-sshole: ignore
        RUN apk add openssh-server
        RUN apk add openssh-server
        """
    )
    assert ignored.ignore is True
    assert normal.ignore is False


# --- shell parsing -----------------------------------------------------------


@pytest.mark.parametrize(
    ('script', 'commands'),
    [
        ('apk add openssh', [['apk', 'add', 'openssh']]),
        ('a && b || c; d | e & f', [['a'], ['b'], ['c'], ['d'], ['e'], ['f']]),
        ('apk add openssh > /dev/null 2>&1', [['apk', 'add', 'openssh', '2']]),
        ('apk add openssh-server>=10.0', [['apk', 'add', 'openssh-server']]),
        ("apk add 'openssh-server>=10.0'", [['apk', 'add', 'openssh-server>=10.0']]),
        ('sudo -E apk add x', [['apk', 'add', 'x']]),
        ('/usr/bin/env FOO=1 BAR=2 apk add x', [['apk', 'add', 'x']]),
        ('if apk add x; then echo ok; fi', [['apk', 'add', 'x'], ['echo', 'ok'], ['fi']]),
        ('{ apk add x; }', [['apk', 'add', 'x']]),
        ('sh -c "apk add x && echo y"', [['apk', 'add', 'x'], ['echo', 'y']]),
        ('/bin/bash -c', [['/bin/bash', '-c']]),
        ('apk add \\\n  openssh', [['apk', 'add', 'openssh']]),
        ('apk add a\napk add b', [['apk', 'add', 'a'], ['apk', 'add', 'b']]),
        ('echo "unbalanced', [['echo', '"unbalanced']]),
        ("sed -i 's/#Port 22/Port 2222/' f", [['sed', '-i', 's/#Port 22/Port 2222/', 'f']]),
        ('echo "" x', [['echo', '', 'x']]),
        ('cat >', [['cat']]),
        ('', []),
    ],
)
def test_shell_commands(script: str, commands: list[list[str]]) -> None:
    assert list(checker.shell_commands(script)) == commands


# --- apk parsing -------------------------------------------------------------


@pytest.mark.parametrize(
    ('args', 'expected'),
    [
        (['add', 'openssh'], checker.ApkCall('add', ['openssh'])),
        (['--no-cache', 'add', '-U', 'a', 'b'], checker.ApkCall('add', ['a', 'b'])),
        (['add', '--virtual', '.deps', 'a'], checker.ApkCall('add', ['a'], '.deps')),
        (['add', '-t', '.deps', 'a'], checker.ApkCall('add', ['a'], '.deps')),
        (['add', '--virtual=.deps', 'a'], checker.ApkCall('add', ['a'], '.deps')),
        (['-X', 'https://mirror/edge/main', 'add', 'a'], checker.ApkCall('add', ['a'])),
        (['--repository=https://mirror', 'add', 'a'], checker.ApkCall('add', ['a'])),
        (['add', '--virtual'], checker.ApkCall('add', [], '')),
        (['del', '.deps'], checker.ApkCall('del', ['.deps'])),
        (['update'], None),
        (['upgrade', 'openssh'], None),
        (['--version'], None),
        ([], None),
    ],
)
def test_parse_apk(args: list[str], expected: checker.ApkCall | None) -> None:
    assert checker.parse_apk(args) == expected


@pytest.mark.parametrize(
    ('spec', 'parsed'),
    [
        ('openssh-server', ('openssh-server', None, None)),
        ('openssh-server=10.0_p1-r11', ('openssh-server', '=', '10.0_p1-r11')),
        ('openssh-server>=10.0_p1-r11', ('openssh-server', '>=', '10.0_p1-r11')),
        ('openssh~10.0', ('openssh', '~', '10.0')),
        ('openssh@edge', ('openssh', None, None)),
        ('openssh@edge=10.6_p2-r0', ('openssh', '=', '10.6_p2-r0')),
        ('=10', None),
        ('', None),
        ('openssh=', None),
    ],
)
def test_parse_spec(spec: str, parsed: tuple[str, str | None, str | None] | None) -> None:
    assert checker.parse_spec(spec) == parsed


# --- sshd settings -----------------------------------------------------------


@pytest.mark.parametrize(
    ('text', 'settings'),
    [
        ("echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config", {'password': 'no'}),
        ('sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" f', {'password': 'no'}),
        ('sed -i "s/^#\\?PasswordAuthentication.*/PasswordAuthentication no/" f', {'password': 'no'}),
        ('sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" f', {'password': 'yes'}),
        ("echo '#PasswordAuthentication no' >> f", {}),
        ("echo '# PasswordAuthentication no' >> f", {}),
        ('sshd -D -o PasswordAuthentication=no', {'password': 'no'}),
        ('sshd -D -oPasswordAuthentication=no', {'password': 'no'}),
        ('["sshd", "-o", "PasswordAuthentication no"]', {'password': 'no'}),
        ('passwordauthentication NO', {'password': 'no'}),
        ('echo AuthenticationMethods publickey >> f', {'methods': 'publickey'}),
        (
            'sed "s/AuthenticationMethods any/AuthenticationMethods publickey,password/"',
            {'methods': 'publickey,password'},
        ),
        ('echo UsePAM yes >> f', {'pam': 'yes'}),
        ('apk add openssh-server', {}),
    ],
)
def test_shell_settings(text: str, settings: dict[str, str]) -> None:
    assert checker.shell_settings(text) == settings


def test_config_settings_first_global_value_wins() -> None:
    text = textwrap.dedent(
        """
        # PasswordAuthentication yes
        PasswordAuthentication no
        PasswordAuthentication yes
        UsePAM yes
        AuthenticationMethods = publickey
        Port 22
        """
    )
    assert checker.config_settings(text) == {'password': 'no', 'pam': 'yes', 'methods': 'publickey'}


def test_config_settings_match_block_can_turn_passwords_on() -> None:
    text = textwrap.dedent(
        """
        PasswordAuthentication no
        Match User backup
            UsePAM no
            PasswordAuthentication yes
        """
    )
    assert checker.config_settings(text) == {'password': 'yes'}


def test_config_settings_match_block_cannot_turn_passwords_off() -> None:
    text = 'Match User x\n  PasswordAuthentication no\n'
    assert checker.config_settings(text) == {}


@pytest.mark.parametrize(
    ('settings', 'packages', 'off'),
    [
        ({'password': 'no'}, {'openssh-server'}, True),
        ({'password': 'yes'}, {'openssh-server'}, False),
        ({}, {'openssh-server'}, False),
        ({'methods': 'publickey'}, {'openssh-server'}, True),
        ({'methods': 'publickey,keyboard-interactive'}, {'openssh-server'}, True),
        ({'methods': 'publickey,password'}, {'openssh-server'}, False),
        ({'methods': 'any'}, {'openssh-server'}, False),
        ({'pam': 'yes'}, {'openssh-server-pam'}, True),
        ({'pam': 'yes'}, {'openssh-server'}, False),
        ({'pam': 'yes'}, {'openssh-server-pam', 'openssh'}, False),
        ({'pam': 'no'}, {'openssh-server-pam'}, False),
    ],
)
def test_password_logins_off(settings: dict[str, str], packages: set[str], off: bool) -> None:
    assert checker.password_logins_off(settings, packages) is off


# --- check(): what gets flagged ----------------------------------------------


def test_flags_sshd_on_alpine_with_default_config() -> None:
    text = """
        FROM alpine:3.22
        RUN apk add --no-cache openssh-server \\
            && ssh-keygen -A
        EXPOSE 22
        CMD ["/usr/sbin/sshd", "-D", "-e"]
        """
    assert message(text) == '\n'.join([
        "Dockerfile:2: sshd from 'openssh-server' on 'alpine:3.22' accepts password logins:"
        ' exposed to *sshole (CVE-2026-123158)',
        '  why: a fresh build may pull the fixed package, but nothing here requires it;'
        ' older or cached builds have the bug',
        "  fix: turn password logins off: RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config",
        '       (or start sshd with -o PasswordAuthentication=no)',
        "   or: if you need password logins, require a fixed build: apk add 'openssh-server>=10.0_p1-r11'",
        "  more: https://sshhole.com/ (to silence, put '# check-sshole: ignore' above line 2)",
    ])


@pytest.mark.parametrize('package', ['openssh', 'openssh-server', 'openssh-server-pam', 'openssh-server-krb5'])
def test_every_sshd_package_is_flagged(package: str) -> None:
    assert flagged_lines(f'FROM alpine:3.24\nRUN apk add {package}\n') == [2]


@pytest.mark.parametrize('package', ['openssh-client', 'openssh-keygen', 'openssh-sftp-server', 'dropbear'])
def test_packages_without_openssh_sshd_are_fine(package: str) -> None:
    assert flagged_lines(f'FROM alpine:3.24\nRUN apk add {package}\n') == []


FIXTURES = Path(__file__).parent / 'fixtures'


def test_fixtures() -> None:
    """CI runs the command, the hook and the Action on these two files."""
    assert flagged_lines((FIXTURES / 'safe.Dockerfile').read_text()) == []
    assert flagged_lines((FIXTURES / 'vulnerable.Dockerfile').read_text()) == [3]


def test_wolfi_and_chainguard_are_not_musl() -> None:
    assert flagged_lines('FROM cgr.dev/chainguard/wolfi-base\nRUN apk add openssh-server\n') == []


def test_unknown_base_that_uses_apk_is_flagged() -> None:
    text = """
        FROM ${BASE}
        RUN apk add openssh-server
        """
    assert "on an apk-based image accepts" in message(text)


@pytest.mark.parametrize(
    'mitigation',
    [
        "RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config",
        "RUN sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
        'RUN echo "AuthenticationMethods publickey" > /etc/ssh/sshd_config.d/keys.conf',
        'CMD ["/usr/sbin/sshd", "-D", "-o", "PasswordAuthentication=no"]',
        'ENTRYPOINT /usr/sbin/sshd -D -oPasswordAuthentication=no',
        'RUN --mount=type=cache,target=/tmp echo "PasswordAuthentication no" >> /etc/ssh/sshd_config',
        'COPY <<EOF /etc/ssh/sshd_config.d/00-keys.conf\nPasswordAuthentication no\nEOF',
    ],
)
def test_turning_password_logins_off_fixes_it(mitigation: str) -> None:
    assert flagged_lines(f'FROM alpine:3.22\nRUN apk add openssh-server\n{mitigation}\n') == []


def test_mitigation_in_the_same_run() -> None:
    text = """
        FROM alpine:3.22
        RUN apk add openssh-server && \\
            echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
        """
    assert flagged_lines(text) == []


def test_turning_password_logins_back_on_is_flagged() -> None:
    text = """
        FROM alpine:3.22
        RUN apk add openssh-server
        RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
        RUN sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
        """
    assert flagged_lines(text) == [2]


def test_cmd_override_beats_config() -> None:
    text = """
        FROM alpine:3.22
        RUN apk add openssh-server && echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
        CMD ["/usr/sbin/sshd", "-D", "-o", "PasswordAuthentication=yes"]
        """
    assert flagged_lines(text) == [2]


def test_pam_flavor_with_use_pam_is_fine() -> None:
    text = """
        FROM alpine:3.22
        RUN apk add openssh-server-pam && echo 'UsePAM yes' >> /etc/ssh/sshd_config
        """
    assert flagged_lines(text) == []


def test_heredoc_run_script_is_checked() -> None:
    text = """
        FROM alpine:3.24
        RUN <<SH
        set -e
        apk add --no-cache openssh-server
        SH
        """
    assert flagged_lines(text) == [2]


def test_exec_form_run() -> None:
    assert flagged_lines('FROM alpine:3.24\nRUN ["apk", "add", "openssh-server"]\n') == [2]
    assert flagged_lines('FROM alpine:3.24\nRUN ["/bin/sh", "-c", "apk add openssh-server"]\n') == [2]


@pytest.mark.parametrize('run', ['RUN [not json', 'RUN ["apk", 1]', 'RUN {"apk": "add"}'])
def test_broken_exec_form_falls_back_to_shell_form(run: str) -> None:
    assert flagged_lines(f'FROM alpine:3.24\n{run} && apk add openssh-server\n') == [2]


@pytest.mark.parametrize(
    ('args', 'words'),
    [('["a", "b"]', ['a', 'b']), ('["a", 1]', None), ('[1]', None), ('[x', None), ('a b', None)],
)
def test_json_list(args: str, words: list[str] | None) -> None:
    assert checker._json_list(args) == words


def test_other_apk_commands_are_ignored() -> None:
    assert flagged_lines('FROM alpine:3.24\nRUN apk update && apk upgrade && apk add openssh-server\n') == [2]


def test_bad_spec_is_skipped() -> None:
    assert flagged_lines("FROM alpine:3.24\nRUN apk add '' openssh-server\n") == [2]


# --- check(): pinned versions and branches -------------------------------------


@pytest.mark.parametrize(
    'spec',
    [
        'openssh-server=10.0_p1-r11',
        'openssh-server>=10.0_p1-r11',
        'openssh-server>10.6_p2-r0',
        'openssh-server~10.0_p1-r11',
        'openssh=10.6_p2-r0',
    ],
)
def test_pinning_a_fixed_build_is_fine(spec: str) -> None:
    assert flagged_lines(f"FROM alpine:3.22\nRUN apk add '{spec}'\n") == []


def test_pinning_a_vulnerable_build() -> None:
    text = "FROM python:3.12-alpine3.22\nRUN apk add 'openssh-server=10.0_p1-r10'\n"
    lines = message(text).splitlines()
    assert lines[0].startswith("Dockerfile:2: sshd from 'openssh-server=10.0_p1-r10' on 'python:3.12-alpine3.22'")
    assert lines[1] == '  why: 10.0_p1-r10 is a vulnerable build; the fix is in 10.0_p1-r11'
    assert "apk add 'openssh-server>=10.0_p1-r11'" in lines[4]


def test_pinning_a_version_no_branch_fixed() -> None:
    lines = message("FROM alpine:3.23\nRUN apk add 'openssh-server=9.8_p1-r0'\n").splitlines()
    assert lines[1] == '  why: 9.8_p1-r0 is a vulnerable build'
    # Falls back to the fixed build of the branch in FROM.
    assert "apk add 'openssh-server>=10.2_p1-r1'" in lines[4]


def test_upper_bound_allows_vulnerable_builds() -> None:
    lines = message("FROM alpine:3.22\nRUN apk add 'openssh-server<11'\n").splitlines()
    assert lines[1] == "  why: '<11' allows vulnerable builds"


def test_eol_branch() -> None:
    lines = message('FROM alpine:3.15\nRUN apk add openssh\n').splitlines()
    assert lines[1] == '  why: Alpine 3.15 never got a fixed openssh build'
    assert lines[4] == '   or: move to Alpine 3.16 or newer and require its fixed openssh build'


def test_eol_branch_with_pin() -> None:
    lines = message("FROM alpine:3.15\nRUN apk add 'openssh=8.8_p1-r1'\n").splitlines()
    assert lines[1:3] == [
        '  why: 8.8_p1-r1 is a vulnerable build',
        '  why: Alpine 3.15 never got a fixed openssh build',
    ]


def test_unknown_branch_points_to_the_table() -> None:
    lines = message('FROM node:20-alpine\nRUN apk add openssh-server\n').splitlines()
    assert lines[4] == (
        '   or: if you need password logins, require the fixed build for your Alpine branch:'
        ' https://github.com/shenxianpeng/check-sshole#fixed-openssh-builds-per-alpine-branch'
    )


@pytest.mark.parametrize(
    ('dockerfile', 'branch_fix'),
    [
        ('ARG ALPINE=3.21\nFROM alpine:${ALPINE}\n', '9.9_p2-r1'),
        ('ARG ALPINE=3.21\nFROM alpine:$ALPINE\n', '9.9_p2-r1'),
        ('FROM alpine:${ALPINE:-3.20}\n', '9.7_p1-r6'),
        ('ARG A=3.19 B\nARG IMAGE="alpine:${A}"\nFROM --platform=$BUILDPLATFORM $IMAGE AS final\n', '9.6_p1-r3'),
    ],
)
def test_global_args_in_from(dockerfile: str, branch_fix: str) -> None:
    assert f">={branch_fix}'" in message(dockerfile + 'RUN apk add openssh-server\n')


def test_instructions_before_first_from_other_than_arg_are_ignored() -> None:
    assert flagged_lines('LABEL x=y\nFROM alpine:3.22\nRUN apk add openssh-server\n') == [3]


def test_instructions_that_do_not_matter_are_ignored() -> None:
    text = """
        FROM alpine:3.22
        WORKDIR /srv
        ONBUILD RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
        RUN apk add openssh-server
        """
    assert flagged_lines(text) == [4]


# --- check(): apk del, ignore pragma, stages -----------------------------------


def test_apk_del_removes_sshd() -> None:
    text = """
        FROM alpine:3.22
        RUN apk add openssh-server openssh-client && apk del openssh-server
        """
    assert flagged_lines(text) == []


def test_apk_del_virtual_group() -> None:
    text = """
        FROM alpine:3.22
        RUN apk add --virtual .tmp openssh-server curl
        RUN apk del .tmp
        """
    assert flagged_lines(text) == []


def test_apk_del_unknown_package() -> None:
    assert flagged_lines('FROM alpine:3.22\nRUN apk add openssh-server && apk del curl\n') == [2]


def test_pragma_on_install_line() -> None:
    text = """
        FROM alpine:3.22
        # check-sshole: ignore
        RUN apk add openssh-server
        """
    assert flagged_lines(text) == []


def test_pragma_on_stage() -> None:
    text = """
        # Check-Sshole: Ignore  (password logins are needed and we rebuild nightly)
        FROM alpine:3.22 AS sftp
        RUN apk add openssh-server
        FROM sftp
        """
    assert flagged_lines(text) == []


def test_pragma_only_covers_its_own_install() -> None:
    text = """
        FROM alpine:3.22
        # check-sshole: ignore
        RUN apk add openssh-server
        RUN apk add openssh
        """
    assert flagged_lines(text) == [4]


def test_child_stage_inherits_install_and_can_fix_it() -> None:
    text = """
        FROM alpine:3.22 AS base
        RUN apk add openssh-server
        FROM base
        RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
        """
    assert flagged_lines(text) == []


def test_two_children_of_one_parent_report_once() -> None:
    text = """
        FROM alpine:3.22 AS base
        RUN apk add openssh-server
        FROM BASE AS a
        FROM base AS b
        """
    assert flagged_lines(text) == [2]


def test_builder_stage_that_is_not_used_as_a_base_is_still_an_image() -> None:
    text = """
        FROM alpine:3.22 AS tools
        RUN apk add openssh-server
        FROM debian:12-slim
        COPY --from=tools /usr/bin/ssh-keygen /usr/bin/
        """
    assert flagged_lines(text) == [2]


def test_findings_are_sorted_by_line() -> None:
    text = """
        FROM alpine:3.22 AS b
        RUN apk add openssh
        FROM alpine:3.22 AS a
        RUN apk add openssh-server
        """
    assert flagged_lines(text) == [2, 4]


def test_first_risky_install_is_reported() -> None:
    text = """
        FROM alpine:3.22
        RUN apk add 'openssh=10.0_p1-r11'
        RUN apk add openssh-server-pam
        RUN apk add openssh-server
        """
    assert flagged_lines(text) == [3]


# --- check(): COPY / ADD of sshd config ----------------------------------------


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip('\n'))
    return path


SSHD_ON_ALPINE = 'FROM alpine:3.22\nRUN apk add openssh-server\n'


@pytest.mark.parametrize(
    ('config', 'flagged'),
    [
        ('PasswordAuthentication no\n', []),
        ('#PasswordAuthentication no\n', [2]),
        ('PasswordAuthentication yes\n', [2]),
        ('PasswordAuthentication no\nMatch User b\n  PasswordAuthentication yes\n', [2]),
    ],
)
def test_copied_sshd_config_is_read(in_tmp_path: Path, config: str, flagged: list[int]) -> None:
    write(in_tmp_path / 'sshd_config', config)
    assert flagged_lines(SSHD_ON_ALPINE + 'COPY sshd_config /etc/ssh/sshd_config\n') == flagged


def test_copy_source_next_to_dockerfile(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'docker' / 'conf' / 'keys.conf', 'PasswordAuthentication no\n')
    text = SSHD_ON_ALPINE + 'COPY --chown=root:root conf/keys.conf /etc/ssh/sshd_config.d/\n'
    assert flagged_lines(text, 'docker/Dockerfile') == []


def test_copy_source_relative_to_repo_root(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'conf' / 'keys.conf', 'PasswordAuthentication no\n')
    text = SSHD_ON_ALPINE + 'COPY conf/keys.conf /etc/ssh/sshd_config.d/\n'
    assert flagged_lines(text, 'docker/Dockerfile') == []


def test_copy_source_with_leading_slash_is_relative_to_context(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'keys.conf', 'PasswordAuthentication no\n')
    assert flagged_lines(SSHD_ON_ALPINE + 'COPY /keys.conf /etc/ssh/sshd_config.d/\n') == []


def test_copy_exec_form(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'sshd_config', 'PasswordAuthentication no\n')
    assert flagged_lines(SSHD_ON_ALPINE + 'COPY ["sshd_config", "/etc/ssh/"]\n') == []


def test_copy_directory_into_etc_ssh(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'ssh' / 'sshd_config', 'Port 22\n')
    write(in_tmp_path / 'ssh' / 'sshd_config.d' / 'keys.conf', 'PasswordAuthentication no\n')
    assert flagged_lines(SSHD_ON_ALPINE + 'ADD ssh/ /etc/ssh/\n') == []


def test_copy_directory_where_one_file_turns_passwords_on(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'ssh' / 'a.conf', 'PasswordAuthentication no\n')
    write(in_tmp_path / 'ssh' / 'b.conf', 'PasswordAuthentication yes\n')
    assert flagged_lines(SSHD_ON_ALPINE + 'COPY ssh/ /etc/ssh/sshd_config.d/\n') == [2]


def test_copy_rootfs_to_slash(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'root' / 'etc' / 'ssh' / 'sshd_config', 'PasswordAuthentication no\n')
    assert flagged_lines(SSHD_ON_ALPINE + 'COPY root/ /\n') == []


def test_copy_rootfs_without_ssh_config(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'root' / 'etc' / 'motd', 'hi\n')
    assert flagged_lines(SSHD_ON_ALPINE + 'COPY root/ /\n') == [2]


def test_copy_unrelated_directory_is_not_scanned(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'app' / 'etc' / 'ssh' / 'sshd_config', 'PasswordAuthentication no\n')
    assert flagged_lines(SSHD_ON_ALPINE + 'COPY app/ /app/\n') == [2]


def test_sshd_config_copied_elsewhere_is_read(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'sshd_config', 'PasswordAuthentication no\n')
    assert flagged_lines(SSHD_ON_ALPINE + 'COPY sshd_config /tmp/\n') == []


def test_unrelated_file_is_not_read(in_tmp_path: Path) -> None:
    write(in_tmp_path / 'notes.txt', 'PasswordAuthentication no\n')
    assert flagged_lines(SSHD_ON_ALPINE + 'COPY notes.txt /srv/\n') == [2]


def test_heredoc_to_other_destination_is_not_config() -> None:
    text = SSHD_ON_ALPINE + 'COPY <<EOF /srv/readme\nPasswordAuthentication no\nEOF\n'
    assert flagged_lines(text) == [2]


@pytest.mark.parametrize(
    ('copy', 'source'),
    [
        ('COPY missing/sshd_config /etc/ssh/sshd_config', 'missing/sshd_config'),
        ('COPY --from=builder /etc/ssh/ /etc/ssh/', '/etc/ssh/'),
        ('COPY conf/*.conf /etc/ssh/sshd_config.d/', 'conf/*.conf'),
        ('ADD https://example.com/sshd_config /etc/ssh/', 'https://example.com/sshd_config'),
        ('COPY ${CONF} /etc/ssh/sshd_config', '${CONF}'),
        ('COPY "sshd_config /etc/ssh/', '"sshd_config'),  # unbalanced quote
    ],
)
def test_unreadable_config_gets_a_note(copy: str, source: str) -> None:
    lines = message(SSHD_ON_ALPINE + copy + '\n').splitlines()
    assert lines[-2] == (
        f'  note: line 3 copies {source} into /etc/ssh but it could not be read here, so its settings were not checked'
    )


@pytest.mark.parametrize(
    'copy',
    [
        'COPY --from=keys /keys/ssh_host_ed25519_key /etc/ssh/',
        'COPY missing.txt /srv/',
        'COPY onlyonearg',
    ],
)
def test_copies_that_cannot_hold_config_get_no_note(copy: str) -> None:
    assert 'note:' not in message(SSHD_ON_ALPINE + copy + '\n')


def test_unreadable_file_gets_a_note(in_tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    write(in_tmp_path / 'sshd_config', 'PasswordAuthentication no\n')
    monkeypatch.setattr(checker, 'read_text', lambda path: None)
    assert 'note: line 3 copies sshd_config' in message(SSHD_ON_ALPINE + 'COPY sshd_config /etc/ssh/\n')


def test_note_is_inherited_by_child_stage() -> None:
    text = """
        FROM alpine:3.22 AS base
        RUN apk add openssh-server
        COPY missing/sshd_config /etc/ssh/sshd_config
        FROM base
        """
    assert 'note: line 3 copies missing/sshd_config' in message(text)


def test_read_handles_oserror(in_tmp_path: Path) -> None:
    assert checker.read_text(in_tmp_path) is None  # a directory
    assert checker.read_text(in_tmp_path / 'missing') is None


def test_copy_source_in_a_parent_folder(in_tmp_path: Path) -> None:
    """compose's ``context: ..``: the source sits next to the Dockerfile's folder, not in it."""
    write(in_tmp_path / 'services' / 'conf' / 'keys.conf', 'PasswordAuthentication no\n')
    text = SSHD_ON_ALPINE + 'COPY conf/keys.conf /etc/ssh/sshd_config.d/\n'
    assert flagged_lines(text, 'services/ssh/Dockerfile') == []


def test_context_dirs(in_tmp_path: Path) -> None:
    root = in_tmp_path.resolve()
    assert checker.context_dirs('Dockerfile') == [root]
    assert checker.context_dirs('a/b/Dockerfile') == [root / 'a' / 'b', root / 'a', root]


def test_context_dirs_outside_the_current_folder(in_tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (in_tmp_path / 'repo').mkdir()
    monkeypatch.chdir(in_tmp_path / 'repo')
    root = in_tmp_path.resolve()
    assert checker.context_dirs(str(root / 'other' / 'Dockerfile')) == [root / 'other', root / 'repo']


def test_findings_carry_the_rule() -> None:
    (finding,) = findings(SSHD_ON_ALPINE)
    assert finding.rule == 'sshole'

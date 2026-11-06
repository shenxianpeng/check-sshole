"""The Dockerfile check: find stages that ship an sshd exposed to *sshole.

*sshole (CVE-2026-123158) is a password authentication bypass in OpenSSH's
sshd before 10.6p2 when it is built against musl libc without PAM, which is
how Alpine builds its default openssh-server. Details: https://sshhole.com/

A Dockerfile is flagged when a stage that ends up as an image:

* installs sshd with apk (openssh, openssh-server, openssh-server-pam/-krb5),
* on a musl base (anything that uses apk, except glibc-based Wolfi/Chainguard),
* leaves password logins on (the OpenSSH default), and
* does not require a fixed openssh build.

The check only reads Dockerfiles and the sshd config files they COPY from the
build context. It never builds or pulls images and never connects to a host.
"""

from __future__ import annotations

import copy
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

CVE = 'CVE-2026-123158'
INFO_URL = 'https://sshhole.com/'
RULE = 'sshole'
DOCS_URL = 'https://github.com/shenxianpeng/check-sshole#fixed-openssh-builds-per-alpine-branch'
PRAGMA = '# check-sshole: ignore'

# First fixed openssh build on each Alpine branch, from the aports commits
# "main/openssh: fix password authentication" (2026-11-05). Alpine 3.15 and
# older got no fix. Keep the README table in sync.
FIXED_BUILDS = {
    '3.16': '9.0_p1-r6',
    '3.17': '9.1_p1-r7',
    '3.18': '9.3_p2-r4',
    '3.19': '9.6_p1-r3',
    '3.20': '9.7_p1-r6',
    '3.21': '9.9_p2-r1',
    '3.22': '10.0_p1-r11',
    '3.23': '10.2_p1-r1',
    '3.24': '10.3_p1-r2',
    'edge': '10.6_p2-r0',
}
OLDEST_FIXED_BRANCH = (3, 16)

SSHD_PACKAGES = frozenset({'openssh', 'openssh-server', 'openssh-server-pam', 'openssh-server-krb5'})
PAM_FLAVOR = frozenset({'openssh-server-pam'})
# apk constraints that rule out every build older than the given version.
PIN_OPERATORS = frozenset({'=', '>=', '>', '~', '=~', '~='})


# --- versions ----------------------------------------------------------------

_VERSION_RE = re.compile(r'(\d+(?:\.\d+)*)((?:_[a-z]+\d*)*)(?:-r(\d+))?')
_SUFFIX_RE = re.compile(r'_([a-z]+)(\d*)')
_SUFFIX_RANK = {'alpha': -4, 'beta': -3, 'pre': -2, 'rc': -1, 'cvs': 1, 'svn': 2, 'git': 3, 'hg': 4, 'p': 5}


def version_key(version: str) -> tuple[tuple[int, ...], tuple[tuple[int, int], ...], int] | None:
    """Sort key for an Alpine package version such as ``10.0_p1-r11``."""
    match = _VERSION_RE.fullmatch(version)
    if match is None:
        return None
    numbers = tuple(int(part) for part in match.group(1).split('.'))
    suffixes = tuple(
        (_SUFFIX_RANK.get(name, 0), int(number or 0)) for name, number in _SUFFIX_RE.findall(match.group(2))
    ) or ((0, 0),)
    return numbers, suffixes, int(match.group(3) or 0)


_FIXED_BY_UPSTREAM = {build.rsplit('-r', 1)[0]: build for build in FIXED_BUILDS.values()}
_FIRST_FIXED_RELEASE = version_key(FIXED_BUILDS['edge'])


def fixed_build_for(version: str) -> str | None:
    """The fixed build of the same upstream version, e.g. 10.0_p1-r10 -> 10.0_p1-r11."""
    return _FIXED_BY_UPSTREAM.get(version.rsplit('-r', 1)[0])


def is_fixed(version: str) -> bool:
    key = version_key(version)
    if key is None:
        return False
    if key >= _FIRST_FIXED_RELEASE:  # type: ignore[operator]
        return True
    fixed = fixed_build_for(version)
    return fixed is not None and key >= version_key(fixed)  # type: ignore[operator]


# --- base images -------------------------------------------------------------


def _split_ref(ref: str) -> tuple[str, str]:
    """Split an image reference into (name, tag), dropping digest and Docker Hub prefixes."""
    ref = ref.lower().split('@', 1)[0]
    name, tag = ref, ''
    if ref.rfind(':') > ref.rfind('/'):
        name, _, tag = ref.rpartition(':')
    for prefix in ('docker.io/', 'index.docker.io/', 'library/'):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name, tag


def alpine_branch(ref: str) -> str | None:
    """Alpine branch an image is built on, when its reference says so (``alpine:3.22``, ``*-alpine3.22``)."""
    name, tag = _split_ref(ref)
    if name == 'alpine':
        if tag.startswith('edge'):
            return 'edge'
        match = re.match(r'(\d+\.\d+)', tag)
    else:
        match = re.search(r'alpine-?(\d+\.\d+)', tag)
    return match.group(1) if match else None


def is_eol_branch(branch: str | None) -> bool:
    """True for Alpine branches that never got a fixed openssh build."""
    if branch is None or branch == 'edge':
        return False
    return tuple(int(part) for part in branch.split('.')) < OLDEST_FIXED_BRANCH


def is_glibc_apk(ref: str) -> bool:
    """Wolfi and Chainguard images use apk but are built on glibc, so they are not affected."""
    name, _ = _split_ref(ref)
    return name.startswith('cgr.dev/') or 'wolfi' in name or 'chainguard' in name


# --- Dockerfile parsing ------------------------------------------------------


@dataclass
class Instruction:
    lineno: int
    keyword: str
    args: str
    heredocs: list[str] = field(default_factory=list)
    ignore: bool = False


_DIRECTIVE_RE = re.compile(r'#\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(\S+)\s*')
_PRAGMA_RE = re.compile(r'check-sshole\s*:\s*ignore\b', re.IGNORECASE)
_HEREDOC_RE = re.compile(r'(?<!<)<<(?!<)(-?)(["\']?)([A-Za-z_][A-Za-z0-9_]*)\2')
_HEREDOC_KEYWORDS = frozenset({'RUN', 'COPY', 'ADD'})


def _is_blank_or_comment(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith('#')


def parse_dockerfile(text: str) -> list[Instruction]:
    """Split a Dockerfile into instructions, joining continuation lines and reading heredocs."""
    lines = text.splitlines()
    escape = '\\'
    index = 0
    while index < len(lines):
        directive = _DIRECTIVE_RE.fullmatch(lines[index])
        if directive is None:
            break
        if directive.group(1).lower() == 'escape':
            escape = directive.group(2)[0]
        index += 1

    instructions: list[Instruction] = []
    ignore_next = False
    while index < len(lines):
        line = lines[index]
        index += 1
        if _is_blank_or_comment(line):
            ignore_next = ignore_next or bool(_PRAGMA_RE.search(line))
            continue
        lineno = index
        parts = []
        while line.rstrip().endswith(escape):
            parts.append(line.rstrip()[:-1])
            # Comment and blank lines inside a continuation are dropped, as Docker does.
            while index < len(lines) and _is_blank_or_comment(lines[index]):
                index += 1
            if index == len(lines):
                line = ''
                break
            line = lines[index]
            index += 1
        parts.append(line)
        match = re.match(r'(\S*)\s*(.*)', ''.join(parts).strip(), re.DOTALL)
        keyword, args = match.group(1).upper(), match.group(2)  # type: ignore[union-attr]
        instruction = Instruction(lineno, keyword, args, ignore=ignore_next)
        ignore_next = False
        if keyword in _HEREDOC_KEYWORDS:
            for heredoc in _HEREDOC_RE.finditer(args):
                strip_tabs, delimiter = heredoc.group(1) == '-', heredoc.group(3)
                body = []
                while index < len(lines):
                    line = lines[index]
                    index += 1
                    if (line.lstrip('\t') if strip_tabs else line) == delimiter:
                        break
                    body.append(line)
                instruction.heredocs.append('\n'.join(body))
        instructions.append(instruction)
    return instructions


def _json_list(args: str) -> list[str] | None:
    """The words of an exec-form instruction (``["a", "b"]``), or None for shell form."""
    if not args.startswith('['):
        return None
    try:
        value = json.loads(args)
    except ValueError:
        return None
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _split_words(args: str) -> list[str]:
    try:
        return shlex.split(args)
    except ValueError:  # unbalanced quotes
        return args.split()


_VAR_RE = re.compile(r'\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))')


def _expand(value: str, env: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        return env.get(match.group(1) or match.group(3)) or match.group(2) or ''

    return _VAR_RE.sub(replace, value)


# --- shell -------------------------------------------------------------------

_PUNCTUATION = frozenset('();<>|&')
_SHELL_WORDS = frozenset({'if', 'then', 'else', 'elif', 'do', 'while', 'until', '!', '{', '}', 'time'})
_WRAPPERS = frozenset({'sudo', 'doas', 'env', 'command', 'exec', 'nice', 'nohup'})
_SHELLS = frozenset({'sh', 'ash', 'bash', 'dash'})
_ASSIGNMENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*=')


def _program(word: str) -> str:
    return word.rsplit('/', 1)[-1]


def _shell_tokens(line: str) -> list[str]:
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    try:
        return list(lexer)
    except ValueError:  # unbalanced quotes, e.g. a string spanning lines
        return line.split()


def _is_prefix(word: str) -> bool:
    return word in _SHELL_WORDS or bool(_ASSIGNMENT_RE.match(word)) or _program(word) in _WRAPPERS


def _strip_prefix(words: list[str]) -> list[str]:
    """Drop what comes before the program: shell keywords, VAR=value, sudo/env and their options."""
    index = 0
    while index < len(words) and _is_prefix(words[index]):
        wrapper = _program(words[index]) in _WRAPPERS
        index += 1
        while wrapper and index < len(words) and words[index].startswith('-'):
            index += 1
    return words[index:]


def _simple_command(words: list[str]) -> Iterator[list[str]]:
    words = _strip_prefix(words)
    if not words:
        return
    if _program(words[0]) in _SHELLS and len(words) > 2 and words[1] == '-c':
        yield from shell_commands(words[2])
    else:
        yield words


def shell_commands(script: str) -> Iterator[list[str]]:
    """Yield the simple commands of a shell script as word lists, redirections removed."""
    for line in script.replace('\\\n', ' ').splitlines():
        words: list[str] = []
        skip_target = False
        for token in _shell_tokens(line):
            if skip_target:
                skip_target = False
            elif token and set(token) <= _PUNCTUATION:
                if '<' in token or '>' in token:
                    skip_target = True
                else:
                    yield from _simple_command(words)
                    words = []
            else:
                words.append(token)
        yield from _simple_command(words)


# --- apk ---------------------------------------------------------------------

_APK_VALUE_OPTIONS = frozenset({
    '-X', '--repository', '-p', '--root', '-t', '--virtual', '--arch',
    '--cache-dir', '--keys-dir', '--repositories-file', '--timeout', '--cache-max-age',
})
_SPEC_RE = re.compile(r'([^=<>~@]+)(?:@[^=<>~]+)?(?:([=<>~]+)(.+))?')


@dataclass
class ApkCall:
    action: str
    names: list[str]
    virtual: str | None = None


def parse_apk(args: list[str]) -> ApkCall | None:
    """Parse the arguments of an ``apk`` command; only ``add`` and ``del`` matter here."""
    action = None
    virtual = None
    names = []
    index = 0
    while index < len(args):
        arg = args[index]
        index += 1
        if arg.startswith('-'):
            option, has_value, value = arg.partition('=')
            if option in _APK_VALUE_OPTIONS and not has_value:
                value = args[index] if index < len(args) else ''
                index += 1
            if option in ('-t', '--virtual'):
                virtual = value
        elif action is None:
            action = arg
        else:
            names.append(arg)
    if action in ('add', 'del'):
        return ApkCall(action, names, virtual)
    return None


def parse_spec(spec: str) -> tuple[str, str | None, str | None] | None:
    """Split ``openssh-server>=10.0_p1-r11`` into (name, operator, version)."""
    match = _SPEC_RE.fullmatch(spec)
    if match is None:
        return None
    return match.group(1), match.group(2), match.group(3)


# --- sshd settings -----------------------------------------------------------


def _setting_re(keyword: str, value: str) -> re.Pattern[str]:
    # Not preceded by '#', so commented-out lines and sed patterns like
    # 's/#PasswordAuthentication yes/.../' don't count.
    return re.compile(rf'(?<!#)(?<!#\s){keyword}["\']?(?:\s*=\s*|[ \t]+)["\']?{value}', re.IGNORECASE)


_SHELL_SETTINGS = {
    'password': _setting_re('PasswordAuthentication', r'(yes|no)\b'),
    'methods': _setting_re('AuthenticationMethods', r'([^"\'\n;&|/<>]+)'),
    'pam': _setting_re('UsePAM', r'(yes|no)\b'),
}
_CONFIG_LINE_RE = re.compile(r'(PasswordAuthentication|AuthenticationMethods|UsePAM)(?:\s*=\s*|\s+)(.*)', re.IGNORECASE)
_CONFIG_KEYS = {'passwordauthentication': 'password', 'authenticationmethods': 'methods', 'usepam': 'pam'}


def shell_settings(text: str) -> dict[str, str]:
    """sshd settings written by shell commands (echo, sed, sshd -o ...); the last one wins."""
    found = {}
    for key, regex in _SHELL_SETTINGS.items():
        matches = regex.findall(text)
        if matches:
            found[key] = matches[-1].strip().lower()
    return found


def config_settings(text: str) -> dict[str, str]:
    """Settings in an sshd_config file; as in sshd, the first global value wins.

    A Match block that turns password logins on counts as on.
    """
    found: dict[str, str] = {}
    in_match = False
    for line in text.splitlines():
        line = line.strip()
        if re.match(r'match\s', line, re.IGNORECASE):
            in_match = True
            continue
        setting = _CONFIG_LINE_RE.fullmatch(line)
        if setting is None:
            continue
        key, value = _CONFIG_KEYS[setting.group(1).lower()], setting.group(2).strip().lower()
        if not in_match:
            found.setdefault(key, value)
        elif key == 'password' and value == 'yes':
            found[key] = value
    return found


def _merge(found: list[dict[str, str]]) -> dict[str, str]:
    """Combine settings from several files; any file turning password logins on wins."""
    merged: dict[str, str] = {}
    for settings in found:
        for key, value in settings.items():
            if key == 'password' and value == 'yes':
                merged[key] = value
            else:
                merged.setdefault(key, value)
    return merged


def password_logins_off(settings: dict[str, str], packages: set[str]) -> bool:
    if settings.get('password') == 'no':
        return True
    methods = settings.get('methods')
    if methods and methods != 'any' and 'password' not in methods:
        return True
    # The PAM build checks passwords through PAM, which is not affected.
    return settings.get('pam') == 'yes' and packages <= PAM_FLAVOR


# --- COPY / ADD of sshd config files -------------------------------------------


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None


def _local_files(source: str, dest: str, ssh_dest: bool, base_dirs: list[Path]) -> list[Path] | None:
    """sshd config files a COPY source puts into the image, or None if the source isn't here."""
    for base in base_dirs:
        path = base / source.lstrip('/')  # COPY sources are relative to the build context, even with a leading /
        if path.is_file():
            return [path] if ssh_dest or path.name.startswith('sshd_config') else []
        if path.is_dir():
            if ssh_dest:
                root = path
            elif dest.strip('/') == '':  # COPY rootfs/ /
                root = path / 'etc' / 'ssh'
            else:
                return []
            return sorted(p for p in root.rglob('*') if p.is_file())
    return None


def _may_hold_config(source: str, dest: str) -> bool:
    """Whether an unreadable COPY source could be sshd config (and not, say, a host key)."""
    return 'sshd_config' in source or 'sshd_config' in dest or source.endswith('/') or bool(set(source) & set('*?['))


def copy_settings(instruction: Instruction, base_dirs: list[Path]) -> tuple[dict[str, str], list[str]]:
    """Settings in the sshd config files a COPY/ADD writes, and the sources that couldn't be read."""
    words = _json_list(instruction.args)
    if words is None:
        words = _split_words(instruction.args)
    from_other_stage = any(word.startswith('--from') for word in words)
    words = [word for word in words if not word.startswith('--')]
    if len(words) < 2:
        return {}, []
    *sources, dest = words
    ssh_dest = '/etc/ssh' in dest
    found = [config_settings(body) for body in instruction.heredocs] if ssh_dest else []
    unread = []
    for source in sources:
        if source.startswith('<<'):
            continue
        files = None
        if not from_other_stage and '://' not in source and not set(source) & set('*?[$'):
            files = _local_files(source, dest, ssh_dest, base_dirs)
        if files is None:
            if ssh_dest and _may_hold_config(source, dest):
                unread.append(source)
            files = []
        for path in files:
            text = read_text(path)
            if text is None:
                unread.append(source)
            else:
                found.append(config_settings(text))
    return _merge(found), unread


# --- stages ------------------------------------------------------------------


@dataclass
class Install:
    lineno: int
    package: str
    operator: str | None
    version: str | None
    ignored: bool

    @property
    def pinned_to_fix(self) -> bool:
        return self.operator in PIN_OPERATORS and is_fixed(str(self.version))


@dataclass
class Stage:
    base: str
    ignored: bool = False
    installs: dict[str, Install] = field(default_factory=dict)
    groups: dict[str, list[str]] = field(default_factory=dict)
    settings: dict[str, str] = field(default_factory=dict)
    cmd: str = ''
    entrypoint: str = ''
    unread: list[tuple[int, str]] = field(default_factory=list)
    has_children: bool = False


@dataclass
class Finding:
    path: str
    lineno: int
    lines: list[str]  # the headline, then indented why/fix/note/more lines
    rule: str = RULE

    def render(self) -> str:
        return f'{self.path}:{self.lineno}: ' + '\n'.join(self.lines)


def _apply_apk(stage: Stage, call: ApkCall, instruction: Instruction) -> None:
    if call.action == 'add':
        added = []
        for spec in call.names:
            parsed = parse_spec(spec)
            if parsed is None:
                continue
            name, operator, version = parsed
            if name in SSHD_PACKAGES:
                stage.installs[name] = Install(instruction.lineno, name, operator, version, instruction.ignore)
            added.append(name)
        if call.virtual:
            stage.groups[call.virtual] = added
    else:
        for name in call.names:
            for package in stage.groups.pop(name, [name]):
                stage.installs.pop(package, None)


def _apply_run(stage: Stage, instruction: Instruction) -> None:
    args = re.sub(r'^(?:--\S+\s+)*', '', instruction.args)  # RUN --mount=... --network=...
    words = _json_list(args)
    script = ' '.join(shlex.quote(word) for word in words) if words is not None else args
    script = '\n'.join([script, *instruction.heredocs])
    for command in shell_commands(script):
        if _program(command[0]) == 'apk':
            call = parse_apk(command[1:])
            if call is not None:
                _apply_apk(stage, call, instruction)
    stage.settings.update(shell_settings(script))


def _parse_from(args: str, env: dict[str, str]) -> tuple[str, str | None]:
    words = [word for word in args.split() if not word.startswith('--')]
    ref = _expand(words[0], env) if words else ''
    name = words[2].lower() if len(words) >= 3 and words[1].lower() == 'as' else None
    return ref, name


def _parse_global_args(args: str, env: dict[str, str]) -> None:
    for word in _split_words(args):
        name, has_value, value = word.partition('=')
        if has_value:
            env[name] = _expand(value, env)


def context_dirs(path: str) -> list[Path]:
    """Where COPY sources may live, most likely first.

    The build context is usually the Dockerfile's folder or one of its parents
    (compose's ``context: ..``), up to the repository root, which is the
    current directory under pre-commit and in CI.
    """
    folder = Path(path).parent.resolve()
    cwd = Path.cwd().resolve()
    dirs = [folder, *folder.parents]
    if cwd in dirs:
        return dirs[:dirs.index(cwd) + 1]
    return [folder, cwd]


def _finding(path: str, stage: Stage, install: Install) -> Finding:
    branch = alpine_branch(stage.base)
    eol = is_eol_branch(branch)
    where = f"'{stage.base}'" if stage.base else 'an apk-based image'
    spec = install.package + (f'{install.operator}{install.version}' if install.operator else '')
    lines = [f"sshd from '{spec}' on {where} accepts password logins: exposed to *sshole ({CVE})"]
    fixed = None
    if install.operator in PIN_OPERATORS:
        fixed = fixed_build_for(str(install.version))
        lines.append(f'  why: {install.version} is a vulnerable build' + (f'; the fix is in {fixed}' if fixed else ''))
    elif install.operator:
        lines.append(f"  why: '{install.operator}{install.version}' allows vulnerable builds")
    if eol:
        lines.append(f'  why: Alpine {branch} never got a fixed openssh build')
    elif not install.operator:
        lines.append('  why: a fresh build may pull the fixed package, but nothing here requires it;'
                     ' older or cached builds have the bug')
    fixed = fixed or FIXED_BUILDS.get(str(branch))
    lines.append("  fix: turn password logins off: RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config")
    lines.append('       (or start sshd with -o PasswordAuthentication=no)')
    if eol:
        lines.append('   or: move to Alpine 3.16 or newer and require its fixed openssh build')
    elif fixed:
        lines.append(f"   or: if you need password logins, require a fixed build: apk add '{install.package}>={fixed}'")
    else:
        lines.append(f'   or: if you need password logins, require the fixed build for your Alpine branch: {DOCS_URL}')
    for lineno, source in stage.unread:
        lines.append(f'  note: line {lineno} copies {source} into /etc/ssh but it could not be read here,'
                     ' so its settings were not checked')
    lines.append(f"  more: {INFO_URL} (to silence, put '{PRAGMA}' above line {install.lineno})")
    return Finding(path, install.lineno, lines)


def _evaluate(path: str, stage: Stage) -> Finding | None:
    if stage.ignored or is_glibc_apk(stage.base):
        return None
    active = [install for install in stage.installs.values() if not install.ignored]
    settings = dict(stage.settings)
    # sshd -o on the command line beats any config file.
    settings.update(shell_settings(stage.entrypoint + '\n' + stage.cmd))
    if not active or password_logins_off(settings, {install.package for install in active}):
        return None
    risky = [install for install in active if not install.pinned_to_fix]
    if not risky:
        return None
    return _finding(path, stage, min(risky, key=lambda install: install.lineno))


def check(text: str, path: str = 'Dockerfile') -> list[Finding]:
    """Check one Dockerfile; ``path`` is used in messages and to find COPY sources."""
    base_dirs = context_dirs(path)
    stages: list[Stage] = []
    named: dict[str, Stage] = {}
    global_args: dict[str, str] = {}
    stage: Stage | None = None
    for instruction in parse_dockerfile(text):
        keyword = instruction.keyword
        if keyword == 'FROM':
            ref, name = _parse_from(instruction.args, global_args)
            parent = named.get(ref.lower())
            if parent is None:
                stage = Stage(ref)
            else:
                parent.has_children = True
                stage = copy.deepcopy(parent)
                stage.has_children = False
            stage.ignored = stage.ignored or instruction.ignore
            stages.append(stage)
            if name:
                named[name] = stage
        elif stage is None:
            if keyword == 'ARG':
                _parse_global_args(instruction.args, global_args)
        elif keyword == 'RUN':
            _apply_run(stage, instruction)
        elif keyword in ('COPY', 'ADD'):
            settings, unread = copy_settings(instruction, base_dirs)
            stage.settings.update(settings)
            stage.unread.extend((instruction.lineno, source) for source in unread)
        elif keyword == 'CMD':
            stage.cmd = instruction.args
        elif keyword == 'ENTRYPOINT':
            stage.entrypoint = instruction.args

    # Only stages no other stage builds on become images; one finding per apk line.
    findings: dict[int, Finding] = {}
    for stage in stages:
        if not stage.has_children:
            finding = _evaluate(path, stage)
            if finding is not None:
                findings.setdefault(finding.lineno, finding)
    return [findings[lineno] for lineno in sorted(findings)]

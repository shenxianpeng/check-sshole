# check-sshole

[![CI](https://github.com/shenxianpeng/check-sshole/actions/workflows/ci.yml/badge.svg)](https://github.com/shenxianpeng/check-sshole/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/check-sshole)](https://pypi.org/project/check-sshole/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Find Dockerfiles that ship an sshd exposed to
[*sshole (CVE-2026-123158)](https://sshhole.com/), with one command and
before anything is built or deployed.

```bash
uvx check-sshole
```

That scans every Dockerfile under the current folder. No install, no Docker,
no network access: it only reads files. (`pipx run check-sshole` or
`pip install check-sshole` work too.)

```text
.devcontainer/Dockerfile:2: sshd from 'openssh' on 'python:3.12-alpine3.15' accepts password logins: exposed to *sshole (CVE-2026-123158)
  why: Alpine 3.15 never got a fixed openssh build
  fix: turn password logins off: RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
       (or start sshd with -o PasswordAuthentication=no)
   or: move to Alpine 3.16 or newer and require its fixed openssh build
  more: https://sshhole.com/ (to silence, put '# check-sshole: ignore' above line 2)

services/sftp/Dockerfile:2: sshd from 'openssh-server' on 'alpine:3.22' accepts password logins: exposed to *sshole (CVE-2026-123158)
  why: a fresh build may pull the fixed package, but nothing here requires it; older or cached builds have the bug
  fix: turn password logins off: RUN echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
       (or start sshd with -o PasswordAuthentication=no)
   or: if you need password logins, require a fixed build: apk add 'openssh-server>=10.0_p1-r11'
  more: https://sshhole.com/ (to silence, put '# check-sshole: ignore' above line 2)

check-sshole: 2 findings in 3 Dockerfiles
```

## Am I affected?

*sshole is a password authentication bypass in OpenSSH's sshd before 10.6p2
when sshd is built against musl libc without PAM. That is how Alpine builds
its default `openssh-server`, so a container that installs sshd with `apk`
and leaves password logins on (the OpenSSH default) is exposed. Accounts whose
password field is `*` (key-only users, and `root` on Alpine) are the ones at
risk. Debian, Ubuntu, RHEL and other glibc images are not affected.

check-sshole flags a Dockerfile stage when all of these are true:

| Condition | What check-sshole looks at |
|---|---|
| sshd is installed | `apk add openssh`, `openssh-server`, `openssh-server-pam` or `openssh-server-krb5`, in shell form, exec form, `sh -c` and heredocs; `apk del` is followed |
| the base is musl | the stage uses apk and is not Wolfi/Chainguard (those are glibc) |
| password logins are on | nothing sets `PasswordAuthentication no` or a password-free `AuthenticationMethods`, in `RUN`, `CMD`/`ENTRYPOINT` (`sshd -o …`), sshd config files COPY'd from the repository, or COPY heredocs; `UsePAM yes` with `openssh-server-pam` also counts as off |
| no fixed build is required | the package is not pinned (`=`, `>=`, `~`) to a fixed build |

Multi-stage builds are followed: a stage inherits what its `FROM <stage>`
parent installed and configured, and only stages that no other stage builds
on are checked.

## Usage

### Command line

```bash
check-sshole                         # every Dockerfile under the current folder
check-sshole services/ Dockerfile    # some folders and files
check-sshole --format json .         # machine-readable
```

It picks up `Dockerfile`, `Containerfile`, `Dockerfile.<anything>` and
`<anything>.Dockerfile`, and skips `.git`, `node_modules` and virtualenvs.
Files you name are checked whatever they are called.

| Exit status | Meaning |
|---|---|
| 0 | nothing found |
| 1 | at least one finding |
| 2 | a path does not exist or could not be read |

### pre-commit

```yaml
repos:
  - repo: https://github.com/shenxianpeng/check-sshole
    rev: v0.1.0
    hooks:
      - id: check-sshole
```

To check every Dockerfile once, not only the ones a commit touches:
`pre-commit run check-sshole --all-files`.

### GitHub Actions

```yaml
jobs:
  check-sshole:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: shenxianpeng/check-sshole@v0.1.0
        # with:
        #   path: services/ Dockerfile   # default: the whole repository
```

Findings show up as annotations on the pull request and in the job summary,
and fail the job. The action runs on the runner's own Python and installs
nothing.

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | files or folders to scan, separated by spaces |
| `format` | `github` | `github` (annotations and a job summary), `text` or `json` |

## Fixed openssh builds per Alpine branch

| Alpine | First fixed build |
|---|---|
| edge | `10.6_p2-r0` |
| 3.24 | `10.3_p1-r2` |
| 3.23 | `10.2_p1-r1` |
| 3.22 | `10.0_p1-r11` |
| 3.21 | `9.9_p2-r1` |
| 3.20 | `9.7_p1-r6` |
| 3.19 | `9.6_p1-r3` |
| 3.18 | `9.3_p2-r4` |
| 3.17 | `9.1_p1-r7` |
| 3.16 | `9.0_p1-r6` |
| 3.15 and older | none: turn password logins off or move to a newer branch |

Source: the aports commits "main/openssh: fix password authentication"
(2026-11-05) on each `*-stable` branch.

### Checking an image you already built

check-sshole reads Dockerfiles, so it cannot see what an existing image
actually contains. To check one, read its installed build and compare it with
the table:

```bash
docker run --rm --entrypoint apk IMAGE list --installed openssh-server
# openssh-server-10.0_p1-r11 aarch64 {openssh} (SSH-OpenSSH) [installed]
```

`sshd -V` and `ssh -V` do not show the Alpine revision (`-r11`), and
`apk info -v` does not print the version, so use `apk list --installed`.
Rebuilding an image without `--no-cache` can keep an old, vulnerable layer.

## Silencing a finding

Put `# check-sshole: ignore` on the line above the `RUN` that installs sshd,
or above `FROM` to skip a whole stage (and the stages built on it):

```dockerfile
FROM alpine:3.22
# check-sshole: ignore  (sshd only listens on the internal network)
RUN apk add --no-cache openssh-server
```

## Limits

- It only reads Dockerfiles and the sshd config files they COPY from the
  repository. It never builds or pulls images and never connects to a host.
- It does not see an sshd that comes with the base image (for example
  `FROM linuxserver/openssh-server`), or sshd config that an entrypoint script
  changes at runtime. Check those images with the command above.

## Development

```bash
pip install -e '.[test]'
pytest --cov    # fails below 100% coverage
```

Releases are cut by publishing a GitHub release tagged `vX.Y.Z`; the publish
workflow builds the package and uploads it to PyPI.

## License

[MIT](LICENSE)

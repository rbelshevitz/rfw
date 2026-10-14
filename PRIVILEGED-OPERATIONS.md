# Privileged operations and audit

`rfw` invokes the host's `firewall-cmd`. Root privileges are needed because
`firewall-cmd` changes the host-wide firewall configuration; they are not a
special requirement of `rfw` itself. Read-only commands may not need `sudo`.

For normal use:

- run commands that change rules through `sudo`, rather than sharing a root account;
- review `--dry-run` before applying a change;
- use the operating system's normal `sudo`/journal log to see who ran the command.

`rfw` does not maintain its own audit log. On systems with formal audit requirements, administrators may additionally configure `auditd` and the organization's existing centralized logging. This is optional infrastructure, not an `rfw` requirement.

Install binaries from a known commit or release and verify their checksum or signature. Open source improves reviewability, but does not by itself prove that the installed binary matches the reviewed source.

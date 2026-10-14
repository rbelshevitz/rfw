# rfw

[![CI](https://github.com/rbelshevitz/rfw/actions/workflows/ci.yml/badge.svg)](https://github.com/rbelshevitz/rfw/actions/workflows/ci.yml)
![Go version](https://img.shields.io/badge/Go-1.25.0-00ADD8?logo=go)
[![License](https://img.shields.io/github/license/rbelshevitz/rfw)](LICENSE)

[Русская версия](README.ru.md)

See [the roadmap](TODO.md) for implemented scope, intentional exclusions, and
next work.

`rfw` is a small command-line frontend for `firewalld` on RHEL, Rocky Linux,
and AlmaLinux. It does not manage nftables directly, which avoids conflicts
with firewalld and keeps behaviour predictable.

## Quick start

```console
rfw status
rfw zones
rfw zone show public
rfw list --zone public
rfw delete 2 --zone public
rfw open 443/tcp
rfw open service https
rfw open 8443/tcp --timeout 10m
rfw open 51820/udp --zone public
rfw close 8080/tcp --runtime
```

By default, `open` and `close` apply a targeted change both to the active
runtime configuration and to the persistent configuration. The change works
immediately and remains after a reboot. Use `--runtime` or `--permanent` to
change only one layer.

`open --timeout DURATION` creates a runtime-only temporary opening, for example
for a short maintenance window. It cannot be combined with `--permanent` and
does not persist after a reboot.

Use `--dry-run` with `open`, `close`, or `delete` to show the exact planned
`firewall-cmd` calls without modifying the firewall.

### Applying changes safely

On a managed host, inspect the plan as root before applying it:

```console
sudo rfw zones
sudo rfw open 443/tcp --zone public --dry-run
sudo rfw open 443/tcp --zone public
```

`--dry-run` performs no rule mutation. For `delete`, rfw still reads the zone
to resolve the requested number, but it does not remove anything. `rfw` never
issues `reload`, `complete-reload`, or `runtime-to-permanent` automatically.

## Rule numbers: scope and limits

Firewalld has no global, persistent UFW-style rule number. Its configuration is
made of independent objects: zone ports, services, rich rules, source bindings,
policies, and more. A number is therefore only meaningful within one list at
one point in time.

`rfw list --zone public` currently numbers only explicit `port` allowances in
that zone. Numbers are sorted, temporary, and reread immediately before
`rfw delete NUMBER --zone public` runs. They do not identify services, rich
rules, policies, NAT, or rules in another zone.

This is deliberate: pretending that all firewalld objects share a stable rule
number could delete the wrong thing. A future rich-rule UI should use an
explicit, complete rule specification or rfw-owned identifiers, rather than a
host-wide ordinal.

`close` removes a previously added port allowance; it does not create an
absolute deny rule. A service, another zone, or a rich rule may still permit
that traffic.

Use a port for a literal endpoint such as `8443/tcp`; use a service for a
firewalld service definition such as `https`. The recommended way to remove an
allowance is the same explicit form: `rfw close 8443/tcp` or
`rfw close service https`.

When connected through SSH, `rfw` refuses to close the current SSH session's
port without explicit `--force`. Use `--force` only when console access is
available.

## Zones

Firewalld applies rules in zones, selected by interface or source address.
Use `rfw zones` to inspect active zone bindings and `rfw zone show ZONE` to
inspect all objects in a zone. For safety, `delete` requires an explicit
`--zone`.

For `open` and `close`, omitting `--zone` is permitted only when exactly one
zone is active. With multiple active zones, rfw stops and asks for `--zone`;
this prevents an accidental change to the wrong interface's traffic policy.

`rfw doctor` is read-only. It reports firewalld state, zone bindings, and warns
when BPF network hooks are present. BPF programs are outside firewalld's model;
rfw does not alter them.

## SELinux

Firewall access and SELinux access are independent. An open port only permits
packets to reach the host; an SELinux policy can still prevent a confined
service from binding, accepting, or connecting as expected. `rfw doctor` shows
the current SELinux mode but never changes SELinux booleans or port labels.
Use the service-specific SELinux documentation and `semanage port` deliberately
when an application needs a non-standard port.

## Build and test

Build a compact standalone binary:

```console
mkdir -p dist
CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o dist/rfw ./cmd/rfw
```

The resulting binary is `dist/rfw`. `-s -w` removes debug symbols; omit it for
development builds that need richer stack traces.

Run tests:

```console
go test -buildvcs=false ./...
```

`rfw` invokes the host's `firewall-cmd`; changing rules normally requires root
privileges.

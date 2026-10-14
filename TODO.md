# rfw scope

[Русская версия](TODO.ru.md)

## What rfw is

rfw is a small, safe, UFW-like frontend for the common firewalld tasks on
RHEL-compatible systems. It is intentionally not a second complete firewalld
CLI.

## Implemented

- Open or close TCP/UDP port allowances.
- Open or close predefined firewalld services.
- Runtime and permanent changes, temporary `--timeout` openings, and
  non-mutating `--dry-run` plans.
- Zone overview and inspection; automatic zone selection only if exactly one
  zone is active.
- Port and service listing; temporary port numbers as a `delete` shortcut.
- SSH safety guard, read-only diagnostics, and SELinux/BPF visibility.

## Likely additions

- Read-only `rfw interface show IFACE`, if it makes zone selection clearer.
- A narrowly scoped source restriction such as `open 443/tcp --from CIDR`, only
  after its rich-rule, IPv4/IPv6, ordering, and SSH implications are designed
  and tested.

## Intentionally out of scope

- Interface moves, NetworkManager profile management, custom zone creation.
- General rich-rule editing, deny rules, policies, ipsets, NAT, masquerading,
  forwarding, routing, direct nftables/iptables rules, and eBPF management.
- Automatic reloads and global/persistent rule numbers.

Use `firewall-cmd`, `nmcli`, `nft`, SELinux tools, and eBPF tools directly for
those administrative tasks.

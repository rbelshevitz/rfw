# Границы rfw

[English version](TODO.md)

## Что такое rfw

rfw — небольшая безопасная UFW-подобная утилита для частых задач firewalld на
RHEL-совместимых системах. Это намеренно не второй полный CLI firewalld.

## Уже реализовано

- Открытие и закрытие TCP/UDP port-разрешений.
- Открытие и закрытие предопределённых firewalld services.
- Runtime и permanent изменения, временные разрешения `--timeout` и планы без
  мутаций через `--dry-run`.
- Обзор и просмотр зон; автоматический выбор зоны только при ровно одной
  активной зоне.
- Список ports/services; временные номера port-разрешений как shortcut для
  `delete`.
- Защита SSH, read-only диагностика и видимость SELinux/BPF.

## Вероятные дополнения

- Read-only `rfw interface show IFACE`, если он сделает выбор зоны понятнее.
- Узкое ограничение источника вида `open 443/tcp --from CIDR` — только после
  проектирования и тестирования rich-rule, IPv4/IPv6, порядка правил и влияния
  на SSH.

## Намеренно вне scope

- Перемещение интерфейсов, управление NetworkManager profiles, создание зон.
- Произвольное редактирование rich rules, deny rules, policies, ipsets, NAT,
  masquerading, forwarding, routing, direct nftables/iptables rules и
  управление eBPF.
- Автоматические reload и глобальные/постоянные номера правил.

Для этих административных задач используйте напрямую `firewall-cmd`, `nmcli`,
`nft`, SELinux tools и eBPF tools.

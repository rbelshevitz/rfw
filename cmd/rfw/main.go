package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

const version = "0.4.0"

func main() {
	a := app{os.Stdout, os.Stderr, commandRunner{}}
	if err := a.execute(os.Args[1:]); err != nil {
		fmt.Fprintln(a.err, "rfw:", err)
		os.Exit(1)
	}
}

func (a app) execute(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		a.usage()
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Fprintln(a.out, version)
		return nil
	}
	switch args[0] {
	case "status", "list":
		return a.listRules(args[1:])
	case "zones":
		return a.zones(args[1:])
	case "zone":
		return a.zone(args[1:])
	case "doctor":
		return a.doctor(args[1:])
	case "open", "allow":
		if len(args) > 1 && args[1] == "service" {
			return a.changeService("open", args[2:])
		}
		return a.changePort("open", args[1:])
	case "close":
		if len(args) > 1 && args[1] == "service" {
			return a.changeService("close", args[2:])
		}
		return a.changePort("close", args[1:])
	case "delete":
		return a.deleteRule(args[1:])
	default:
		return fmt.Errorf("unknown command %q; run 'rfw help'", args[0])
	}
}

func (a app) zone(args []string) error {
	if len(args) != 2 || args[0] != "show" {
		return fmt.Errorf("usage: rfw zone show ZONE")
	}
	return a.firewall("--zone="+args[1], "--list-all")
}

func (a app) doctor(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("doctor does not accept arguments")
	}
	fmt.Fprintln(a.out, "rfw diagnostics (read-only)")
	state, err := a.firewallOutput("--state")
	if err != nil {
		fmt.Fprintf(a.out, "firewalld: unavailable (%v)\n", err)
	} else {
		fmt.Fprintf(a.out, "firewalld: %s\n", strings.TrimSpace(string(state)))
	}
	if err == nil {
		if zone, zoneErr := a.firewallOutput("--get-default-zone"); zoneErr == nil {
			fmt.Fprintf(a.out, "default zone: %s\n", strings.TrimSpace(string(zone)))
		}
		if active, activeErr := a.firewallOutput("--get-active-zones"); activeErr == nil {
			fmt.Fprintf(a.out, "active zones:\n%s", string(active))
		}
	}
	if mode, modeErr := a.run.Run("getenforce"); modeErr != nil {
		fmt.Fprintln(a.out, "SELinux: not inspectable")
	} else {
		mode := strings.TrimSpace(string(mode))
		fmt.Fprintf(a.out, "SELinux: %s\n", mode)
		if mode == "Enforcing" {
			fmt.Fprintln(a.out, "Note: opening a firewall port does not grant an application SELinux permission to use it.")
		}
	}
	bpf, bpfErr := a.run.Run("bpftool", "net", "show")
	if bpfErr != nil {
		fmt.Fprintln(a.out, "BPF network hooks: not inspectable (requires suitable privileges)")
	} else {
		attachments := bpfAttachments(string(bpf))
		if len(attachments) == 0 {
			fmt.Fprintln(a.out, "BPF network hooks: none reported")
		} else {
			fmt.Fprintln(a.out, "WARNING: BPF network hooks are present; they can affect traffic outside firewalld.")
			for _, attachment := range attachments {
				fmt.Fprintln(a.out, attachment)
			}
		}
	}
	return nil
}

func bpfAttachments(output string) []string {
	sections := map[string]bool{
		"xdp:": true, "tc:": true, "tcx:": true, "netkit:": true,
		"flow_dissector:": true, "netfilter:": true,
	}
	var attachments []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || sections[line] {
			continue
		}
		attachments = append(attachments, line)
	}
	return attachments
}

func (a app) zones(args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("zones does not accept arguments")
	}
	defaultZone, err := a.firewallOutput("--get-default-zone")
	if err != nil {
		return err
	}
	active, err := a.firewallOutput("--get-active-zones")
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Default zone: %s\n\n", strings.TrimSpace(string(defaultZone)))
	fmt.Fprint(a.out, "Active zones (interfaces and sources):\n")
	if strings.TrimSpace(string(active)) == "" {
		fmt.Fprintln(a.out, "  none")
		return nil
	}
	fmt.Fprint(a.out, string(active))
	return nil
}
func (a app) listRules(args []string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	if opts.runtimeOnly || opts.force || opts.timeout != "" || opts.dryRun || len(opts.args) != 0 {
		return fmt.Errorf("usage: rfw list [--zone ZONE] [--permanent]")
	}
	zone, err := a.resolveZone(opts.zone)
	if err != nil {
		return err
	}
	ports, err := a.ports(zone, opts.permanentOnly)
	if err != nil {
		return err
	}
	layer := "runtime"
	if opts.permanentOnly {
		layer = "permanent"
	}
	services, err := a.services(zone, opts.permanentOnly)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.out, "Zone: %s (%s)\n\n", zone, layer)
	if len(ports) == 0 && len(services) == 0 {
		fmt.Fprintln(a.out, "No explicit port or service allowances.")
		return nil
	}
	if len(ports) != 0 {
		fmt.Fprintln(a.out, "PORT ALLOWANCES (use: rfw close PORT --zone "+zone+")")
		fmt.Fprintln(a.out, "NUMBER  PORT")
		for i, port := range ports {
			fmt.Fprintf(a.out, "%6d  %s\n", i+1, port)
		}
	}
	if len(services) != 0 {
		if len(ports) != 0 {
			fmt.Fprintln(a.out)
		}
		fmt.Fprintln(a.out, "SERVICES (use: rfw close service NAME --zone "+zone+")")
		for _, service := range services {
			fmt.Fprintf(a.out, "  %s\n", service)
		}
	}
	return nil
}

func (a app) deleteRule(args []string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	if opts.zone == "" {
		return fmt.Errorf("delete requires --zone ZONE; rule numbers are scoped to a zone")
	}
	if opts.timeout != "" {
		return fmt.Errorf("--timeout is only valid with open")
	}
	if len(opts.args) != 1 {
		return fmt.Errorf("delete requires one rule number; run 'rfw list' first")
	}
	n, err := strconv.Atoi(opts.args[0])
	if err != nil || n < 1 {
		return fmt.Errorf("invalid rule number %q; run 'rfw list' first", opts.args[0])
	}
	ports, err := a.ports(opts.zone, opts.permanentOnly)
	if err != nil {
		return err
	}
	if n > len(ports) {
		return fmt.Errorf("rule number %d does not exist in zone %q; run 'rfw list --zone %s'", n, opts.zone, opts.zone)
	}
	port := ports[n-1]
	if !opts.runtimeOnly && !opts.permanentOnly {
		permanentPorts, err := a.ports(opts.zone, true)
		if err != nil {
			return err
		}
		if !contains(permanentPorts, port) {
			return fmt.Errorf("refusing to delete %s from both configurations: it exists only in runtime; use --runtime after checking 'rfw list --zone %s'", port, opts.zone)
		}
	}
	if !opts.force && isCurrentSSHPort(port) {
		return fmt.Errorf("refusing to delete rule %d (%s): it is the current SSH session port; use --force only if you have console access", n, port)
	}
	changeArgs := []string{port, "--zone", opts.zone}
	if opts.runtimeOnly {
		changeArgs = append(changeArgs, "--runtime")
	}
	if opts.permanentOnly {
		changeArgs = append(changeArgs, "--permanent")
	}
	if opts.force {
		changeArgs = append(changeArgs, "--force")
	}
	if opts.dryRun {
		changeArgs = append(changeArgs, "--dry-run")
	}
	return a.changePort("close", changeArgs)
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

func (a app) resolveZone(zone string) (string, error) {
	if zone != "" {
		return zone, nil
	}
	output, err := a.firewallOutput("--get-default-zone")
	if err != nil {
		return "", err
	}
	zone = strings.TrimSpace(string(output))
	if zone == "" {
		return "", fmt.Errorf("firewalld returned no default zone")
	}
	return zone, nil
}

func (a app) ports(zone string, permanent bool) ([]string, error) {
	return a.zoneItems(zone, permanent, "--list-ports")
}

func (a app) services(zone string, permanent bool) ([]string, error) {
	return a.zoneItems(zone, permanent, "--list-services")
}

func (a app) zoneItems(zone string, permanent bool, operation string) ([]string, error) {
	cmd := []string{"--zone=" + zone, operation}
	if permanent {
		cmd = append([]string{"--permanent"}, cmd...)
	}
	output, err := a.firewallOutput(cmd...)
	if err != nil {
		return nil, err
	}
	ports := strings.Fields(string(output))
	sort.Strings(ports)
	return ports, nil
}
func (a app) changePort(action string, args []string) error {
	return a.changeItem(action, "port", args)
}

func (a app) changeService(action string, args []string) error {
	return a.changeItem(action, "service", args)
}

func (a app) changeItem(action, kind string, args []string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	if opts.force && action != "close" {
		return fmt.Errorf("--force is only valid with close")
	}
	if opts.timeout != "" {
		if action != "open" {
			return fmt.Errorf("--timeout is only valid with open")
		}
		if opts.permanentOnly {
			return fmt.Errorf("--timeout cannot be combined with --permanent")
		}
		opts.runtimeOnly = true
	}
	if len(opts.args) != 1 {
		return fmt.Errorf("%s requires one %s, for example: rfw %s %s", action, kind, action, example(kind))
	}
	item := opts.args[0]
	if kind == "port" {
		item, err = parsePort(item)
	} else {
		err = parseService(item)
	}
	if err != nil {
		return err
	}
	if action == "close" && !opts.force && ((kind == "port" && isCurrentSSHPort(item)) || (kind == "service" && item == "ssh" && os.Getenv("SSH_CONNECTION") != "")) {
		return fmt.Errorf("refusing to close %s %s during an SSH session; use --force only if you have console access", kind, item)
	}
	zone, err := a.resolveMutationZone(opts.zone)
	if err != nil {
		return err
	}
	op := "--add-" + kind + "=" + item
	if action == "close" {
		op = "--remove-" + kind + "=" + item
	}
	base := []string{op}
	if opts.timeout != "" {
		base = append(base, "--timeout="+opts.timeout)
	}
	if zone != "" {
		base = append([]string{"--zone=" + zone}, base...)
	}
	if opts.dryRun {
		if !opts.permanentOnly {
			a.plan(base...)
		}
		if !opts.runtimeOnly {
			a.plan(append([]string{"--permanent"}, base...)...)
		}
		return nil
	}
	if !opts.permanentOnly {
		if err := a.firewall(base...); err != nil {
			return err
		}
		if opts.timeout != "" {
			fmt.Fprintf(a.out, "Done: %s %s %s now; it expires after %s.\n", kind, item, result(action), opts.timeout)
		} else {
			fmt.Fprintf(a.out, "Done: %s %s %s now.\n", kind, item, result(action))
		}
	}
	if !opts.runtimeOnly {
		permanent := append([]string{"--permanent"}, base...)
		if err := a.firewall(permanent...); err != nil {
			if !opts.permanentOnly {
				return fmt.Errorf("%s %s is %s now, but was not saved for reboot: %w", kind, item, result(action), err)
			}
			return err
		}
		fmt.Fprintf(a.out, "Done: %s %s %s after reboot.\n", kind, item, result(action))
	}
	return nil
}

func (a app) plan(args ...string) {
	fmt.Fprintf(a.out, "Would run: firewall-cmd %s\n", strings.Join(args, " "))
}

func (a app) resolveMutationZone(zone string) (string, error) {
	if zone != "" {
		return zone, nil
	}
	output, err := a.firewallOutput("--get-active-zones")
	if err != nil {
		return "", err
	}
	var zones []string
	for _, line := range strings.Split(string(output), "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		zones = append(zones, strings.TrimSpace(line))
	}
	if len(zones) == 1 {
		fmt.Fprintf(a.out, "Using active zone: %s\n", zones[0])
		return zones[0], nil
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("no active firewalld zone; specify --zone ZONE")
	}
	return "", fmt.Errorf("multiple active zones; specify --zone ZONE (run 'rfw zones')")
}
func (a app) usage() {
	fmt.Fprintf(a.out, `rfw — simple firewalld management

Everyday use:
  rfw open PORT/tcp|udp [--zone ZONE] [--runtime|--permanent|--timeout DURATION] [--dry-run]
  rfw open service NAME [--zone ZONE] [--runtime|--permanent|--timeout DURATION] [--dry-run]
  rfw close PORT/tcp|udp [--zone ZONE] [--runtime|--permanent] [--force] [--dry-run]
  rfw close service NAME [--zone ZONE] [--runtime|--permanent] [--force] [--dry-run]
  rfw status [--zone ZONE]

By default open/close applies now and after reboot. Use --runtime or
--permanent to change one layer. Use --timeout only with open for a temporary
runtime-only opening. --dry-run prints the planned firewall-cmd calls.

When one zone is active, it is selected automatically. With several active
zones, specify --zone ZONE. Options may appear before or after the item.

SSH safety: when connected over SSH, rfw will not close the current session's
port without --force. Use --force only when console access is available.

Examples:
  rfw open 443/tcp
  rfw open service https
  rfw open 8443/tcp --timeout 10m
  rfw close 443/tcp --dry-run

Inspect and troubleshoot:
  rfw zones                       show active zones, interfaces, and sources
  rfw zone show ZONE              show all objects in one zone
  rfw list [--zone ZONE]          list ports and services (status is an alias)
  rfw delete NUMBER --zone ZONE   shortcut to remove a listed port
  rfw doctor                      read-only firewalld, SELinux, and BPF checks

Compatibility: rfw allow is an alias for rfw open.

rfw %s · Roman Belshevitz
`, version)
}

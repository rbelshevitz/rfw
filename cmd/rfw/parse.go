package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type options struct {
	zone                       string
	runtimeOnly, permanentOnly bool
	force                      bool
	timeout                    string
	dryRun                     bool
	args                       []string
}

func parseOptions(args []string) (options, error) {
	var opts options
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--zone="):
			opts.zone = strings.TrimPrefix(arg, "--zone=")
			if opts.zone == "" {
				return options{}, fmt.Errorf("--zone requires a zone name")
			}
			continue
		case arg == "--zone":
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "-") {
				return options{}, fmt.Errorf("--zone requires a zone name")
			}
			i++
			opts.zone = args[i]
		case arg == "--runtime":
			opts.runtimeOnly = true
		case arg == "--permanent":
			opts.permanentOnly = true
		case arg == "--force":
			opts.force = true
		case arg == "--dry-run":
			opts.dryRun = true
		case strings.HasPrefix(arg, "--timeout="):
			opts.timeout = strings.TrimPrefix(arg, "--timeout=")
			if opts.timeout == "" {
				return options{}, fmt.Errorf("--timeout requires a duration")
			}
		case arg == "--timeout":
			if i+1 == len(args) || strings.HasPrefix(args[i+1], "-") {
				return options{}, fmt.Errorf("--timeout requires a duration")
			}
			i++
			opts.timeout = args[i]
		case strings.HasPrefix(arg, "-"):
			return options{}, fmt.Errorf("unknown option %q", arg)
		default:
			opts.args = append(opts.args, arg)
		}
	}
	if opts.runtimeOnly && opts.permanentOnly {
		return options{}, fmt.Errorf("choose only one: --runtime or --permanent")
	}
	return opts, nil
}

func parsePort(value string) (string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || (parts[1] != "tcp" && parts[1] != "udp") {
		return "", fmt.Errorf("invalid port %q; expected PORT/tcp or PORT/udp", value)
	}
	n, err := strconv.Atoi(parts[0])
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("invalid port %q; expected a number from 1 to 65535", parts[0])
	}
	return value, nil
}

func parseService(value string) error {
	if value == "" {
		return fmt.Errorf("service name is required")
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return fmt.Errorf("invalid service name %q", value)
		}
	}
	return nil
}

func example(kind string) string {
	if kind == "service" {
		return "service https"
	}
	return "443/tcp"
}

func isCurrentSSHPort(port string) bool {
	if !strings.HasSuffix(port, "/tcp") {
		return false
	}
	fields := strings.Fields(os.Getenv("SSH_CONNECTION"))
	return len(fields) == 4 && strings.TrimSuffix(port, "/tcp") == fields[3]
}

func result(action string) string {
	if action == "open" {
		return "open"
	}
	return "closed"
}

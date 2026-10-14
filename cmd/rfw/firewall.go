package main

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// runner makes the firewalld boundary testable and avoids shell interpolation.
type runner interface {
	Run(name string, args ...string) ([]byte, error)
}

type commandRunner struct{}

func (commandRunner) Run(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

type app struct {
	out, err io.Writer
	run      runner
}

func (a app) firewall(args ...string) error {
	output, err := a.firewallOutput(args...)
	if len(output) > 0 {
		fmt.Fprint(a.out, string(output))
	}
	return err
}

func (a app) firewallOutput(args ...string) ([]byte, error) {
	output, err := a.run.Run("firewall-cmd", args...)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 252 {
			return output, fmt.Errorf("firewalld is not running; start it with: sudo systemctl enable --now firewalld")
		}
		detail := strings.TrimSpace(string(output))
		if detail != "" {
			return output, fmt.Errorf("firewall-cmd %s: %s", strings.Join(args, " "), detail)
		}
		return output, fmt.Errorf("firewall-cmd %s: %w", strings.Join(args, " "), err)
	}
	return output, nil
}

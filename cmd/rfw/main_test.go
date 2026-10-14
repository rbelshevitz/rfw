package main

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

type call struct {
	name string
	args []string
}
type fakeRunner struct {
	calls []call
	err   error
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, call{name, args})
	return []byte("success\n"), f.err
}

func TestOpenDefaultsToRuntimeAndPermanent(t *testing.T) {
	f := &fakeRunner{}
	a := app{out: &bytes.Buffer{}, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"open", "443/tcp", "--zone", "public"}); err != nil {
		t.Fatal(err)
	}
	want := []call{{"firewall-cmd", []string{"--zone=public", "--add-port=443/tcp"}}, {"firewall-cmd", []string{"--permanent", "--zone=public", "--add-port=443/tcp"}}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %#v, want %#v", f.calls, want)
	}
}
func TestCloseSSHPortNeedsForce(t *testing.T) {
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.20 2222")
	f := &fakeRunner{}
	a := app{out: &bytes.Buffer{}, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"close", "2222/tcp"}); err == nil {
		t.Fatal("expected SSH protection error")
	}
	if len(f.calls) != 0 {
		t.Fatal("firewall-cmd must not run")
	}
	if err := a.execute([]string{"close", "2222/tcp", "--force", "--permanent"}); err != nil {
		t.Fatal(err)
	}
}
func TestPermanentLimitsChange(t *testing.T) {
	f := &fakeRunner{}
	a := app{out: &bytes.Buffer{}, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"close", "53/udp", "--permanent", "--zone", "public"}); err != nil {
		t.Fatal(err)
	}
	want := []call{{"firewall-cmd", []string{"--permanent", "--zone=public", "--remove-port=53/udp"}}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %#v, want %#v", f.calls, want)
	}
}

func TestDeleteRequiresExplicitZone(t *testing.T) {
	f := &fakeRunner{}
	a := app{out: &bytes.Buffer{}, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"delete", "1"}); err == nil {
		t.Fatal("expected explicit-zone error")
	}
	if len(f.calls) != 0 {
		t.Fatal("firewall-cmd must not run without an explicit zone")
	}
}

func TestForceIsRejectedForOpen(t *testing.T) {
	f := &fakeRunner{}
	a := app{out: &bytes.Buffer{}, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"open", "443/tcp", "--zone", "public", "--force"}); err == nil {
		t.Fatal("expected invalid-force error")
	}
	if len(f.calls) != 0 {
		t.Fatal("firewall-cmd must not run")
	}
}

func TestTimeoutOpensRuntimeOnly(t *testing.T) {
	f := &fakeRunner{}
	a := app{out: &bytes.Buffer{}, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"open", "8443/tcp", "--zone", "public", "--timeout", "10m"}); err != nil {
		t.Fatal(err)
	}
	want := []call{{"firewall-cmd", []string{"--zone=public", "--add-port=8443/tcp", "--timeout=10m"}}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %#v, want %#v", f.calls, want)
	}
}

func TestOpenService(t *testing.T) {
	f := &fakeRunner{}
	a := app{out: &bytes.Buffer{}, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"open", "service", "https", "--zone", "public"}); err != nil {
		t.Fatal(err)
	}
	want := []call{{"firewall-cmd", []string{"--zone=public", "--add-service=https"}}, {"firewall-cmd", []string{"--permanent", "--zone=public", "--add-service=https"}}}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls = %#v, want %#v", f.calls, want)
	}
}

func TestTimeoutRejectsPermanent(t *testing.T) {
	f := &fakeRunner{}
	a := app{out: &bytes.Buffer{}, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"open", "8443/tcp", "--zone", "public", "--timeout=10m", "--permanent"}); err == nil {
		t.Fatal("expected timeout/permanent error")
	}
	if len(f.calls) != 0 {
		t.Fatal("firewall-cmd must not run")
	}
}

func TestDryRunDoesNotInvokeFirewall(t *testing.T) {
	f := &fakeRunner{}
	var out bytes.Buffer
	a := app{out: &out, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"open", "443/tcp", "--zone", "public", "--dry-run"}); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("firewall-cmd calls = %#v, want none", f.calls)
	}
	want := "Would run: firewall-cmd --zone=public --add-port=443/tcp\nWould run: firewall-cmd --permanent --zone=public --add-port=443/tcp\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}
func TestRejectsInvalidPort(t *testing.T) {
	for _, port := range []string{"443", "0/tcp", "65536/tcp", "443/sctp", "x/tcp"} {
		if _, err := parsePort(port); err == nil {
			t.Errorf("parsePort(%q) succeeded", port)
		}
	}
}
func TestRunnerFailureIsReturned(t *testing.T) {
	f := &fakeRunner{err: errors.New("exit status 1")}
	a := app{out: &bytes.Buffer{}, err: &bytes.Buffer{}, run: f}
	if err := a.execute([]string{"status"}); err == nil {
		t.Fatal("expected error")
	}
}

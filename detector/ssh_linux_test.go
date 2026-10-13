package detector

import (
	"net"
	"os"
	"testing"
)

func TestParseSSHTarget(t *testing.T) {
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"host only":             {args: []string{"example.com"}, want: "example.com"},
		"user@host":             {args: []string{"deploy@10.0.0.5"}, want: "deploy@10.0.0.5"},
		"-l user":               {args: []string{"-l", "alice", "example.com"}, want: "alice@example.com"},
		"-luser attached":       {args: []string{"-luser", "example.com"}, want: "user@example.com"},
		"port option skipped":   {args: []string{"-p", "2222", "example.com"}, want: "example.com"},
		"-o value skipped":      {args: []string{"-o", "ProxyCommand=nc %h %p", "bob@host"}, want: "bob@host"},
		"flags before host":     {args: []string{"-A", "-v", "-N", "host"}, want: "host"},
		"double dash":           {args: []string{"--", "host"}, want: "host"},
		"no host":               {args: []string{"-V"}, want: ""},
		"user flag and at sign": {args: []string{"-l", "alice", "bob@example.com"}, want: "bob@example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := parseSSHTarget(test.args); got != test.want {
				t.Fatalf("parseSSHTarget(%q) = %q, want %q", test.args, got, test.want)
			}
		})
	}
}

func TestDecodeProcAddress(t *testing.T) {
	// 10.0.0.5:22 is stored as 0500000A in little-endian order
	ip, port, ok := decodeProcAddress("0500000A:0016")
	if !ok || !ip.Equal(net.IPv4(10, 0, 0, 5)) || port != 22 {
		t.Fatalf("IPv4 decode = %v, %d, %t", ip, port, ok)
	}

	// ::1 is stored as four little-endian words
	ip, port, ok = decodeProcAddress("00000000000000000000000001000000:01BB")
	if !ok || !ip.Equal(net.ParseIP("::1")) || port != 443 {
		t.Fatalf("IPv6 decode = %v, %d, %t", ip, port, ok)
	}

	for _, invalid := range []string{"", "0500000A", "ZZ:22", "0500000A:XYZ", "0500:22"} {
		if _, _, ok := decodeProcAddress(invalid); ok {
			t.Fatalf("decodeProcAddress(%q) accepted invalid input", invalid)
		}
	}
}

func TestDescribeSSHProcessIgnoresNonSSH(t *testing.T) {
	// The current test binary is not named ssh, so no detail must be produced
	if detail := describeSSHProcess(0); detail != "" {
		t.Fatalf("describeSSHProcess(0) = %q, want empty", detail)
	}
}

func TestParentPID(t *testing.T) {
	if got, want := parentPID(os.Getpid()), os.Getppid(); got != want {
		t.Fatalf("parentPID(self) = %d, want %d", got, want)
	}
}

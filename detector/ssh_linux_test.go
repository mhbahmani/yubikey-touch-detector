package detector

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
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
	if ctx := describeSSHProcess(0); ctx != (notifier.TouchContext{}) {
		t.Fatalf("describeSSHProcess(0) = %+v, want empty", ctx)
	}
}

func TestParentPID(t *testing.T) {
	if got, want := parentPID(os.Getpid()), os.Getppid(); got != want {
		t.Fatalf("parentPID(self) = %d, want %d", got, want)
	}
}

func TestIsSSHAgentProcess(t *testing.T) {
	for name, want := range map[string]bool{
		"ssh-agent":       true,
		"gcr-ssh-agent":   true,
		"gnome-keyring-d": true,
		"ssh-sk-helper":   false,
		"firefox":         false,
		"ssh":             false,
		"":                false,
	} {
		if got := isSSHAgentProcess(name); got != want {
			t.Fatalf("isSSHAgentProcess(%q) = %t, want %t", name, got, want)
		}
	}
}

func TestSSHAgentRequestContext(t *testing.T) {
	first := notifier.TouchContext{Host: "worker-a", IP: "10.60.12.129", Port: "22"}
	second := notifier.TouchContext{Host: "worker-b", IP: "10.60.12.130", Port: "22"}
	third := notifier.TouchContext{Host: "worker-c", IP: "10.60.12.132", Port: "22"}
	ansibleFirst, ansibleSecond := first, second
	ansibleFirst.Ansible, ansibleSecond.Ansible = true, true
	for _, test := range []struct {
		name    string
		details map[notifier.TouchContext]bool
		want    notifier.TouchContext
	}{
		{name: "unknown"},
		{name: "single destination", details: map[notifier.TouchContext]bool{first: true}, want: first},
		{
			name:    "parallel SSH authentications",
			details: map[notifier.TouchContext]bool{third: true, first: true, second: true},
			want:    notifier.TouchContext{SSHCandidates: "10.60.12.129:22, 10.60.12.130:22, 10.60.12.132:22"},
		},
		{
			name:    "confirmed Ansible workers",
			details: map[notifier.TouchContext]bool{ansibleSecond: true, ansibleFirst: true},
			want:    notifier.TouchContext{SSHCandidates: "10.60.12.129\n10.60.12.130", Ansible: true},
		},
		{
			name:    "mixed SSH and Ansible stays ambiguous",
			details: map[notifier.TouchContext]bool{ansibleFirst: true, second: true},
			want:    notifier.TouchContext{SSHCandidates: "10.60.12.129:22, 10.60.12.130:22"},
		},
		{
			name: "Ansible IPv4 numerical order",
			details: map[notifier.TouchContext]bool{
				{IP: "10.0.0.100", Ansible: true}: true,
				{IP: "10.0.0.2", Ansible: true}:   true,
				{IP: "10.0.0.10", Ansible: true}:  true,
			},
			want: notifier.TouchContext{SSHCandidates: "10.0.0.2\n10.0.0.10\n10.0.0.100", Ansible: true},
		},
		{
			name: "Ansible IPv6 numerical order",
			details: map[notifier.TouchContext]bool{
				{IP: "2001:db8::10", Ansible: true}: true,
				{IP: "2001:db8::2", Ansible: true}:  true,
			},
			want: notifier.TouchContext{SSHCandidates: "2001:db8::2\n2001:db8::10", Ansible: true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := sshAgentRequestContext(test.details); got != test.want {
				t.Fatalf("sshAgentRequestContext() = %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestHasAnsibleAncestor(t *testing.T) {
	if os.Getenv("YTD_TEST_ANSIBLE_PROCESS") == "child" {
		if !hasAnsibleAncestor(os.Getpid()) {
			t.Fatal("Ansible parent was not detected")
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("YTD_TEST_ANSIBLE_PROCESS") == "parent" {
		cmd := exec.Command(executable, "-test.run=^TestHasAnsibleAncestor$")
		cmd.Env = append(os.Environ(), "YTD_TEST_ANSIBLE_PROCESS=child")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, output)
		}
		return
	}
	if hasAnsibleAncestor(os.Getpid()) {
		t.Fatal("unrelated process was classified as Ansible")
	}
	for _, name := range []string{"ansible", "ansible-playbook"} {
		helper := filepath.Join(t.TempDir(), name)
		if err := os.Symlink(executable, helper); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(helper, "-test.run=^TestHasAnsibleAncestor$")
		cmd.Env = append(os.Environ(), "YTD_TEST_ANSIBLE_PROCESS=parent")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, output)
		}
	}
}

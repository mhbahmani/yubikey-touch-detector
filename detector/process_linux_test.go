package detector

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

func TestRequesterContextOfSelf(t *testing.T) {
	useTestApplications(t, "")
	ctx := requesterContext(os.Getpid())
	if ctx.PID != os.Getpid() || ctx.Process != processName(os.Getpid()) || ctx.Process == "" {
		t.Fatalf("requesterContext(self) = %+v", ctx)
	}
}

func TestRequesterContextKeepsPIDWithoutName(t *testing.T) {
	// Spawn a process and reap it, so its PID no longer has a /proc entry
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Skip("cannot run true: ", err)
	}
	pid := cmd.Process.Pid
	if got, want := requesterContext(pid), (notifier.TouchContext{PID: pid}); got != want {
		t.Fatalf("requesterContext(exited) = %+v, want %+v", got, want)
	}
	if got := requesterContext(0); got != (notifier.TouchContext{}) {
		t.Fatalf("requesterContext(0) = %+v, want empty", got)
	}
}

func TestRequesterNameCompletesTruncatedComm(t *testing.T) {
	const name = "a-very-long-requester-name"
	cmd := startNamed(t, name)

	if comm := processName(cmd.Process.Pid); comm != name[:commLength] {
		t.Fatalf("comm = %q, want the kernel to truncate it to %q", comm, name[:commLength])
	}
	if got := requesterName(cmd.Process.Pid); got != name {
		t.Fatalf("requesterName() = %q, want %q", got, name)
	}
}

func TestSSHRequestDetailNamesNonSSHClient(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "agent.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	client, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	// The test binary is the client; it is not ssh, so it is named instead
	want := notifier.TouchContext{Process: requesterName(os.Getpid()), PID: os.Getpid()}
	if got := sshRequestDetail(server); got != want {
		t.Fatalf("sshRequestDetail() = %+v, want %+v", got, want)
	}
}

// startNamed runs sleep under another name and returns its process
func startNamed(t *testing.T, name string) *exec.Cmd {
	t.Helper()
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep is not available")
	}
	helper := filepath.Join(t.TempDir(), name)
	if err := os.Symlink(sleep, helper); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(helper, "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})
	return cmd
}

func TestRequesterContextNamesAppRunningSigningTool(t *testing.T) {
	useTestApplications(t)
	for _, tool := range []string{"gpg", "ssh-keygen"} {
		t.Run(tool, func(t *testing.T) {
			// The test binary plays the app, e.g. an IDE, that runs the tool
			child := startNamed(t, tool)
			want := notifier.TouchContext{Process: "Fake IDE", PID: os.Getpid(), Via: tool}
			if got := requesterContext(child.Process.Pid); got != want {
				t.Fatalf("requesterContext(%s) = %+v, want %+v", tool, got, want)
			}
		})
	}
}

func TestRequesterContextKeepsOtherProcesses(t *testing.T) {
	useTestApplications(t)
	child := startNamed(t, "firefox")
	want := notifier.TouchContext{Process: "firefox", PID: child.Process.Pid}
	if got := requesterContext(child.Process.Pid); got != want {
		t.Fatalf("requesterContext(firefox) = %+v, want %+v", got, want)
	}
}

// A shell started by an application, e.g. "sh -c gpg ...", is passed through
// to that application; only a shell in a terminal hides it (see
// TestIsTerminalSpawn)
func TestRequesterContextSeesThroughScriptShell(t *testing.T) {
	useTestApplications(t)
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("sleep is not available")
	}
	helper := filepath.Join(t.TempDir(), "gpg")
	if err := os.Symlink(sleep, helper); err != nil {
		t.Fatal(err)
	}
	// Run gpg from a shell started by the test binary, and learn its PID
	shell := exec.Command("sh", "-c", `"$0" 10 & echo $!; wait`, helper)
	stdout, err := shell.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := shell.Start(); err != nil {
		t.Fatal(err)
	}
	var pid int
	_, scanErr := fmt.Fscan(stdout, &pid)
	defer func() {
		if pid > 0 {
			syscall.Kill(pid, syscall.SIGKILL)
		}
		shell.Wait()
	}()
	if scanErr != nil {
		t.Fatal(scanErr)
	}

	// The shell forks before it runs gpg; a real client has already started
	// gpg by the time it connects to the agent
	for deadline := time.Now().Add(2 * time.Second); processName(pid) != "gpg" && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	want := notifier.TouchContext{Process: "Fake IDE", PID: os.Getpid(), Via: "gpg"}
	if got := requesterContext(pid); got != want {
		t.Fatalf("requesterContext(gpg from sh) = %+v, want %+v", got, want)
	}
}

func TestIsShell(t *testing.T) {
	for name, want := range map[string]bool{
		"zsh":  true,
		"-zsh": true,
		"sh":   true,
		"git":  false,
		"gpg":  false,
		"":     false,
	} {
		if got := isShell(name); got != want {
			t.Fatalf("isShell(%q) = %t, want %t", name, got, want)
		}
	}
}

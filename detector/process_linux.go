package detector

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

// commLength is the most characters the kernel keeps in /proc/<pid>/comm
const commLength = 15

// peerCredentials returns the credentials of the process on the other end of
// a unix socket
func peerCredentials(conn net.Conn) (*unix.Ucred, bool) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, false
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return nil, false
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return nil, false
	}
	return cred, true
}

// requesterContext describes a process that asked for a touch. The PID is
// kept even when the name cannot be read, so the request is never anonymous.
// Signing tools usually run on behalf of another program, so that program is
// named instead, e.g. git running gpg to sign a commit.
func requesterContext(pid int) notifier.TouchContext {
	if pid <= 0 {
		return notifier.TouchContext{}
	}
	ctx := notifier.TouchContext{Process: requesterName(pid), PID: pid}
	if !isSigningTool(ctx.Process) {
		return ctx
	}
	parent := parentPID(pid)
	if parent <= 1 {
		return ctx
	}
	// A shell parent means the tool was run by hand; naming the shell would
	// say nothing useful
	name := requesterName(parent)
	if name == "" || isShell(name) || isSigningTool(name) {
		return ctx
	}
	return notifier.TouchContext{Process: name, PID: parent, Via: ctx.Process}
}

// isSigningTool reports whether a process signs or decrypts for the program
// that runs it, e.g. gpg for git, pass, or a mail client
func isSigningTool(name string) bool {
	switch name {
	case "gpg", "gpg2", "gpgsm", "ssh-keygen":
		return true
	}
	return false
}

// isShell reports whether a process name belongs to a command shell
func isShell(name string) bool {
	switch strings.TrimPrefix(name, "-") {
	case "sh", "bash", "zsh", "fish", "dash", "ksh", "mksh", "tcsh", "csh", "nu", "elvish", "xonsh", "busybox":
		return true
	}
	return false
}

// requesterName returns the name of a process. The kernel truncates comm, so
// a truncated name is completed from the executable in the command line,
// e.g. "ansible-playboo" becomes "ansible-playbook".
func requesterName(pid int) string {
	name := processName(pid)
	if len(name) < commLength {
		return name
	}
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return name
	}
	executable := filepath.Base(strings.SplitN(string(argv), "\x00", 2)[0])
	if strings.HasPrefix(executable, name) {
		return executable
	}
	return name
}

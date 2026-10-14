package detector

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

// sshOptionsWithValue lists ssh flags that consume the following argument
const sshOptionsWithValue = "BbcDEeFIiJLlmOoPpQRSWw"

// sshRequestDetail describes the ssh client connected to the agent socket.
// It returns the zero value when the client cannot be identified as ssh.
func sshRequestDetail(conn net.Conn) notifier.TouchContext {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return notifier.TouchContext{}
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return notifier.TouchContext{}
	}

	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return notifier.TouchContext{}
	}

	return describeSSHProcess(int(cred.Pid))
}

// describeSSHProcess reads the user, host, and remote address of an ssh process
func describeSSHProcess(pid int) notifier.TouchContext {
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return notifier.TouchContext{}
	}
	args := strings.Split(strings.TrimRight(string(argv), "\x00"), "\x00")
	if len(args) == 0 || filepath.Base(args[0]) != "ssh" {
		return notifier.TouchContext{}
	}

	user, host := splitSSHTarget(parseSSHTarget(args[1:]))
	var ip, port string
	if address := remoteAddress(pid); address != "" {
		ip, port, _ = net.SplitHostPort(address)
	}
	return notifier.TouchContext{User: user, Host: host, IP: ip, Port: port}
}

// splitSSHTarget splits "user@host" into its parts
func splitSSHTarget(target string) (user, host string) {
	if i := strings.LastIndex(target, "@"); i >= 0 {
		return target[:i], target[i+1:]
	}
	return "", target
}

// parseSSHTarget returns "user@host" (or just "host") from ssh arguments
func parseSSHTarget(args []string) string {
	var user, host string
	for i := 0; i < len(args) && host == ""; i++ {
		arg := args[i]
		if arg == "--" {
			if i+1 < len(args) {
				host = args[i+1]
			}
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			host = arg
			break
		}
		for j := 1; j < len(arg); j++ {
			flag := arg[j]
			if !strings.ContainsRune(sshOptionsWithValue, rune(flag)) {
				continue
			}
			value := arg[j+1:]
			if value == "" && i+1 < len(args) {
				i++
				value = args[i]
			}
			if flag == 'l' {
				user = value
			}
			break
		}
	}

	if host == "" {
		return ""
	}
	if !strings.Contains(host, "@") && user != "" {
		host = user + "@" + host
	}
	return host
}

// remoteAddress returns the peer "ip:port" of the first established TCP
// connection owned by pid
func remoteAddress(pid int) string {
	inodes := socketInodes(pid)
	if len(inodes) == 0 {
		return ""
	}

	for _, table := range []string{"tcp", "tcp6"} {
		content, err := os.ReadFile(fmt.Sprintf("/proc/net/%s", table))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(content), "\n")[1:] {
			fields := strings.Fields(line)
			// Field 3 is the state, 1 is ESTABLISHED
			if len(fields) < 10 || fields[3] != "01" || !inodes[fields[9]] {
				continue
			}
			if ip, port, ok := decodeProcAddress(fields[2]); ok {
				return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
			}
		}
	}
	return ""
}

// socketInodes lists the inode numbers of all sockets held open by pid
func socketInodes(pid int) map[string]bool {
	inodes := make(map[string]bool)
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return inodes
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") {
			continue
		}
		inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
	}
	return inodes
}

// decodeProcAddress parses an address from /proc/net/tcp(6), which stores each
// 32-bit word of the IP in little-endian order, as "HEXIP:HEXPORT"
func decodeProcAddress(value string) (net.IP, uint16, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, false
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil || (len(raw) != net.IPv4len && len(raw) != net.IPv6len) {
		return nil, 0, false
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return ip, uint16(port), true
}

// touchContextForDevice describes the request that is talking to a FIDO
// device directly. The process holding the hidraw node open is the ssh client
// itself (ed25519-sk key), an SSH agent helper, or the application making the
// request, e.g. a browser during a WebAuthn operation.
func touchContextForDevice(devicePath string) notifier.TouchContext {
	fds, err := filepath.Glob("/proc/[0-9]*/fd/*")
	if err != nil {
		return notifier.TouchContext{}
	}
	for _, fd := range fds {
		if target, err := os.Readlink(fd); err != nil || target != devicePath {
			continue
		}
		holder, err := strconv.Atoi(strings.Split(fd, "/")[2])
		if err != nil {
			continue
		}
		for depth, pid := 0, holder; depth < 4 && pid > 1; depth, pid = depth+1, parentPID(pid) {
			if ctx := describeSSHProcess(pid); ctx != (notifier.TouchContext{}) {
				log.Debugf("Touch request on %s comes from %+v", devicePath, ctx)
				return ctx
			}
			if isSSHAgentProcess(processName(pid)) {
				// The key is used through an SSH agent; its client cannot be
				// found from the device
				log.Debugf("Touch request on %s goes through an SSH agent", devicePath)
				return sshDetailForAgentRequest()
			}
		}
		// The holder is the application itself, e.g. a browser; the agent
		// fallback must not run here, it could blame an unrelated ssh session
		log.Debugf("Touch request on %s comes from %s", devicePath, processName(holder))
		return notifier.TouchContext{Process: processName(holder)}
	}
	log.Debugf("No process found holding %s open, checking ssh sessions using an agent", devicePath)
	return sshDetailForAgentRequest()
}

// processName reads the name of a process from /proc/<pid>/comm
func processName(pid int) string {
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(comm))
}

// isSSHAgentProcess reports whether a process name belongs to an SSH agent or
// its security key helper
func isSSHAgentProcess(name string) bool {
	switch name {
	case "ssh-agent", "gcr-ssh-agent", "gnome-keyring-d", "ssh-sk-helper":
		return true
	}
	return false
}

// sshDetailForAgentRequest handles security keys used through an SSH agent.
// The agent (e.g. gnome-keyring or ssh-agent) talks to the device and runs
// ssh-sk-helper as its own child, so the ssh client cannot be found from the
// device. Instead, look for ssh clients that use an agent and have a live TCP
// connection. A host is only reported when exactly one such session exists,
// so the wrong address is never shown.
func sshDetailForAgentRequest() notifier.TouchContext {
	procs, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		return notifier.TouchContext{}
	}
	details := make(map[notifier.TouchContext]bool)
	for _, proc := range procs {
		argv, err := os.ReadFile(proc)
		if err != nil {
			continue
		}
		args := strings.Split(strings.TrimRight(string(argv), "\x00"), "\x00")
		if len(args) == 0 || filepath.Base(args[0]) != "ssh" {
			continue
		}
		pid, err := strconv.Atoi(strings.Split(proc, "/")[2])
		// Only a session that is talking to the agent right now has an open
		// unix socket; idle sessions have closed it after authenticating
		if err != nil || !usesSSHAgent(pid) || !hasOpenUnixSocket(pid) {
			continue
		}
		if ctx := describeSSHProcess(pid); ctx.IP != "" {
			details[ctx] = true
		}
	}
	if len(details) != 1 {
		log.Debugf("Found %d ssh sessions using an SSH agent with a live connection", len(details))
		return notifier.TouchContext{}
	}
	for ctx := range details {
		log.Debugf("Touch request comes from %+v (via SSH agent)", ctx)
		return ctx
	}
	return notifier.TouchContext{}
}

// usesSSHAgent reports whether the process environment sets SSH_AUTH_SOCK
func usesSSHAgent(pid int) bool {
	env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return false
	}
	for _, entry := range strings.Split(string(env), "\x00") {
		if strings.HasPrefix(entry, "SSH_AUTH_SOCK=") && len(entry) > len("SSH_AUTH_SOCK=") {
			return true
		}
	}
	return false
}

// parentPID reads the parent process ID from /proc/<pid>/stat
func parentPID(pid int) int {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	// The command name is in parentheses and may contain spaces
	fields := strings.Fields(string(stat)[strings.LastIndex(string(stat), ")")+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}

// hasOpenUnixSocket reports whether pid holds an open unix socket, which is
// how ssh talks to an agent during authentication
func hasOpenUnixSocket(pid int) bool {
	inodes := socketInodes(pid)
	if len(inodes) == 0 {
		return false
	}
	content, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(content), "\n")[1:] {
		fields := strings.Fields(line)
		// The inode is the seventh field
		if len(fields) >= 7 && inodes[fields[6]] {
			return true
		}
	}
	return false
}

package detector

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"
)

// sshOptionsWithValue lists ssh flags that consume the following argument
const sshOptionsWithValue = "BbcDEeFIiJLlmOoPpQRSWw"

// sshRequestDetail describes the ssh client connected to the agent socket,
// e.g. "SSH to user@host (1.2.3.4:22)". It returns an empty string when the
// client cannot be identified as ssh.
func sshRequestDetail(conn net.Conn) string {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return ""
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return ""
	}

	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil || credErr != nil {
		return ""
	}

	return describeSSHProcess(int(cred.Pid))
}

func describeSSHProcess(pid int) string {
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	args := strings.Split(strings.TrimRight(string(argv), "\x00"), "\x00")
	if len(args) == 0 || filepath.Base(args[0]) != "ssh" {
		return ""
	}

	target := parseSSHTarget(args[1:])
	address := remoteAddress(pid)

	switch {
	case target != "" && address != "":
		return fmt.Sprintf("SSH to %s (%s)", target, address)
	case address != "":
		return fmt.Sprintf("SSH to %s", address)
	case target != "":
		return fmt.Sprintf("SSH to %s", target)
	default:
		return "SSH"
	}
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

// sshDetailForDevice describes the ssh session that is talking to a FIDO
// device directly, e.g. for an ed25519-sk key. The process holding the hidraw
// node open is either ssh itself or its ssh-sk-helper child.
func sshDetailForDevice(devicePath string) string {
	fds, err := filepath.Glob("/proc/[0-9]*/fd/*")
	if err != nil {
		return ""
	}
	for _, fd := range fds {
		if target, err := os.Readlink(fd); err != nil || target != devicePath {
			continue
		}
		pid, err := strconv.Atoi(strings.Split(fd, "/")[2])
		if err != nil {
			continue
		}
		for depth := 0; depth < 4 && pid > 1; depth++ {
			if detail := describeSSHProcess(pid); detail != "" {
				log.Debugf("Touch request on %s comes from %s", devicePath, detail)
				return detail
			}
			pid = parentPID(pid)
		}
	}
	log.Debugf("No ssh process found holding %s open, checking ssh sessions using an agent", devicePath)
	return sshDetailForAgentRequest()
}

// sshDetailForAgentRequest handles security keys used through an SSH agent.
// The agent (e.g. gnome-keyring or ssh-agent) talks to the device and runs
// ssh-sk-helper as its own child, so the ssh client cannot be found from the
// device. Instead, look for ssh clients that use an agent and have a live TCP
// connection. A host is only reported when exactly one such session exists,
// so the wrong address is never shown.
func sshDetailForAgentRequest() string {
	procs, err := filepath.Glob("/proc/[0-9]*/cmdline")
	if err != nil {
		return ""
	}
	details := make(map[string]bool)
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
		if detail := describeSSHProcess(pid); strings.Contains(detail, "(") {
			details[detail] = true
		}
	}
	if len(details) != 1 {
		log.Debugf("Found %d ssh sessions using an SSH agent with a live connection", len(details))
		return ""
	}
	for detail := range details {
		log.Debugf("Touch request comes from %s (via SSH agent)", detail)
		return detail
	}
	return ""
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

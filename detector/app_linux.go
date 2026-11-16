package detector

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxAncestors bounds the walk up the process tree
const maxAncestors = 32

// isPlumbing reports whether a process only passes a request along, so the
// program that started it is the one to name, e.g. git and ssh run by an IDE
func isPlumbing(name string) bool {
	if isShell(name) || strings.HasPrefix(name, "git-") {
		return true
	}
	switch name {
	case "ssh", "scp", "sftp", "rsync", "git", "env", "nice", "ionice", "timeout", "flock", "xargs", "nohup", "setsid", "stdbuf":
		return true
	}
	return false
}

// requestingApp names the application behind a process, e.g. "Cursor" for an
// ssh that Cursor started through git. It is empty when the command was typed
// in a terminal, where naming the terminal would say nothing useful.
func requestingApp(pid int) string {
	app, ok := appAncestor(pid)
	if !ok {
		return ""
	}
	name, terminal := appDisplayName(app, true)
	if terminal {
		return ""
	}
	return name
}

// appAncestor finds the first process above pid that is not plumbing. It
// reports false when the walk reaches a shell started by a terminal.
func appAncestor(pid int) (int, bool) {
	for depth := 0; depth < maxAncestors && pid > 1; depth++ {
		name := requesterName(pid)
		if name == "" {
			return 0, false
		}
		if !isPlumbing(name) {
			return pid, true
		}
		parent := parentPID(pid)
		if isShell(name) && isTerminalSpawn(processScope(pid), processScope(parent)) {
			return 0, false
		}
		pid = parent
	}
	return 0, false
}

// isTerminalSpawn reports whether a shell runs in its own scope created by a
// terminal emulator, e.g. a VTE terminal or tmux. A shell sharing its
// parent's scope belongs to that application, e.g. an IDE's built-in terminal.
func isTerminalSpawn(shellScope, parentScope string) bool {
	if shellScope == "" || shellScope == parentScope {
		return false
	}
	return strings.HasPrefix(shellScope, "vte-spawn-") || strings.HasPrefix(shellScope, "tmux-spawn-")
}

// processScope returns the name of the systemd unit holding a process, e.g.
// "app-gnome-code-1234.scope"
func processScope(pid int) string {
	cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	// The unified hierarchy has a single "0::/path" line
	for _, line := range strings.Split(strings.TrimSpace(string(cgroup)), "\n") {
		if path, found := strings.CutPrefix(line, "0::"); found {
			return filepath.Base(path)
		}
	}
	return ""
}

// appDisplayName names an application process the way the desktop does, e.g.
// "Visual Studio Code" rather than "code", and reports whether it is a
// terminal emulator. It prefers the desktop entry of the executable itself,
// since an application started by another one, e.g. an IDE launched from
// JetBrains Toolbox, runs in its launcher's scope. With useScope, a process
// without its own entry is named after the application whose scope it runs
// in, e.g. a command line tool shipped inside a desktop application.
func appDisplayName(pid int, useScope bool) (string, bool) {
	index := desktopIndex()
	if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		if entry, ok := index.byExecutable(strings.TrimSuffix(exe, " (deleted)"), processArgs(pid)); ok {
			return entry.name, entry.terminal
		}
	}
	if useScope {
		for _, id := range scopeDesktopIDs(processScope(pid)) {
			if entry, ok := index.byID[id]; ok {
				return entry.name, entry.terminal
			}
		}
	}
	return requesterName(pid), false
}

// scopeEscape matches the \xNN escapes systemd uses in unit names
var scopeEscape = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)

// scopeDesktopIDs returns the desktop entry IDs a systemd unit may belong
// to. Desktops start applications in units named after their entry, e.g.
// "app-gnome-jetbrains\x2dgoland-1234.scope", "app-flatpak-org.gimp.GIMP-1234.scope",
// or "snap.code.code-<uuid>.scope".
func scopeDesktopIDs(unit string) []string {
	name := strings.TrimSuffix(strings.TrimSuffix(unit, ".scope"), ".service")
	if snap, found := strings.CutPrefix(name, "snap."); found {
		parts := strings.SplitN(snap, ".", 2)
		if len(parts) != 2 {
			return nil
		}
		app, _, _ := strings.Cut(parts[1], "-")
		return []string{parts[0] + "_" + app}
	}
	rest, found := strings.CutPrefix(name, "app-")
	if !found {
		return nil
	}
	if at := strings.Index(rest, "@"); at >= 0 {
		rest = rest[:at]
	} else if dash := strings.LastIndex(rest, "-"); dash >= 0 && strings.HasSuffix(unit, ".scope") {
		// Scopes end in the PID or another unique suffix
		rest = rest[:dash]
	}
	// Dashes inside the ID are escaped, so a remaining dash separates the
	// launcher, e.g. "gnome" or "flatpak"
	fields := strings.Split(rest, "-")
	id := fields[len(fields)-1]
	if id == "" {
		return nil
	}
	return []string{unescapeUnit(id)}
}

func unescapeUnit(value string) string {
	return scopeEscape.ReplaceAllStringFunc(value, func(escape string) string {
		code, err := strconv.ParseUint(escape[2:], 16, 8)
		if err != nil {
			return escape
		}
		return string(rune(code))
	})
}

type desktopEntry struct {
	name     string
	terminal bool
	hidden   bool
	// args are the arguments the entry passes its executable, e.g. the
	// --app-id of a web app installed from a browser
	args []string
}

type desktopEntries struct {
	byID   map[string]*desktopEntry
	byExec map[string][]*desktopEntry
}

// byExecutable finds the entry that runs exe with arguments found in the
// process's command line, falling back to an entry installed in the same
// application directory, e.g. for an IDE whose process is its bundled Java
// runtime
func (entries *desktopEntries) byExecutable(exe string, args []string) (*desktopEntry, bool) {
	if entry, ok := pickEntry(entries.byExec[exe], args); ok {
		return entry, true
	}
	dir := filepath.Dir(exe)
	for depth := 0; depth < 3 && !isSharedDir(dir); depth++ {
		if entry, ok := pickEntry(entries.under(dir), args); ok {
			return entry, true
		}
		dir = filepath.Dir(dir)
	}
	return nil, false
}

// under lists the entries whose executable is installed below dir
func (entries *desktopEntries) under(dir string) []*desktopEntry {
	var found []*desktopEntry
	for exe, candidates := range entries.byExec {
		if strings.HasPrefix(exe, dir+"/") {
			found = append(found, candidates...)
		}
	}
	return found
}

// pickEntry chooses among entries sharing an executable. An entry matches
// when the process received all of its arguments; the most specific match
// wins, e.g. a browser web app over the browser, and visible entries win
// over hidden ones such as URL handlers. It fails when the best matches
// disagree on the name.
func pickEntry(candidates []*desktopEntry, args []string) (*desktopEntry, bool) {
	received := make(map[string]bool, len(args))
	for _, arg := range args {
		received[arg] = true
	}
	var best []*desktopEntry
	better := func(a, b *desktopEntry) bool {
		if a.hidden != b.hidden {
			return !a.hidden
		}
		return len(a.args) > len(b.args)
	}
	for _, candidate := range candidates {
		matches := true
		for _, arg := range candidate.args {
			matches = matches && received[arg]
		}
		switch {
		case !matches:
		case len(best) == 0 || better(candidate, best[0]):
			best = []*desktopEntry{candidate}
		case !better(best[0], candidate):
			best = append(best, candidate)
		}
	}
	if len(best) == 0 {
		return nil, false
	}
	for _, entry := range best[1:] {
		if entry.name != best[0].name {
			return nil, false
		}
	}
	return best[0], true
}

// processArgs returns the arguments a process was started with
func processArgs(pid int) []string {
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}
	args := strings.Split(strings.TrimRight(string(argv), "\x00"), "\x00")
	if len(args) == 0 {
		return nil
	}
	return args[1:]
}

// isSharedDir reports whether a directory holds many unrelated programs, so
// sharing it says nothing about belonging to one application
func isSharedDir(dir string) bool {
	if strings.Count(dir, "/") < 2 {
		return true
	}
	home, _ := os.UserHomeDir()
	switch dir {
	case "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/share", "/usr/local/lib", "/usr/local/share", "/opt", "/snap/bin", "/var/lib/flatpak",
		home, filepath.Join(home, ".local"), filepath.Join(home, ".local/bin"), filepath.Join(home, ".local/share"):
		return true
	}
	return false
}

var desktopCache struct {
	sync.Mutex
	entries *desktopEntries
	loaded  time.Time
}

// desktopCacheLifetime limits how long installed applications are remembered
const desktopCacheLifetime = time.Minute

func desktopIndex() *desktopEntries {
	desktopCache.Lock()
	defer desktopCache.Unlock()
	if desktopCache.entries == nil || time.Since(desktopCache.loaded) > desktopCacheLifetime {
		desktopCache.entries = loadDesktopEntries(applicationDirs())
		desktopCache.loaded = time.Now()
	}
	return desktopCache.entries
}

// applicationDirs lists the XDG application directories, most important
// first
func applicationDirs() []string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, _ := os.UserHomeDir()
		dataHome = filepath.Join(home, ".local/share")
	}
	dataDirs := os.Getenv("XDG_DATA_DIRS")
	if dataDirs == "" {
		dataDirs = "/usr/local/share:/usr/share"
	}
	dirs := []string{filepath.Join(dataHome, "applications")}
	for _, dir := range strings.Split(dataDirs, ":") {
		if dir != "" {
			dirs = append(dirs, filepath.Join(dir, "applications"))
		}
	}
	return dirs
}

// loadDesktopEntries indexes the applications in dirs. An entry in an
// earlier directory hides the same ID in a later one.
func loadDesktopEntries(dirs []string) *desktopEntries {
	entries := &desktopEntries{
		byID:   make(map[string]*desktopEntry),
		byExec: make(map[string][]*desktopEntry),
	}
	for _, dir := range dirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.desktop"))
		for _, file := range files {
			id := strings.TrimSuffix(filepath.Base(file), ".desktop")
			if _, seen := entries.byID[id]; seen {
				continue
			}
			parsed, ok := parseDesktopEntry(file)
			if !ok {
				continue
			}
			exe, args := resolveCommand(parsed.exec)
			entry := &desktopEntry{name: parsed.name, terminal: parsed.terminal, hidden: parsed.hidden, args: args}
			entries.byID[id] = entry
			if exe != "" {
				entries.byExec[exe] = append(entries.byExec[exe], entry)
			}
		}
	}
	return entries
}

type parsedDesktopEntry struct {
	name     string
	exec     string
	hidden   bool
	terminal bool
}

// parseDesktopEntry reads the [Desktop Entry] group of an application
func parseDesktopEntry(file string) (parsedDesktopEntry, bool) {
	f, err := os.Open(file)
	if err != nil {
		return parsedDesktopEntry{}, false
	}
	defer f.Close()

	var entry parsedDesktopEntry
	isApplication := false
	inGroup := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			if inGroup {
				break
			}
			inGroup = line == "[Desktop Entry]"
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !inGroup || !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Type":
			isApplication = strings.TrimSpace(value) == "Application"
		case "Name":
			entry.name = strings.TrimSpace(value)
		case "Exec":
			entry.exec = strings.TrimSpace(value)
		case "NoDisplay", "Hidden":
			entry.hidden = entry.hidden || strings.TrimSpace(value) == "true"
		case "Categories":
			for _, category := range strings.Split(value, ";") {
				entry.terminal = entry.terminal || category == "TerminalEmulator"
			}
		}
	}
	return entry, isApplication && entry.name != ""
}

// resolveCommand returns the real path of the program an Exec line runs and
// the arguments it passes, skipping "env", variable assignments, and field
// codes such as %U
func resolveCommand(execLine string) (string, []string) {
	fields := splitExec(execLine)
	for i, field := range fields {
		if field == "env" || (strings.Contains(field, "=") && !strings.Contains(field, "/")) {
			continue
		}
		path := field
		if !strings.Contains(path, "/") {
			found, err := exec.LookPath(path)
			if err != nil {
				return "", nil
			}
			path = found
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return "", nil
		}
		var args []string
		for _, arg := range fields[i+1:] {
			if !(len(arg) == 2 && arg[0] == '%') {
				args = append(args, arg)
			}
		}
		return resolved, args
	}
	return "", nil
}

// splitExec splits an Exec line into fields, honoring double quotes
func splitExec(execLine string) []string {
	var fields []string
	var current strings.Builder
	quoted, escaped, started := false, false, false
	for _, r := range execLine {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case r == '\\' && quoted:
			escaped = true
		case r == '"':
			quoted = !quoted
			started = true
		case (r == ' ' || r == '\t') && !quoted:
			if started {
				fields = append(fields, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteRune(r)
			started = true
		}
	}
	if started {
		fields = append(fields, current.String())
	}
	return fields
}

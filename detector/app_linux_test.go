package detector

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// useTestApplications indexes only the given desktop entries, by default one
// named "Fake IDE" that runs the test binary, so results do not depend on
// the applications installed on this machine
func useTestApplications(t *testing.T, entries ...string) {
	t.Helper()
	if len(entries) == 0 {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		entries = []string{"[Desktop Entry]\nType=Application\nName=Fake IDE\nExec=\"" + self + "\" %F\n"}
	}
	dataHome := t.TempDir()
	dir := filepath.Join(dataHome, "applications")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i, entry := range entries {
		if entry == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, "app"+string(rune('a'+i))+".desktop"), []byte(entry), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_DATA_DIRS", filepath.Join(dataHome, "none"))
	resetDesktopCache := func() {
		desktopCache.Lock()
		desktopCache.entries = nil
		desktopCache.Unlock()
	}
	resetDesktopCache()
	t.Cleanup(resetDesktopCache)
}

func TestRequestingAppSkipsGitAndSSH(t *testing.T) {
	useTestApplications(t)
	// The test binary plays the IDE that runs git, which runs ssh
	for _, name := range []string{"git", "ssh", "git-remote-https"} {
		child := startNamed(t, name)
		if got := requestingApp(child.Process.Pid); got != "Fake IDE" {
			t.Errorf("requestingApp(%s) = %q, want %q", name, got, "Fake IDE")
		}
	}
}

func TestIsTerminalSpawn(t *testing.T) {
	for _, test := range []struct {
		shell, parent string
		want          bool
	}{
		{"vte-spawn-3e7f8af6.scope", "app-gnome-org.gnome.Terminal-1.scope", true},
		{"tmux-spawn-3e7f8af6.scope", "session-2.scope", true},
		// An IDE's built-in terminal, even in an IDE launched from a terminal
		{"app-cursor-1064074.scope", "app-cursor-1064074.scope", false},
		{"vte-spawn-3e7f8af6.scope", "vte-spawn-3e7f8af6.scope", false},
		{"app-cursor-1064074.scope", "init.scope", false},
		{"", "init.scope", false},
	} {
		if got := isTerminalSpawn(test.shell, test.parent); got != test.want {
			t.Errorf("isTerminalSpawn(%q, %q) = %t, want %t", test.shell, test.parent, got, test.want)
		}
	}
}

func TestScopeDesktopIDs(t *testing.T) {
	for unit, want := range map[string][]string{
		"app-cursor-1064074.scope":                                  {"cursor"},
		`app-gnome-jetbrains\x2dpycharm\x2d31f8d2d5-12345.scope`:    {"jetbrains-pycharm-31f8d2d5"},
		"app-com.anthropic.Claude-1019075.scope":                    {"com.anthropic.Claude"},
		"app-flatpak-org.gimp.GIMP-4242.scope":                      {"org.gimp.GIMP"},
		`app-gnome-jetbrains\x2dtoolbox@autostart.service`:          {"jetbrains-toolbox"},
		"app-org.gnome.Terminal.service":                            {"org.gnome.Terminal"},
		"snap.code.code-3e7f8af6-9a7c-44d4-84d6-f7964dcbea2f.scope": {"code_code"},
		"vte-spawn-3e7f8af6-9a7c-44d4-84d6-f7964dcbea2f.scope":      nil,
		"session-2.scope": nil,
		"":                nil,
	} {
		if got := scopeDesktopIDs(unit); !slices.Equal(got, want) {
			t.Errorf("scopeDesktopIDs(%q) = %q, want %q", unit, got, want)
		}
	}
}

func TestSplitExec(t *testing.T) {
	for line, want := range map[string][]string{
		`/usr/share/cursor/cursor %F`:                     {"/usr/share/cursor/cursor", "%F"},
		`"/opt/My IDE/bin/ide" %u`:                        {"/opt/My IDE/bin/ide", "%u"},
		`env BAMF_DESKTOP_FILE_HINT=x /snap/bin/code --a`: {"env", "BAMF_DESKTOP_FILE_HINT=x", "/snap/bin/code", "--a"},
		`"/a/b \"c\"" d`:                                  {`/a/b "c"`, "d"},
	} {
		if got := splitExec(line); !slices.Equal(got, want) {
			t.Errorf("splitExec(%q) = %q, want %q", line, got, want)
		}
	}
}

func TestResolveCommand(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real-ide")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "ide")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	for line, want := range map[string]string{
		link + " --new-window %F":    target,
		"env FOO=bar ide %U":         target,
		"missing-program --flag":     "",
		"FOO=bar " + link + " --app": target,
	} {
		got, args := resolveCommand(line)
		if got != want {
			t.Errorf("resolveCommand(%q) = %q, want %q", line, got, want)
		}
		if slices.ContainsFunc(args, func(arg string) bool { return strings.HasPrefix(arg, "%") }) {
			t.Errorf("resolveCommand(%q) kept a field code in %q", line, args)
		}
	}
}

func TestPickEntryPrefersTheMatchingWebApp(t *testing.T) {
	browser := &desktopEntry{name: "Brave Web Browser"}
	chat := &desktopEntry{name: "FluffyChat", args: []string{"--profile-directory=Default", "--app-id=chat"}}
	mail := &desktopEntry{name: "Mail", args: []string{"--profile-directory=Default", "--app-id=mail"}}
	handler := &desktopEntry{name: "Browser URL Handler", hidden: true, args: []string{"--open-url"}}
	candidates := []*desktopEntry{chat, mail, browser, handler}
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"https://example.com"}, "Brave Web Browser"},
		{[]string{"--profile-directory=Default", "--app-id=chat"}, "FluffyChat"},
		{[]string{"--type=renderer", "--app-id=mail", "--profile-directory=Default"}, "Mail"},
		{[]string{"--open-url", "x"}, "Brave Web Browser"},
	} {
		entry, ok := pickEntry(candidates, test.args)
		if !ok || entry.name != test.want {
			t.Errorf("pickEntry(%q) = %+v, %t, want %q", test.args, entry, ok, test.want)
		}
	}
	// Web apps alone cannot name the browser itself
	if entry, ok := pickEntry([]*desktopEntry{chat, mail}, []string{"https://example.com"}); ok {
		t.Errorf("pickEntry matched %q without its app id", entry.name)
	}
	// Equally good entries with different names are ambiguous
	if _, ok := pickEntry([]*desktopEntry{{name: "A"}, {name: "B"}}, nil); ok {
		t.Error("pickEntry chose between two equally good entries")
	}
}

func TestByExecutableRecognizesBundledHelpers(t *testing.T) {
	root := t.TempDir()
	ide := filepath.Join(root, "goland", "bin", "goland")
	java := filepath.Join(root, "goland", "jbr", "bin", "java")
	for _, file := range []string{ide, java} {
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	apps := filepath.Join(root, "applications")
	if err := os.MkdirAll(apps, 0o755); err != nil {
		t.Fatal(err)
	}
	entry := "[Desktop Entry]\nType=Application\nName=GoLand 2026.2.3\nExec=\"" + ide + "\" %u\n"
	if err := os.WriteFile(filepath.Join(apps, "jetbrains-goland.desktop"), []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}
	index := loadDesktopEntries([]string{apps})
	for _, exe := range []string{ide, java} {
		got, ok := index.byExecutable(exe, nil)
		if !ok || got.name != "GoLand 2026.2.3" {
			t.Errorf("byExecutable(%s) = %+v, %t, want GoLand", exe, got, ok)
		}
	}
	if got, ok := index.byExecutable("/usr/bin/true", nil); ok {
		t.Errorf("byExecutable matched an unrelated program to %q", got.name)
	}
}

func TestParseDesktopEntry(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	terminal := write("term.desktop", "[Desktop Entry]\nType=Application\nName=Terminal\nName[de]=Terminal DE\nExec=term\nCategories=System;TerminalEmulator;\n\n[Desktop Action new]\nName=New Window\nExec=term --new\n")
	got, ok := parseDesktopEntry(terminal)
	if !ok || got.name != "Terminal" || got.exec != "term" || !got.terminal || got.hidden {
		t.Errorf("parseDesktopEntry(terminal) = %+v, %t", got, ok)
	}
	handler := write("handler.desktop", "[Desktop Entry]\nType=Application\nName=Handler\nExec=app --open-url %U\nNoDisplay=true\n")
	if got, ok := parseDesktopEntry(handler); !ok || !got.hidden {
		t.Errorf("parseDesktopEntry(handler) = %+v, %t, want hidden", got, ok)
	}
	link := write("link.desktop", "[Desktop Entry]\nType=Link\nName=Docs\nURL=https://example.com\n")
	if _, ok := parseDesktopEntry(link); ok {
		t.Error("parseDesktopEntry accepted a link entry")
	}
}

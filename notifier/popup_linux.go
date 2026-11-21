//go:build linux

package notifier

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

// failedStartWindow is how soon a dialog that exits with an error counts as
// having failed to open its window
const failedStartWindow = 3 * time.Second

type popupExit struct {
	cmd     *exec.Cmd
	err     error
	elapsed time.Duration
}

// SetupPopupNotifier shows the built-in touch dialog (the "popup"
// subcommand of this binary) whenever a touch is required, and terminates
// it once the touch is registered. Running the dialog as a child process
// keeps the GUI isolated from the detector.
func SetupPopupNotifier(notifiers *sync.Map, position string) {
	touch := make(chan Message, 10)
	notifiers.Store("notifier/popup", touch)

	state := newTouchState()
	display := newDisplayCache(os.Environ(), systemdUserEnvironment)
	var running *exec.Cmd
	var restart, stopping, retried bool
	exited := make(chan popupExit, 1)
	start := func() {
		self, err := os.Executable()
		if err != nil {
			log.Error("Cannot find this binary to launch the touch dialog: ", err)
			return
		}

		cmd := popupCommand(self, display.environment(os.Environ()), state.reasons(), touchDetails(), position)
		if err := cmd.Start(); err != nil {
			log.Error("Cannot launch the touch dialog: ", err)
			return
		}
		running, stopping = cmd, false
		started := time.Now()

		go func() {
			err := cmd.Wait()
			if err != nil {
				log.Debugf("Touch dialog exited: %v", err)
			}
			exited <- popupExit{cmd: cmd, err: err, elapsed: time.Since(started)}
		}()
	}

	for {
		var value Message
		select {
		case exit := <-exited:
			if running == exit.cmd {
				running = nil
				// A dialog that could not open its window may have used
				// display settings that went stale, e.g. after XWayland
				// restarted; read them again and retry once
				if exit.err != nil && !stopping && exit.elapsed < failedStartWindow && display.forget() && !retried && len(state.active) > 0 {
					log.Debug("Touch dialog failed to open, retrying with fresh display settings")
					retried = true
					start()
				} else if restart && len(state.active) > 0 {
					restart = false
					start()
				}
			}
			continue
		case value = <-touch:
		}

		wasActive, isActive, _ := state.update(value)
		if isActive && !wasActive {
			retried = false
			if running == nil {
				start()
			} else {
				restart = true
			}
		} else if !isActive && wasActive && running != nil {
			restart, stopping = false, true
			if err := syscall.Kill(-running.Process.Pid, syscall.SIGTERM); err != nil {
				log.Error("Cannot close the touch dialog: ", err)
			}
		}
	}
}

// popupCommand prepares the touch dialog process. Its content travels in
// the environment, which only this user can read, and the kernel terminates
// it if the detector dies, so it never outlives the touch it describes.
func popupCommand(self string, environ []string, reasons, details, position string) *exec.Cmd {
	cmd := exec.Command(self, "popup")
	cmd.Env = popupEnvironment(environ, reasons, details, position)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	return cmd
}

// noWayland names a Wayland socket that cannot exist. Unsetting
// WAYLAND_DISPLAY is not enough: libwayland then falls back to "wayland-0".
const noWayland = "/nonexistent/yubikey-touch-detector-uses-x11"

// EGL guesses its platform from the session and crashes setting up an X11
// window inside a Wayland session unless told the platform explicitly
const eglPlatformX11 = "EGL_PLATFORM=x11"

// popupEnvironment passes the dialog its content and position. Wayland does
// not let windows place themselves, so a positioned dialog runs through
// XWayland when it is available.
func popupEnvironment(environ []string, reasons, details, position string) []string {
	forceX11 := position != "auto" && lookupEnv(environ, "DISPLAY") != ""
	env := make([]string, 0, len(environ)+5)
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		switch {
		case name == PopupReasonsEnv, name == PopupDetailsEnv, name == PopupPositionEnv:
		case (name == "WAYLAND_DISPLAY" || name == "EGL_PLATFORM") && forceX11:
		default:
			env = append(env, entry)
		}
	}
	if forceX11 {
		env = append(env, "WAYLAND_DISPLAY="+noWayland, eglPlatformX11)
	}
	return append(env,
		PopupReasonsEnv+"="+reasons,
		PopupDetailsEnv+"="+details,
		PopupPositionEnv+"="+position,
	)
}

// displayVariables are what a window needs to reach the desktop
var displayVariables = []string{"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"}

// displayCache remembers the display variables the dialog needs. The
// detector usually starts with the session, before the desktop exports them,
// so until they are known they are read from the user's service manager each
// time the dialog opens. Once DISPLAY is known they are kept, as positioning
// needs it; a WAYLAND_DISPLAY alone may come before XWayland is ready.
type displayCache struct {
	values []string
	lookup func() ([]string, error)
}

func newDisplayCache(environ []string, lookup func() ([]string, error)) *displayCache {
	cache := &displayCache{lookup: lookup}
	// Started inside a running session, the detector's own values are current
	if lookupEnv(environ, "DISPLAY") != "" {
		cache.values = displayEntries(environ)
	}
	return cache
}

// environment returns environ with the session's display variables
func (cache *displayCache) environment(environ []string) []string {
	if cache.values != nil {
		return mergeDisplayVariables(environ, cache.values)
	}
	session, err := cache.lookup()
	if err != nil {
		log.Debugf("Cannot read the session environment, using the detector's own: %v", err)
		return environ
	}
	entries := displayEntries(session)
	if lookupEnv(entries, "DISPLAY") != "" {
		cache.values = entries
	}
	return mergeDisplayVariables(environ, entries)
}

// forget drops remembered values so the next dialog reads them again, and
// reports whether there was anything to drop
func (cache *displayCache) forget() bool {
	had := cache.values != nil
	cache.values = nil
	return had
}

// displayEntries picks the display variables out of an environment
func displayEntries(environ []string) []string {
	var entries []string
	for _, name := range displayVariables {
		if value := lookupEnv(environ, name); value != "" {
			entries = append(entries, name+"="+value)
		}
	}
	return entries
}

// systemdUserEnvironment reads the environment the user's service manager
// gives new processes, which the desktop updates when it starts
func systemdUserEnvironment() ([]string, error) {
	conn, err := dbus.SessionBusPrivate()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.Auth(nil); err != nil {
		return nil, err
	}
	if err := conn.Hello(); err != nil {
		return nil, err
	}
	value, err := conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").GetProperty("org.freedesktop.systemd1.Manager.Environment")
	if err != nil {
		return nil, err
	}
	environment, ok := value.Value().([]string)
	if !ok {
		return nil, fmt.Errorf("unexpected environment type %T", value.Value())
	}
	return environment, nil
}

// mergeDisplayVariables takes each display variable from session when it is
// set there, as the session's values are current, and keeps the rest of
// environ
func mergeDisplayVariables(environ, session []string) []string {
	merged := make([]string, 0, len(environ)+len(displayVariables))
	current := make(map[string]string)
	for _, name := range displayVariables {
		if value := lookupEnv(session, name); value != "" {
			current[name] = value
		}
	}
	for _, entry := range environ {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := current[name]; !replaced {
			merged = append(merged, entry)
		}
	}
	for _, name := range displayVariables {
		if value, found := current[name]; found {
			merged = append(merged, name+"="+value)
		}
	}
	return merged
}

func lookupEnv(environ []string, name string) string {
	for _, entry := range environ {
		if key, value, found := strings.Cut(entry, "="); found && key == name {
			return value
		}
	}
	return ""
}

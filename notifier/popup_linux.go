//go:build linux

package notifier

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"github.com/godbus/dbus/v5"
	log "github.com/sirupsen/logrus"
)

// SetupPopupNotifier shows the built-in touch dialog (the "popup"
// subcommand of this binary) whenever a touch is required, and terminates
// it once the touch is registered. Running the dialog as a child process
// keeps the GUI isolated from the detector.
func SetupPopupNotifier(notifiers *sync.Map, position string) {
	touch := make(chan Message, 10)
	notifiers.Store("notifier/popup", touch)

	state := newTouchState()
	var running *exec.Cmd
	var restart bool
	exited := make(chan *exec.Cmd, 1)
	start := func() {
		self, err := os.Executable()
		if err != nil {
			log.Error("Cannot find this binary to launch the touch dialog: ", err)
			return
		}

		cmd := popupCommand(self, sessionEnvironment(os.Environ()), state.reasons(), touchDetails(), position)
		if err := cmd.Start(); err != nil {
			log.Error("Cannot launch the touch dialog: ", err)
			return
		}
		running = cmd

		go func() {
			if err := cmd.Wait(); err != nil {
				log.Debugf("Touch dialog exited: %v", err)
			}
			exited <- cmd
		}()
	}

	for {
		var value Message
		select {
		case cmd := <-exited:
			if running == cmd {
				running = nil
				if restart && len(state.active) > 0 {
					restart = false
					start()
				}
			}
			continue
		case value = <-touch:
		}

		wasActive, isActive, _ := state.update(value)
		if isActive && !wasActive {
			if running == nil {
				start()
			} else {
				restart = true
			}
		} else if !isActive && wasActive && running != nil {
			restart = false
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

// sessionEnvironment returns environ with the desktop session's current
// display variables. The detector usually starts with the session, before
// the desktop exports them, so its own environment lacks them; without
// DISPLAY the dialog could not be positioned through XWayland.
func sessionEnvironment(environ []string) []string {
	session, err := systemdUserEnvironment()
	if err != nil {
		log.Debugf("Cannot read the session environment, using the detector's own: %v", err)
		return environ
	}
	return mergeDisplayVariables(environ, session)
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

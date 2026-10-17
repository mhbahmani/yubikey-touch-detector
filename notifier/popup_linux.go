//go:build linux

package notifier

import (
	"os"
	"os/exec"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// SetupPopupNotifier shows the built-in touch dialog (the "popup"
// subcommand of this binary) whenever a touch is required, and terminates
// it once the touch is registered. Running the dialog as a child process
// keeps the GUI isolated from the detector.
func SetupPopupNotifier(notifiers *sync.Map) {
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

		cmd := exec.Command(self, "popup", state.reasons(), touchDetails())
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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

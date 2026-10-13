package notifier

import (
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"text/template"

	log "github.com/sirupsen/logrus"
)

// SetupExecNotifier configures a notifier that starts a command when a touch
// is required and terminates it once the touch has been registered. This
// allows external tools to display persistent prompts, such as a dialog
// window that stays visible until the YubiKey is touched.
func SetupExecNotifier(notifiers *sync.Map, command string) {
	commandTemplate, err := template.New("exec command").Parse(command)
	if err != nil {
		log.Error("Cannot initialize exec notifier: ", err)
		return
	}

	touch := make(chan Message, 10)
	notifiers.Store("notifier/exec", touch)

	state := newTouchState()
	var running *exec.Cmd
	exited := make(chan *exec.Cmd, 1)

	for {
		var value Message
		select {
		case cmd := <-exited:
			if running == cmd {
				running = nil
			}
			continue
		case value = <-touch:
		}

		wasActive, isActive, _ := state.update(value)
		if isActive && !wasActive && running == nil {
			var rendered strings.Builder
			if err := commandTemplate.Execute(&rendered, newNotificationTemplateData(state.reasons())); err != nil {
				log.Error("Cannot render exec notifier command: ", err)
				continue
			}

			cmd := exec.Command("sh", "-c", rendered.String())
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			if err := cmd.Start(); err != nil {
				log.Error("Cannot start exec notifier command: ", err)
				continue
			}
			running = cmd

			go func() {
				if err := cmd.Wait(); err != nil {
					log.Debugf("Exec notifier command exited: %v", err)
				}
				exited <- cmd
			}()
		} else if !isActive && wasActive && running != nil {
			// Terminate the whole process group so shell wrappers die too
			if err := syscall.Kill(-running.Process.Pid, syscall.SIGTERM); err != nil {
				log.Error("Cannot terminate exec notifier command: ", err)
			}
		}
	}
}

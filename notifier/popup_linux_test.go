//go:build linux

package notifier

import (
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestPopupCommandKeepsContentOffTheCommandLine(t *testing.T) {
	cmd := popupCommand("/bin/ytd", []string{"HOME=/home/u"}, "u2f", "SSH to deploy@10.0.0.5", "center")
	if want := []string{"/bin/ytd", "popup"}; !slices.Equal(cmd.Args, want) {
		t.Fatalf("args = %q, want %q", cmd.Args, want)
	}
	for _, want := range []string{PopupReasonsEnv + "=u2f", PopupDetailsEnv + "=SSH to deploy@10.0.0.5", PopupPositionEnv + "=center", "HOME=/home/u"} {
		if !slices.Contains(cmd.Env, want) {
			t.Errorf("env %q is missing %q", cmd.Env, want)
		}
	}
	if attr := cmd.SysProcAttr; attr == nil || attr.Pdeathsig != syscall.SIGTERM || !attr.Setpgid {
		t.Fatalf("SysProcAttr = %+v, want Setpgid and Pdeathsig SIGTERM", attr)
	}
}

func TestPopupEnvironmentChoosesDisplay(t *testing.T) {
	environ := []string{"DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", PopupDetailsEnv + "=stale"}
	for _, test := range []struct {
		name        string
		environ     []string
		position    string
		wantWayland bool
	}{
		{"positioned dialog uses XWayland", environ, "center", false},
		{"auto keeps Wayland", environ, "auto", true},
		{"no X server keeps Wayland", []string{"WAYLAND_DISPLAY=wayland-0"}, "top-right", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			env := popupEnvironment(test.environ, "gpg", "fresh", test.position)
			if got := slices.Contains(env, "WAYLAND_DISPLAY=wayland-0"); got != test.wantWayland {
				t.Fatalf("WAYLAND_DISPLAY kept = %t, want %t (env %q)", got, test.wantWayland, env)
			}
			// libwayland falls back to wayland-0 when the variable is unset,
			// so it must name a missing socket instead
			if !test.wantWayland && (!slices.Contains(env, "WAYLAND_DISPLAY="+noWayland) || !slices.Contains(env, eglPlatformX11)) {
				t.Fatalf("env %q does not switch the dialog to X11", env)
			}
			var details []string
			for _, entry := range env {
				if strings.HasPrefix(entry, PopupDetailsEnv+"=") {
					details = append(details, entry)
				}
			}
			if want := []string{PopupDetailsEnv + "=fresh"}; !slices.Equal(details, want) {
				t.Fatalf("details entries = %q, want %q", details, want)
			}
		})
	}
}

func TestValidatePopupPosition(t *testing.T) {
	for _, position := range PopupPositions {
		if err := ValidatePopupPosition(position); err != nil {
			t.Errorf("ValidatePopupPosition(%q) = %v", position, err)
		}
	}
	for _, position := range []string{"", "middle", "Center", "top left"} {
		if err := ValidatePopupPosition(position); err == nil {
			t.Errorf("ValidatePopupPosition(%q) accepted an invalid position", position)
		}
	}
}

func TestMergeDisplayVariables(t *testing.T) {
	session := []string{"DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "XAUTHORITY=/run/user/1/.mutter-Xwaylandauth", "PATH=/session/bin"}
	for _, test := range []struct {
		name    string
		environ []string
		want    []string
	}{
		{
			// Started with the session, before the desktop exported them
			"missing from the detector",
			[]string{"HOME=/home/u", "PATH=/usr/bin"},
			[]string{"HOME=/home/u", "PATH=/usr/bin", "DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "XAUTHORITY=/run/user/1/.mutter-Xwaylandauth"},
		},
		{
			// Left over from an earlier login
			"stale in the detector",
			[]string{"DISPLAY=:1", "HOME=/home/u", "XAUTHORITY=/old"},
			[]string{"HOME=/home/u", "DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "XAUTHORITY=/run/user/1/.mutter-Xwaylandauth"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := mergeDisplayVariables(test.environ, session); !slices.Equal(got, test.want) {
				t.Fatalf("mergeDisplayVariables() = %q, want %q", got, test.want)
			}
		})
	}
	// Variables the session does not set are kept as they are
	if got := mergeDisplayVariables([]string{"DISPLAY=:5"}, []string{"PATH=/bin"}); !slices.Equal(got, []string{"DISPLAY=:5"}) {
		t.Fatalf("mergeDisplayVariables() without session values = %q", got)
	}
}

func TestSessionEnvironmentReadsSystemd(t *testing.T) {
	session, err := systemdUserEnvironment()
	if err != nil {
		t.Skipf("no user service manager on the session bus: %v", err)
	}
	if len(session) == 0 {
		t.Fatal("the user service manager reported an empty environment")
	}
}

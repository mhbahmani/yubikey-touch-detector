//go:build linux

package notifier

import (
	"errors"
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

// fakeSession counts lookups and returns the environment it currently holds
type fakeSession struct {
	calls   int
	environ []string
	err     error
}

func (session *fakeSession) lookup() ([]string, error) {
	session.calls++
	return session.environ, session.err
}

func TestDisplayCacheLooksUpUntilDisplayIsKnown(t *testing.T) {
	session := &fakeSession{environ: []string{"WAYLAND_DISPLAY=wayland-0"}}
	cache := newDisplayCache([]string{"HOME=/home/u"}, session.lookup)

	// Early in a login only Wayland is ready; it is used but not kept
	env := cache.environment([]string{"HOME=/home/u"})
	if !slices.Contains(env, "WAYLAND_DISPLAY=wayland-0") {
		t.Fatalf("env %q lacks the session's WAYLAND_DISPLAY", env)
	}
	cache.environment(nil)
	if session.calls != 2 {
		t.Fatalf("looked up %d times before DISPLAY was known, want 2", session.calls)
	}

	// Once XWayland is up, the values are kept
	session.environ = []string{"DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "XAUTHORITY=/run/user/1/auth", "PATH=/bin"}
	cache.environment(nil)
	for i := 0; i < 3; i++ {
		env = cache.environment([]string{"HOME=/home/u"})
	}
	if session.calls != 3 {
		t.Fatalf("looked up %d times, want no lookups after DISPLAY was known", session.calls)
	}
	if want := []string{"HOME=/home/u", "DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "XAUTHORITY=/run/user/1/auth"}; !slices.Equal(env, want) {
		t.Fatalf("env = %q, want %q", env, want)
	}

	// After a failed dialog the values are read again
	if !cache.forget() {
		t.Fatal("forget() found nothing to drop")
	}
	session.environ = []string{"DISPLAY=:1", "XAUTHORITY=/run/user/1/new-auth"}
	if env := cache.environment(nil); !slices.Contains(env, "DISPLAY=:1") || session.calls != 4 {
		t.Fatalf("after forget: env %q with %d lookups, want fresh DISPLAY=:1 from a 4th lookup", env, session.calls)
	}
}

func TestDisplayCacheTrustsDisplayFromStart(t *testing.T) {
	session := &fakeSession{}
	environ := []string{"DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "HOME=/home/u"}
	cache := newDisplayCache(environ, session.lookup)
	if env := cache.environment(environ); !slices.Contains(env, "DISPLAY=:0") || session.calls != 0 {
		t.Fatalf("env %q with %d lookups, want the detector's DISPLAY and no lookup", env, session.calls)
	}
	if cache.forget() != true || cache.forget() != false {
		t.Fatal("forget() should report a drop only once")
	}
}

func TestDisplayCacheFallsBackWhenLookupFails(t *testing.T) {
	session := &fakeSession{err: errors.New("no session bus")}
	cache := newDisplayCache(nil, session.lookup)
	environ := []string{"HOME=/home/u"}
	for i := 0; i < 2; i++ {
		if env := cache.environment(environ); !slices.Equal(env, environ) {
			t.Fatalf("env = %q, want the detector's own %q", env, environ)
		}
	}
	if session.calls != 2 {
		t.Fatalf("looked up %d times, want a retry on every dialog while failing", session.calls)
	}
}

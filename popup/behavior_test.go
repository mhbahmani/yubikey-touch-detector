//go:build linux

package popup

import (
	"image"
	"testing"

	"gioui.org/f32"
	"gioui.org/io/event"
	"gioui.org/io/input"
	"gioui.org/io/key"
	"gioui.org/io/pointer"
	"gioui.org/layout"
	"gioui.org/op"
)

func TestReasonText(t *testing.T) {
	for reasons, want := range map[string]string{
		"u2f":            "A security key is asking for a touch",
		"gpg":            "A GPG operation is waiting",
		"hmac":           "A challenge-response request is waiting",
		"gpg, u2f":       "Several requests are waiting",
		"gpg, hmac, u2f": "Several requests are waiting",
		"":               "A request is waiting",
		"other":          "A request is waiting",
	} {
		if got := reasonText(reasons); got != want {
			t.Errorf("reasonText(%q) = %q, want %q", reasons, got, want)
		}
	}
}

func TestOrigin(t *testing.T) {
	// A second monitor to the right of a 1920x1080 one
	monitor := image.Rect(1920, 0, 1920+2560, 1440)
	size := image.Pt(440, 200)
	const margin = 24
	for position, want := range map[string]image.Point{
		"center":       {1920 + 1060, 620},
		"top":          {1920 + 1060, 24},
		"bottom":       {1920 + 1060, 1440 - 200 - 24},
		"left":         {1920 + 24, 620},
		"right":        {1920 + 2560 - 440 - 24, 620},
		"top-left":     {1920 + 24, 24},
		"top-right":    {1920 + 2560 - 440 - 24, 24},
		"bottom-left":  {1920 + 24, 1440 - 200 - 24},
		"bottom-right": {1920 + 2560 - 440 - 24, 1440 - 200 - 24},
	} {
		if got := origin(position, monitor, size, margin); got != want {
			t.Errorf("origin(%q) = %v, want %v", position, got, want)
		}
	}
}

func TestDismissed(t *testing.T) {
	for name, ev := range map[string]event.Event{
		"escape": key.Event{Name: key.NameEscape, State: key.Press},
		"click":  pointer.Event{Kind: pointer.Press, Source: pointer.Mouse, Buttons: pointer.ButtonPrimary, Position: f32.Pt(50, 50)},
	} {
		t.Run(name, func(t *testing.T) {
			var router input.Router
			var ops op.Ops
			frame := func() bool {
				ops.Reset()
				gtx := layout.Context{Ops: &ops, Source: router.Source(), Constraints: layout.Exact(image.Pt(440, 200))}
				dismiss := dismissed(gtx)
				router.Frame(&ops)
				return dismiss
			}
			if frame() {
				t.Fatal("dismissed without input")
			}
			router.Queue(ev)
			if !frame() {
				t.Fatalf("%s did not dismiss the dialog", name)
			}
		})
	}
}

func TestOtherKeysDoNotDismiss(t *testing.T) {
	var router input.Router
	var ops op.Ops
	frame := func() bool {
		ops.Reset()
		gtx := layout.Context{Ops: &ops, Source: router.Source(), Constraints: layout.Exact(image.Pt(440, 200))}
		dismiss := dismissed(gtx)
		router.Frame(&ops)
		return dismiss
	}
	frame()
	router.Queue(key.Event{Name: "A", State: key.Press})
	if frame() {
		t.Fatal("a key other than Escape dismissed the dialog")
	}
}

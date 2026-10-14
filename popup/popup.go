//go:build linux

// Package popup shows a persistent dialog while the YubiKey is waiting for a
// touch. It is invoked as a subcommand of the detector binary, e.g. through
// --exec-command, so the dialog code ships with the installed binary instead
// of a user-writable script.
package popup

import (
	"image"
	"image/color"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gioui.org/app"
	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

// Palette follows the ui-ux-pro-max "Dark Mode (OLED)" entry, matching the
// design of the GTK dialog this package replaces.
var (
	colBackground = nrgba(0x02, 0x06, 0x17, 0xff)
	colCard       = nrgba(0x0e, 0x12, 0x23, 0xff)
	colBorder     = nrgba(0x1e, 0x29, 0x3b, 0xff)
	colTitle      = nrgba(0xf8, 0xfa, 0xfc, 0xff)
	colReason     = nrgba(0xcb, 0xd5, 0xe1, 0xff)
	colAccent     = nrgba(0x4a, 0xde, 0x80, 0xff)
	colAccentBg   = nrgba(0x4a, 0xde, 0x80, 0x38)
	colChipBg     = nrgba(0x4a, 0xde, 0x80, 0x26)
	colChipBorder = nrgba(0x4a, 0xde, 0x80, 0x59)
	colChipText   = nrgba(0x86, 0xef, 0xac, 0xff)
	colFooter     = nrgba(0x94, 0xa3, 0xb8, 0xff)
)

// safetyTimeout bounds the dialog's lifetime in case the detector dies
// without terminating this process
const safetyTimeout = 120 * time.Second

// reasonText describes the active event types, matching the notification wording
func reasonText(reason string) string {
	switch reason {
	case "u2f":
		return "A security key is asking for a touch"
	case "gpg":
		return "A GPG operation is waiting"
	case "hmac":
		return "An SSH connection is waiting"
	default:
		return "A request is waiting"
	}
}

// Run shows the touch dialog until the process is terminated. It never
// returns while the window is open; the detector ends it with SIGTERM once
// the touch is registered.
func Run(reason, details string) {
	// Use the system fonts, matching the look of native dialogs
	theme := material.NewTheme()
	theme.Shaper = text.NewShaper()

	window := new(app.Window)
	window.Option(
		app.Title("YubiKey touch required"),
		app.Size(unit.Dp(460), unit.Dp(210)),
		app.Decorated(false),
	)

	go func() {
		var ops op.Ops
		var height int
		for {
			switch event := window.Event().(type) {
			case app.DestroyEvent:
				os.Exit(0)
			case app.FrameEvent:
				gtx := app.NewContext(&ops, event)
				size := draw(gtx, theme, reasonText(reason), details)
				// Let the dialog grow or shrink with its content, e.g. when
				// the reason text wraps to a second line
				if abs(size.Y-height) > 2 {
					height = size.Y
					window.Option(app.Size(unit.Dp(460), gtx.Metric.PxToDp(size.Y)))
				}
				event.Frame(&ops)
			}
		}
	}()

	// The detector SIGTERMs the process when the touch is registered; the
	// timeout guards against an orphan window if it dies unexpectedly
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
	go func() {
		select {
		case <-signals:
		case <-time.After(safetyTimeout):
		}
		os.Exit(0)
	}()

	app.Main()
}

// draw paints the dialog and returns the natural content size, with the
// card centered in the window
func draw(gtx layout.Context, theme *material.Theme, waitingOn, details string) image.Point {
	// Window background
	paint.FillShape(gtx.Ops, colBackground, clip.Rect{Max: gtx.Constraints.Max}.Op())

	// Lay out the card at its natural size, then center it in the window
	gtx.Constraints.Min = image.Point{}
	macro := op.Record(gtx.Ops)
	dims := layout.UniformInset(unit.Dp(20)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{}.Layout(gtx,
			// Card background and border
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				bounds := image.Rectangle{Max: gtx.Constraints.Min}
				card := clip.UniformRRect(bounds, gtx.Dp(unit.Dp(16)))
				paint.FillShape(gtx.Ops, colCard, card.Op(gtx.Ops))
				border := clip.Stroke{Path: card.Path(gtx.Ops), Width: float32(gtx.Dp(1))}
				paint.FillShape(gtx.Ops, colBorder, border.Op())
				return layout.Dimensions{Size: gtx.Constraints.Min}
			}),
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(unit.Dp(24)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{
						Axis:      layout.Horizontal,
						Gap:       gtx.Dp(unit.Dp(20)),
						Alignment: layout.Middle,
					}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return drawRing(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return drawText(gtx, theme, waitingOn, details)
						}),
					)
				})
			}),
		)
	})
	call := macro.Stop()

	window := gtx.Constraints.Max
	center := op.Offset(image.Pt((window.X-dims.Size.X)/2, (window.Y-dims.Size.Y)/2)).Push(gtx.Ops)
	call.Add(gtx.Ops)
	center.Pop()
	return dims.Size
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// drawRing renders the green ring marking the active touch state, with a
// simple key glyph in its center
func drawRing(gtx layout.Context) layout.Dimensions {
	size := gtx.Dp(unit.Dp(68))
	radius := size/2 - gtx.Dp(2)
	bounds := image.Rect(size/2-radius, size/2-radius, size/2+radius, size/2+radius)

	ring := clip.Ellipse(bounds)
	paint.FillShape(gtx.Ops, colAccentBg, ring.Op(gtx.Ops))
	stroke := clip.Stroke{Path: ring.Path(gtx.Ops), Width: float32(gtx.Dp(3))}
	paint.FillShape(gtx.Ops, colAccent, stroke.Op())

	// Key glyph centered in the ring
	keySize := gtx.Dp(unit.Dp(26))
	centered := op.Offset(image.Pt((size-keySize)/2, (size-keySize)/2)).Push(gtx.Ops)
	drawKey(gtx, keySize)
	centered.Pop()
	return layout.Dimensions{Size: image.Pt(size, size)}
}

// drawKey renders a simple key: a round bow and a straight shaft
func drawKey(gtx layout.Context, size int) layout.Dimensions {
	col := colAccent

	bowRadius := size / 6
	bow := image.Rect(size/4-bowRadius, size/2-bowRadius, size/4+bowRadius, size/2+bowRadius)
	bowShape := clip.Ellipse(bow)
	bowStroke := clip.Stroke{Path: bowShape.Path(gtx.Ops), Width: float32(gtx.Dp(3))}
	paint.FillShape(gtx.Ops, col, bowStroke.Op())

	shaftHeight := gtx.Dp(3)
	shaft := image.Rect(size/2, size/2-shaftHeight, size, size/2+shaftHeight)
	paint.FillShape(gtx.Ops, col, clip.UniformRRect(shaft, shaftHeight).Op(gtx.Ops))

	return layout.Dimensions{Size: image.Pt(size, size)}
}

func drawText(gtx layout.Context, theme *material.Theme, waitingOn, details string) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical, Gap: gtx.Dp(unit.Dp(4))}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			title := material.Label(theme, unit.Sp(20), "Touch your YubiKey")
			title.Font.Weight = font.SemiBold
			title.Color = colTitle
			return title.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			reason := material.Body1(theme, waitingOn+" on the touch sensor.")
			reason.Color = colReason
			return reason.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if details == "" {
				return layout.Dimensions{}
			}
			return layout.Stack{}.Layout(gtx,
				// Pill with a hairline border so it stands out from the card
				layout.Expanded(func(gtx layout.Context) layout.Dimensions {
					bounds := image.Rectangle{Max: gtx.Constraints.Min}
					radius := min(gtx.Dp(unit.Dp(12)), bounds.Max.Y/2)
					chip := clip.UniformRRect(bounds, radius)
					paint.FillShape(gtx.Ops, colChipBg, chip.Op(gtx.Ops))
					border := clip.Stroke{Path: chip.Path(gtx.Ops), Width: float32(gtx.Dp(1))}
					paint.FillShape(gtx.Ops, colChipBorder, border.Op())
					return layout.Dimensions{Size: bounds.Max}
				}),
				layout.Stacked(func(gtx layout.Context) layout.Dimensions {
					return layout.Inset{
						Top: unit.Dp(5), Bottom: unit.Dp(5),
						Left: unit.Dp(12), Right: unit.Dp(12),
					}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
						// Monospace so host names and addresses are easy to read
						host := material.Label(theme, unit.Sp(13), details)
						host.Font = font.Font{Typeface: "monospace"}
						host.Color = colChipText
						return host.Layout(gtx)
					})
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			footer := material.Label(theme, unit.Sp(12), "This window closes automatically once the key is touched.")
			footer.Color = colFooter
			return layout.Inset{Top: unit.Dp(8)}.Layout(gtx, footer.Layout)
		}),
	)
}

func nrgba(r, g, b, a uint8) color.NRGBA {
	return color.NRGBA{R: r, G: g, B: b, A: a}
}

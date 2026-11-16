//go:build linux

// Package popup displays the built-in YubiKey touch dialog.
package popup

import (
	"image"
	"image/color"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"gioui.org/app"
	"gioui.org/f32"
	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

var (
	colBackground = nrgba(0x02, 0x06, 0x17, 0xff)
	colCard       = nrgba(0x0e, 0x12, 0x23, 0xff)
	colBorder     = nrgba(0x1e, 0x29, 0x3b, 0xff)
	colTitle      = nrgba(0xf8, 0xfa, 0xfc, 0xff)
	colReason     = nrgba(0xcb, 0xd5, 0xe1, 0xff)
	colAccent     = nrgba(0x22, 0xc5, 0x5e, 0xff)
	colKey        = nrgba(0xf8, 0xfa, 0xfc, 0xff)
	colRingBg     = nrgba(0x10, 0x28, 0x2a, 0xff)
	colChipBg     = nrgba(0x10, 0x24, 0x29, 0xff)
	colFooter     = nrgba(0x94, 0xa3, 0xb8, 0xff)
)

// safetyTimeout bounds the dialog's lifetime in case the detector dies
// without terminating this process
const safetyTimeout = 120 * time.Second

// reasonText describes the active event types for the dialog
func reasonText(reasons string) string {
	var active []string
	for _, reason := range strings.Split(reasons, ",") {
		if reason = strings.TrimSpace(reason); reason != "" {
			active = append(active, reason)
		}
	}
	if len(active) > 1 {
		return "Several requests are waiting"
	}
	switch strings.Join(active, "") {
	case "u2f":
		return "A security key is asking for a touch"
	case "gpg":
		return "A GPG operation is waiting"
	case "hmac":
		return "A challenge-response request is waiting"
	default:
		return "A request is waiting"
	}
}

// Run shows the touch dialog until the process is terminated. It never
// returns while the window is open; the detector ends it with SIGTERM once
// the touch is registered.
func Run(reason, details string) {
	theme := material.NewTheme()
	theme.Shaper = text.NewShaper()

	window := new(app.Window)
	window.Option(
		app.Title("YubiKey touch required"),
		app.Size(unit.Dp(440), unit.Dp(232)),
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
				// Resize when text wrapping changes the natural height.
				if abs(size.Y-height) > 2 {
					height = size.Y
					window.Option(app.Size(unit.Dp(440), gtx.Metric.PxToDp(size.Y)))
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

func draw(gtx layout.Context, theme *material.Theme, waitingOn, details string) image.Point {
	window := gtx.Constraints.Max
	paint.FillShape(gtx.Ops, colBackground, clip.Rect{Max: gtx.Constraints.Max}.Op())

	gtx.Constraints.Min = image.Point{}
	// Measure the full content before requesting a window resize.
	gtx.Constraints.Max.Y = 1 << 20
	macro := op.Record(gtx.Ops)
	dims := layout.UniformInset(unit.Dp(20)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Stack{}.Layout(gtx,
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

func drawRing(gtx layout.Context) layout.Dimensions {
	size := gtx.Dp(unit.Dp(72))
	drawKey(gtx, size)
	return layout.Dimensions{Size: image.Pt(size, size)}
}

// Coordinates use a 144x144 design grid.
func drawKey(gtx layout.Context, size int) {
	ops := gtx.Ops
	s := float32(size) / 144
	pt := func(x, y float32) f32.Point { return f32.Pt(x*s, y*s) }

	paint.FillShape(ops, colRingBg, clip.Ellipse{Max: image.Pt(size, size)}.Op(ops))

	inset := int(2 * s)
	ring := clip.Ellipse{Min: image.Pt(inset, inset), Max: image.Pt(size-inset, size-inset)}
	paint.FillShape(ops, colAccent, clip.Stroke{Path: ring.Path(ops), Width: 4 * s}.Op())

	head := clip.Ellipse{Min: image.Pt(int(34*s), int(55*s)), Max: image.Pt(int(68*s), int(89*s))}
	paint.FillShape(ops, colKey, clip.Stroke{Path: head.Path(ops), Width: 4.5 * s}.Op())
	paint.FillShape(ops, colKey, clip.Ellipse{
		Min: image.Pt(int(40*s), int(67*s)),
		Max: image.Pt(int(48*s), int(75*s)),
	}.Op(ops))

	var key clip.Path
	key.Begin(ops)
	key.MoveTo(pt(68, 65))
	key.LineTo(pt(100, 65))
	key.LineTo(pt(109, 72))
	key.LineTo(pt(100, 81))
	key.LineTo(pt(95, 76))
	key.LineTo(pt(90, 81))
	key.LineTo(pt(85, 76))
	key.LineTo(pt(80, 81))
	key.LineTo(pt(69, 81))
	paint.FillShape(ops, colKey, clip.Stroke{Path: key.End(), Width: 4.5 * s}.Op())
}

func drawText(gtx layout.Context, theme *material.Theme, waitingOn, details string) layout.Dimensions {
	return layout.Flex{Axis: layout.Vertical, Gap: gtx.Dp(unit.Dp(4))}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			title := material.Label(theme, unit.Sp(22.7), "Touch your YubiKey")
			title.Font.Weight = font.Bold
			title.Color = colTitle
			return title.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			reason := material.Label(theme, unit.Sp(14.7), waitingOn+" on the touch sensor.")
			reason.Color = colReason
			return reason.Layout(gtx)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			if details == "" {
				return layout.Dimensions{}
			}
			return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Stack{}.Layout(gtx,
					layout.Expanded(func(gtx layout.Context) layout.Dimensions {
						bounds := image.Rectangle{Max: gtx.Constraints.Min}
						chip := clip.UniformRRect(bounds, gtx.Dp(unit.Dp(8)))
						paint.FillShape(gtx.Ops, colChipBg, chip.Op(gtx.Ops))
						return layout.Dimensions{Size: bounds.Max}
					}),
					layout.Stacked(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{
							Top: unit.Dp(6), Bottom: unit.Dp(6),
							Left: unit.Dp(10), Right: unit.Dp(10),
						}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							host := material.Label(theme, unit.Sp(14), details)
							host.Font = font.Font{Typeface: "monospace"}
							host.Color = colAccent
							return host.Layout(gtx)
						})
					}),
				)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			footer := material.Label(theme, unit.Sp(12.7), "This window closes automatically once the key is touched.")
			footer.Color = colFooter
			return layout.Inset{Top: unit.Dp(8)}.Layout(gtx, footer.Layout)
		}),
	)
}

func nrgba(r, g, b, a uint8) color.NRGBA {
	return color.NRGBA{R: r, G: g, B: b, A: a}
}

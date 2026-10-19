//go:build linux

package popup

import (
	"image"
	"strings"
	"testing"

	"gioui.org/font/gofont"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

func TestDrawMeasuresFullHeight(t *testing.T) {
	for _, metric := range []unit.Metric{
		{PxPerDp: 1, PxPerSp: 1},
		{PxPerDp: 2, PxPerSp: 2},
		{PxPerDp: 1, PxPerSp: 1.5},
	} {
		theme := material.NewTheme()
		theme.Shaper = text.NewShaper(text.WithCollection(gofont.Collection()))
		measure := func(height int, details string) image.Point {
			var ops op.Ops
			gtx := layout.Context{
				Ops:         &ops,
				Metric:      metric,
				Constraints: layout.Exact(image.Pt(metric.Dp(440), height)),
			}
			return draw(gtx, theme, reasonText("u2f"), details)
		}
		details := "SSH to one of " + strings.Repeat("10.60.12.129:22, ", 12)
		want := measure(metric.Dp(4000), details)
		for _, height := range []int{metric.Dp(232), want.Y} {
			if got := measure(height, details); got != want {
				t.Errorf("metric %+v, window height %d: measured %v, want full content size %v", metric, height, got, want)
			}
		}
		if short := measure(metric.Dp(4000), ""); want.Y <= short.Y {
			t.Errorf("long details height %d must exceed short content height %d", want.Y, short.Y)
		}
	}
}
